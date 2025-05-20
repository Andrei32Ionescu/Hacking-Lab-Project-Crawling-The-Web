package main

import (
	"bufio"
	"crypto/tls"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
	"github.com/chromedp/chromedp"

)

type Metrics struct {
    sync.Mutex
    StartTime       time.Time
    TotalRequests   int
    SuccessRequests int
    FailedRequests  int
    Redirects       int
    PagesCrawled    int
    LinksFound      int
    TotalBytes      int64
    RequestTimes    []time.Duration
}

var metrics Metrics

type Result struct {
	Source string
	URL    string
	Where  string
}

var headers map[string]string
var sm sync.Map

func main() {

	metrics = Metrics{
		StartTime: time.Now(),
	}

	inside := flag.Bool("i", false, "Only crawl inside path")
	threads := flag.Int("t", 8, "Number of threads to utilise.")
	depth := flag.Int("d", 2, "Depth to crawl.")
	maxSize := flag.Int("size", -1, "Page size limit, in KB.")
	insecure := flag.Bool("insecure", false, "Disable TLS verification.")
	subsInScope := flag.Bool("subs", false, "Include subdomains for crawling.")
	showJson := flag.Bool("json", false, "Output as JSON.")
	showSource := flag.Bool("s", false, "Show the source of URL based on where it was found.")
	showWhere := flag.Bool("w", false, "Show at which link the URL is found.")
	rawHeaders := flag.String("h", "", "Custom headers separated by two semi-colons.")
	unique := flag.Bool("u", false, "Show only unique urls.")
	proxy := flag.String("proxy", "", "Proxy URL.")
	timeout := flag.Int("timeout", -1, "Maximum time to crawl each URL, in seconds.")
	disableRedirects := flag.Bool("dr", false, "Disable HTTP redirects.")
	domainLimit := flag.Int("n", 1000, "Limit the number of domains to crawl.")
	csvPath := flag.String("csv", "top-1m.csv", "Path to CSV file of domains.")
	headless := flag.Bool("headless", false, "Use headless browser for advanced detection")
	flag.Parse()

	err := parseHeaders(*rawHeaders)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing headers:", err)
		os.Exit(1)
	}

	// if *proxy != "" {
	// 	os.Setenv("PROXY", *proxy)
	// }
	// proxyURL, _ := url.Parse(os.Getenv("PROXY"))

	var proxyURL *url.URL
	if *proxy != "" {
		parsed, err := url.Parse(*proxy)
		if err != nil {
			log.Fatalf("Invalid proxy URL: %v", err)
		}
		proxyURL = parsed
	}


	// Load domains
	domains, err := loadDomains(*csvPath, *domainLimit)
	if err != nil {
		log.Fatalf("Failed to load domains: %v", err)
	}

	log.Printf("Loaded %d domains from CSV\n", len(domains))


	results := make(chan string, *threads*10)
	var wg sync.WaitGroup

	// Start result printer
	go func() {
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()
		if *unique {
			for res := range results {
				if isUnique(res) {
					fmt.Fprintln(w, res)
				}
			}
		} else {
			for res := range results {
				fmt.Fprintln(w, res)
			}
		}
	}()

	// Worker pool
	sem := make(chan struct{}, *threads * 2)
	for _, domain := range domains {
		sem <- struct{}{}
		wg.Add(1)
		go func(domain string) {
			defer func() {
				wg.Done()
				<-sem
			}()
			crawlDomain(domain, proxyURL, *insecure, *inside, *depth, *maxSize, *subsInScope, *disableRedirects, *timeout, *showJson, *showSource, *showWhere, *headless, results)
		}(domain)
	}

	wg.Wait()

	printMetrics()
	close(results)
}

func crawlDomain(
	url string,
	proxyURL *url.URL,
	insecure, inside bool,
	depth, maxSize int,
	subsInScope, disableRedirects bool,
	timeout int,
	showJson, showSource, showWhere bool,
	headless bool,
	results chan string,
) {

	log.Printf("Crawling: %s", url)

	hostname, err := extractHostname(url)
	if err != nil {
		log.Println("Invalid URL:", err)
		return
	}

	allowedDomains := []string{hostname}
	if val, ok := headers["Host"]; ok {
		allowedDomains = append(allowedDomains, val)
	}

	c := colly.NewCollector(
		colly.UserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"),
		colly.Headers(headers),
		colly.AllowedDomains(allowedDomains...),
		colly.MaxDepth(depth),
		colly.Async(true),
	)

	if headless {
		suspicious, err := analyzeWithHeadlessBrowser(url)
		if err != nil {
			log.Printf("Headless analysis failed for %s: %v", url, err)
		} else if len(suspicious) > 0 {
			for _, s := range suspicious {
				results <- fmt.Sprintf("[CRYPTO] %s", s)
			}
		}
	}

	if maxSize != -1 {
		c.MaxBodySize = maxSize * 1024
	}

	if subsInScope {
		c.AllowedDomains = nil
		c.URLFilters = []*regexp.Regexp{regexp.MustCompile(".*(\\.|\\/\\/)" + strings.ReplaceAll(hostname, ".", "\\.") + ".*")}
	}

	if disableRedirects {
		c.SetRedirectHandler(func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		})
	}

	// c.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: 2})
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 6, // Increased from 2
		Delay:       300 * time.Millisecond, // Small delay between requests
	})

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		if strings.HasPrefix(link, "#") {
			return
		}
		abs := e.Request.AbsoluteURL(link)
		if inside && !strings.Contains(abs, hostname) {
			return
		}
		printResult(link, "href", showSource, showWhere, showJson, results, e)
		e.Request.Visit(link)
	})

	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		printResult(e.Attr("src"), "script", showSource, showWhere, showJson, results, e)
	})

	c.OnHTML("form[action]", func(e *colly.HTMLElement) {
		printResult(e.Attr("action"), "form", showSource, showWhere, showJson, results, e)
	})

	c.OnRequest(func(r *colly.Request) {
		r.Ctx.Put("start_time", time.Now().Format(time.RFC3339Nano))
		
		metrics.Lock()
		metrics.TotalRequests++
		metrics.Unlock()
		
		for header, val := range headers {
			r.Headers.Set(header, val)
		}
	})

	c.OnResponse(func(r *colly.Response) {
		metrics.Lock()
		metrics.SuccessRequests++
		metrics.PagesCrawled++
		metrics.TotalBytes += int64(len(r.Body))
		metrics.Unlock()
		
		log.Printf("Visited: %s [%d]", r.Request.URL.String(), r.StatusCode)
	})

	c.OnError(func(r *colly.Response, err error) {
		metrics.Lock()
		if r != nil {
			if r.StatusCode >= 300 && r.StatusCode < 400 {
				metrics.Redirects++
			} else {
				metrics.FailedRequests++
			}
		} else {
			metrics.FailedRequests++
		}
		metrics.Unlock()
		
		log.Printf("Error visiting %s: %v", r.Request.URL.String(), err)
	})

	c.OnScraped(func(r *colly.Response) {
		startStr := r.Ctx.Get("start_time")
		if startStr == "" {
			return
		}
		
		startTime, err := time.Parse(time.RFC3339Nano, startStr)
		if err != nil {
			log.Printf("Error parsing start time: %v", err)
			return
		}
		
		metrics.Lock()
		metrics.RequestTimes = append(metrics.RequestTimes, time.Since(startTime))
		metrics.Unlock()
	})

	// tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
	// if proxyURL != nil {
	// 	tr.Proxy = http.ProxyURL(proxyURL)
	// }

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	c.WithTransport(tr)

	if timeout == -1 {
		c.Visit(url)
		c.Wait()
	} else {
		finished := make(chan struct{})
		go func() {
			c.Visit(url)
			c.Wait()
			close(finished)
		}()
		select {
		case <-finished:
		case <-time.After(time.Duration(timeout) * time.Second):
			log.Println("[timeout]", url)
		}
	}
}

func parseHeaders(rawHeaders string) error {
	if rawHeaders != "" {
		if !strings.Contains(rawHeaders, ":") {
			return errors.New("headers flag not formatted properly")
		}
		headers = make(map[string]string)
		parts := strings.Split(rawHeaders, ";;")
		for _, header := range parts {
			if h := strings.SplitN(header, ":", 2); len(h) == 2 {
				headers[strings.TrimSpace(h[0])] = strings.TrimSpace(h[1])
			}
		}
	}
	return nil
}

func extractHostname(urlString string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil || !u.IsAbs() {
		return "", errors.New("must be a valid absolute URL")
	}
	return u.Hostname(), nil
}

func printResult(link, source string, showSource, showWhere, showJson bool, results chan string, e *colly.HTMLElement) {

	metrics.Lock()
    metrics.LinksFound++
    metrics.Unlock()


	result := e.Request.AbsoluteURL(link)
	where := e.Request.URL.String()
	if result != "" {
		if showJson {
			bytes, _ := json.Marshal(Result{Source: source, URL: result, Where: where})
			result = string(bytes)
		} else if showSource {
			result = "[" + source + "] " + result
		}
		if showWhere && !showJson {
			result = "[" + where + "] " + result
		}
		defer func() { recover() }()
		results <- result
	}
}

func isUnique(u string) bool {
	_, exists := sm.Load(u)
	if exists {
		return false
	}
	sm.Store(u, true)
	return true
}

func loadDomains(filePath string, limit int) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	var domains []string
	for {
		record, err := reader.Read()
		if err == io.EOF || (limit > 0 && len(domains) >= limit) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) < 2 {
			continue
		}
		domain := strings.TrimSpace(record[1])
		if domain != "" {
			domains = append(domains, "https://"+domain, "http://"+domain)
		}
	}
	return domains, nil
}

func analyzeWithHeadlessBrowser(targetURL string) ([]string, error) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Set up options for the browser
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	ctx, cancel = chromedp.NewContext(allocCtx)
	defer cancel()

	var scripts []string
	var resources []string

	// Tasks to run in the browser
	tasks := chromedp.Tasks{
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body"),
		// Get all script sources
		chromedp.Evaluate(`Array.from(document.scripts).map(s => s.src)`, &scripts),
		// Get all network requests
		chromedp.Evaluate(`
			window.resources = [];
			const observer = new PerformanceObserver(list => {
				list.getEntries().forEach(entry => {
					window.resources.push(entry.name);
				});
			});
			observer.observe({type: 'resource', buffered: true});
			Promise.resolve();
		`, nil),
		chromedp.Sleep(5 * time.Second), // Wait for scripts to execute
		chromedp.Evaluate(`window.resources`, &resources),
	}

	if err := chromedp.Run(ctx, tasks); err != nil {
		return nil, err
	}

	// Analyze for suspicious patterns
	suspicious := detectSuspiciousPatterns(scripts, resources)
	return suspicious, nil
}

func detectSuspiciousPatterns(scripts, resources []string) []string {
	var suspicious []string
	cryptoPatterns := []string{
		"coin-hive", "crypto", "miner", "webassembly", "wasm",
		"pool", "mine", "xmr", "monero", "cryptonight",
	}

	for _, script := range scripts {
		for _, pattern := range cryptoPatterns {
			if strings.Contains(strings.ToLower(script), pattern) {
				suspicious = append(suspicious, script)
				break
			}
		}
	}

	// Check resources for known mining pools
	miningPools := []string{
		"coinhive", "cryptoloot", "miner", "webmine", "ppoi",
		"jsecoin", "deepminer", "minero", "minemytraffic",
	}

	for _, res := range resources {
		for _, pool := range miningPools {
			if strings.Contains(strings.ToLower(res), pool) {
				suspicious = append(suspicious, res)
				break
			}
		}
	}

	return suspicious
}

func printMetrics() {
    metrics.Lock()
    defer metrics.Unlock()
    
    duration := time.Since(metrics.StartTime)
    reqPerSec := float64(metrics.TotalRequests) / duration.Seconds()
    avgReqTime := calculateAverage(metrics.RequestTimes)
    bytesPerSec := float64(metrics.TotalBytes) / duration.Seconds()
    
    fmt.Println("\n=== Crawling Metrics ===")
    fmt.Printf("Total runtime: %v\n", duration.Round(time.Second))
    fmt.Printf("Total domains processed: %d\n", metrics.PagesCrawled)
    fmt.Printf("Total requests made: %d\n", metrics.TotalRequests)
    fmt.Printf("Successful requests: %d (%.1f%%)\n", metrics.SuccessRequests, 
        float64(metrics.SuccessRequests)/float64(metrics.TotalRequests)*100)
    fmt.Printf("Failed requests: %d (%.1f%%)\n", metrics.FailedRequests,
        float64(metrics.FailedRequests)/float64(metrics.TotalRequests)*100)
    fmt.Printf("Redirects handled: %d\n", metrics.Redirects)
    fmt.Printf("Total links found: %d\n", metrics.LinksFound)
    fmt.Printf("Total data downloaded: %s\n", formatBytes(metrics.TotalBytes))
    fmt.Printf("Requests per second: %.2f\n", reqPerSec)
    fmt.Printf("Average request time: %v\n", avgReqTime.Round(time.Millisecond))
    fmt.Printf("Data rate: %s/s\n", formatBytes(int64(bytesPerSec)))
}

func calculateAverage(durations []time.Duration) time.Duration {
    if len(durations) == 0 {
        return 0
    }
    var sum time.Duration
    for _, d := range durations {
        sum += d
    }
    return sum / time.Duration(len(durations))
}

func formatBytes(b int64) string {
    const unit = 1024
    if b < unit {
        return fmt.Sprintf("%d B", b)
    }
    div, exp := int64(unit), 0
    for n := b / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}