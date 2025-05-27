package main

import (
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gocolly/colly"
	"github.com/gocolly/colly/proxy"
)

// Vulnerability represents a found security issue
type Vulnerability struct {
	URL         string
	Type        string
	Severity    string
	Description string
	Evidence    string
}

// Scanner interface for different types of vulnerability scanners
type Scanner interface {
	Scan(url string, c *colly.Collector) []Vulnerability
}

// SecurityCollector extends the basic collector with security scanning capabilities
type SecurityCollector struct {
	collector    *colly.Collector
	scanners     []Scanner
	vulns        []Vulnerability
	vulnMutex    sync.Mutex
	visitedURLs  map[string]bool
	visitedMutex sync.Mutex
}

func main() {
	// Command-line flags
	csvfile := flag.String("file", "top-1m.csv", "CSV file with domains")
	concurrency := flag.Int("concurrency", 50, "Number of sites to crawl in parallel")
	timeout := flag.Int("timeout", 30, "Timeout in seconds for each request")
	resultsFile := flag.String("results", "security-results.csv", "File to write results to")
	proxyFile := flag.String("proxies", "proxies.csv", "File containing proxy list")
	flag.Parse()

	// Initialize results file
	results, err := os.Create(*resultsFile)
	if err != nil {
		fmt.Printf("Failed to create results file: %v\n", err)
		return
	}
	defer results.Close()

	// Write CSV header
	writer := csv.NewWriter(results)
	writer.Write([]string{"URL", "Vulnerability Type", "Severity", "Description", "Evidence"})
	writer.Flush()

	// Load domains
	domains, err := loadDomains(*csvfile)
	if err != nil {
		fmt.Printf("Failed to load domains: %v\n", err)
		return
	}

	// Load proxies
	proxies, err := loadProxies(*proxyFile)
	if err != nil {
		fmt.Printf("Warning: Failed to load proxies: %v\n", err)
	}

	// Initialize scanners
	scanners := []Scanner{
		&XSSScanner{},
		&SQLInjectionScanner{},
		&OpenRedirectScanner{},
		&HeaderSecurityScanner{},
		&SSLScanner{},
	}

	// Create semaphore for concurrency control
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	var totalScanned int64
	var vulnerabilitiesFound int64

	start := time.Now()

	// Process each domain
	for _, domain := range domains {
		sem <- struct{}{} // acquire slot
		wg.Add(1)
		go func(domain string) {
			defer func() {
				<-sem // release slot
				wg.Done()
			}()

			// Create collector for this domain
			collector := newSecurityCollector(scanners, *timeout, proxies)
			
			// Start scanning
			url := ensureHTTPS(domain)
			vulns := collector.Scan(url)

			// Write results
			if len(vulns) > 0 {
				atomic.AddInt64(&vulnerabilitiesFound, int64(len(vulns)))
				writeVulnerabilities(writer, vulns)
			}

			atomic.AddInt64(&totalScanned, 1)
			
			// Print progress
			if atomic.LoadInt64(&totalScanned)%100 == 0 {
				elapsed := time.Since(start)
				rate := float64(totalScanned) / elapsed.Seconds()
				fmt.Printf("Progress: %d/%d domains (%.2f domains/sec), %d vulnerabilities found\n",
					totalScanned, len(domains), rate, vulnerabilitiesFound)
			}
		}(domain)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Print final statistics
	fmt.Printf("\nScan completed in %s\n", elapsed)
	fmt.Printf("Total domains scanned: %d\n", totalScanned)
	fmt.Printf("Total vulnerabilities found: %d\n", vulnerabilitiesFound)
	fmt.Printf("Average scan rate: %.2f domains/sec\n", float64(totalScanned)/elapsed.Seconds())
}

func newSecurityCollector(scanners []Scanner, timeout int, proxies []string) *SecurityCollector {
	c := colly.NewCollector(
		colly.MaxDepth(2),
		colly.Async(true),
	)

	// Configure collector
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 2,
		RandomDelay: 5 * time.Second,
	})

	// Set timeout
	c.SetRequestTimeout(time.Duration(timeout) * time.Second)

	// Configure TLS
	c.WithTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})

	// Set up proxy if available
	if len(proxies) > 0 {
		proxyFunc, err := proxy.RoundRobinProxySwitcher(proxies...)
		if err == nil {
			c.SetProxyFunc(proxyFunc)
		}
	}

	return &SecurityCollector{
		collector:   c,
		scanners:    scanners,
		visitedURLs: make(map[string]bool),
	}
}

func (sc *SecurityCollector) Scan(startURL string) []Vulnerability {
	fmt.Printf("Starting scan for URL: %s\n", startURL)
	
	// Add request callback
	sc.collector.OnRequest(func(r *colly.Request) {
		fmt.Printf("Making request to: %s\n", r.URL.String())
	})

	// Add response callback
	sc.collector.OnResponse(func(r *colly.Response) {
		fmt.Printf("Received response from: %s (Status: %d)\n", r.Request.URL.String(), r.StatusCode)
	})

	// Add error callback
	sc.collector.OnError(func(r *colly.Response, err error) {
		fmt.Printf("Error visiting %s: %v\n", r.Request.URL.String(), err)
	})

	sc.collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		absoluteURL := e.Request.AbsoluteURL(link)
		if sc.shouldVisit(absoluteURL) {
			fmt.Printf("Found link to visit: %s\n", absoluteURL)
			e.Request.Visit(link)
		}
	})

	// Run all scanners
	for _, scanner := range sc.scanners {
		fmt.Printf("Running scanner: %T\n", scanner)
		vulns := scanner.Scan(startURL, sc.collector)
		fmt.Printf("Scanner %T found %d vulnerabilities\n", scanner, len(vulns))
		sc.addVulnerabilities(vulns)
	}

	fmt.Printf("Starting to visit: %s\n", startURL)
	sc.collector.Visit(startURL)
	sc.collector.Wait()
	fmt.Printf("Scan completed for URL: %s\n", startURL)
	return sc.vulns
}

func (sc *SecurityCollector) shouldVisit(url string) bool {
	sc.visitedMutex.Lock()
	defer sc.visitedMutex.Unlock()

	if sc.visitedURLs[url] {
		return false
	}
	sc.visitedURLs[url] = true
	return true
}

func (sc *SecurityCollector) addVulnerabilities(vulns []Vulnerability) {
	sc.vulnMutex.Lock()
	defer sc.vulnMutex.Unlock()
	sc.vulns = append(sc.vulns, vulns...)
}

func loadDomains(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var domains []string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) > 0 {
			domains = append(domains, strings.TrimSpace(record[0]))
		}
	}
	return domains, nil
}

func loadProxies(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var proxies []string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(record) > 0 {
			proxies = append(proxies, strings.TrimSpace(record[0]))
		}
	}
	return proxies, nil
}

func writeVulnerabilities(writer *csv.Writer, vulns []Vulnerability) {
	for _, vuln := range vulns {
		writer.Write([]string{
			vuln.URL,
			vuln.Type,
			vuln.Severity,
			vuln.Description,
			vuln.Evidence,
		})
	}
	writer.Flush()
}

func ensureHTTPS(domain string) string {
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return domain
	}
	return "https://" + domain
} 