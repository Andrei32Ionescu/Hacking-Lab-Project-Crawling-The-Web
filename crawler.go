package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gocolly/colly"
	"github.com/gocolly/colly/proxy"
)

// initialize a map to store visited URLs
var visitedurls = make(map[string]bool)

func main() {
	// Command-line flags
	mode := flag.String("mode", "title", "Mode: 'title', 'jssearch', 'wordpress', 'tomcat', or 'apache'")
	keyword := flag.String("keyword", "", "Keyword to search for in JS files (jssearch mode)")
	depth := flag.Int("depth", 1, "Crawl depth (1 = only main page)")
	csvfile := flag.String("file", "top-1m.csv", "CSV file with domains")
	logToConsole := flag.Bool("console", false, "Also log results to console")
	concurrency := flag.Int("concurrency", 1, "Number of sites to crawl in parallel")
	debug := flag.Bool("debug", false, "Show detailed crawl/debug logs")
	indexed := flag.Bool("indexed", false, "CSV has an index column; domain is in the second column")
	resultsFileN := flag.String("results", "results", "File to write results to (default: 'results')")
	flag.Parse()

	// Open results file for writing
	resultsFileName := *resultsFileN
	resultsFile, err := os.Create(resultsFileName)
	if err != nil {
		fmt.Println("Failed to create results file:", err)
		return
	}
	defer resultsFile.Close()

	// Helper function for output
	writeResult := func(format string, a ...interface{}) {
		if *logToConsole {
			fmt.Printf(format, a...)
		} else {
			resultsFile.WriteString(fmt.Sprintf(format, a...))
		}
	}

	start := time.Now()

	var totalCrawled int64
	var crawlWG sync.WaitGroup
	var successCount int64
	var failCount int64
	var statusCounts sync.Map  // map[int]int64
	var status0Errors sync.Map // map[string]int, grouped error type -> count

	// Load CSV file
	file, err := os.Open(*csvfile)
	if err != nil {
		writeResult("Failed to open domains file: %v\n", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		writeResult("Failed to read CSV: %v\n", err)
		return
	}

	// Load proxies from proxies.csv if available
	var proxies []string
	proxyFile, err := os.Open("proxies.csv")
	if err == nil {
		defer proxyFile.Close()
		proxyReader := csv.NewReader(proxyFile)
		proxyRecords, err := proxyReader.ReadAll()
		if err == nil {
			for _, row := range proxyRecords {
				if len(row) > 0 && strings.TrimSpace(row[0]) != "" {
					proxies = append(proxies, strings.TrimSpace(row[0]))
				}
			}
		}
	}

	// Helper to get proxy func if proxies are loaded
	var proxyFunc colly.ProxyFunc
	if len(proxies) > 0 {
		proxyFunc, err = proxy.RoundRobinProxySwitcher(proxies...)
		if err != nil {
			writeResult("Failed to set up proxies: %v\n", err)
			proxyFunc = nil
		}
	}

	sem := make(chan struct{}, *concurrency)

	for _, row := range records {
		if len(row) == 0 {
			continue
		}
		var domain string
		if *indexed {
			if len(row) < 2 {
				continue // skip if not enough columns
			}
			domain = strings.TrimSpace(row[1])
		} else {
			domain = strings.TrimSpace(row[0])
		}
		if domain == "" {
			continue
		}
		url := ensureHTTPS(domain)
		if *debug {
			writeResult("\n--- Starting crawl for: %s ---\n", url)
		}

		sem <- struct{}{} // acquire slot
		crawlWG.Add(1)
		go func(url string) {
			defer func() {
				<-sem // release slot
				crawlWG.Done()
			}()
			var gotValid bool
			if *mode == "title" {
				gotValid = crawlForTitle(url, *depth, writeResult, proxyFunc, *debug, &statusCounts, &status0Errors)
			} else if *mode == "jssearch" {
				gotValid = crawlForJS(url, *depth, *keyword, writeResult, proxyFunc, *debug, &statusCounts, &status0Errors)
			} else if *mode == "wordpress" {
				gotValid = crawlForWordPress(url, *depth, writeResult, proxyFunc, *debug, &statusCounts, &status0Errors)
			} else if *mode == "tomcat" { // Added tomcat mode
				gotValid = crawlForTomcat(url, writeResult, proxyFunc, *debug, &statusCounts, &status0Errors)
			} else if *mode == "apache" { // Added apache mode
				gotValid = crawlForApache(url, writeResult, proxyFunc, *debug, &statusCounts, &status0Errors)
			} else {
				if *debug {
					writeResult("Unknown mode: %s\n", *mode)
				}
			}
			if gotValid {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
			atomic.AddInt64(&totalCrawled, 1)
		}(url)
	}

	crawlWG.Wait()

	elapsed := time.Since(start)
	writeResult("\nScraping completed in %s\n", elapsed)
	writeResult("Scraped %v urls\n", len(visitedurls))
	writeResult("Scraped %v root domains\n", totalCrawled)
	writeResult("Scraped %v urls per second\n", float64(len(visitedurls))/elapsed.Seconds())
	writeResult("Root domains per second: %.2f\n", float64(totalCrawled)/elapsed.Seconds())
	writeResult("Concurrency: %d\n", *concurrency)
	writeResult("Mode: %s\n", *mode)
	writeResult("Depth: %d\n", *depth)
	writeResult("Valid responses: %d\n", successCount)
	writeResult("Failed responses: %d\n", failCount)
	writeResult("Status code breakdown:\n")
	statusCounts.Range(func(key, value any) bool {
		writeResult("  %v: %v\n", key, value)
		return true
	})
	// Add summary for status 0 errors (grouped by error type)
	var status0Total int
	var errList []struct {
		msg   string
		count int
	}
	status0Errors.Range(func(key, value any) bool {
		errList = append(errList, struct {
			msg   string
			count int
		}{key.(string), value.(int)})
		status0Total += value.(int)
		return true
	})
	if len(errList) > 0 {
		sort.Slice(errList, func(i, j int) bool { return errList[i].count > errList[j].count })
		writeResult("Status 0 error breakdown (grouped network errors):\n")
		for i, ec := range errList {
			if i >= 10 {
				writeResult("  ...and %d more\n", len(errList)-10)
				break
			}
			writeResult("  %v: %d\n", ec.msg, ec.count)
		}
		writeResult("Total status 0 (network) errors: %d\n", status0Total)
		if failCount > 0 {
			writeResult("Status 0 errors: %d (%.1f%% of all failed responses)\n", status0Total, float64(status0Total)/float64(failCount)*100)
		}
	}
}

func ensureHTTPS(domain string) string {
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return domain
	}
	return "https://" + domain
}

// crawlForTitle crawls the site and prints titles up to the given depth
// Returns true if a valid (2xx) response was received, false otherwise
func crawlForTitle(currenturl string, maxdepth int, writeResult func(string, ...interface{}), proxyFunc colly.ProxyFunc, debug bool, statusCounts *sync.Map, status0Errors *sync.Map) bool {
	c := newCollectorWithConfig(maxdepth, proxyFunc, debug, writeResult)
	var gotValid bool
	c.OnResponse(func(r *colly.Response) {
		status := r.StatusCode
		if status >= 200 && status < 300 {
			gotValid = true
		}
		val, _ := statusCounts.LoadOrStore(status, int64(0))
		statusCounts.Store(status, val.(int64)+1)
	})
	c.OnHTML("title", func(e *colly.HTMLElement) {
		writeResult("Page Title: %s\n", e.Text)
	})
	c.OnError(func(r *colly.Response, err error) {
		status := r.StatusCode
		val, _ := statusCounts.LoadOrStore(status, int64(0))
		statusCounts.Store(status, val.(int64)+1)
		if status == 0 {
			grouped := groupStatus0Error(err.Error())
			cnt, _ := status0Errors.LoadOrStore(grouped, 0)
			status0Errors.Store(grouped, cnt.(int)+1)
		}
		if debug {
			if status == 0 {
				writeResult("Request URL: %s failed with status: %d %s (%v)\n", r.Request.URL, r.StatusCode, http.StatusText(r.StatusCode), err)
			} else {
				writeResult("Request URL: %s failed with status: %d %s\n", r.Request.URL, r.StatusCode, http.StatusText(r.StatusCode))
			}
			if len(r.Body) > 0 {
				snippet := string(r.Body)
				if len(snippet) > 200 {
					snippet = snippet[:200] + "..."
				}
				writeResult("Response body (truncated): %s\n", snippet)
			}
			writeResult("Error: %v\n", err)
		}
	})
	err := c.Visit(currenturl)
	if err != nil && debug {
		fmt.Println("Error visiting page:", err)
	}
	c.Wait()
	return gotValid
}

func crawlForWordPress(currenturl string, maxdepth int, writeResult func(string, ...interface{}), proxyFunc colly.ProxyFunc, debug bool, statusCounts *sync.Map, status0Errors *sync.Map) bool {
	// Step 1: Check {currenturl}/wp-login.php
	loginURL := strings.TrimRight(currenturl, "/") // + "/wp-login.php"
	client := &http.Client{
		Timeout: 5 * time.Second, // Lowered timeout for faster skipping of dead sites
		Transport: &http.Transport{
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   1000,
			TLSHandshakeTimeout:   2 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       5 * time.Second,
			DisableKeepAlives:     false,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}
	resp, err := client.Get(loginURL)
	if err != nil {
		if debug {
			writeResult("Failed to fetch wp-login.php: %v\n", err)
		}
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if debug {
			writeResult("wp-login.php returned status: %d\n", resp.StatusCode)
		}
		return false
	}

	// Step 2: Visit main page and extract info
	c := newCollectorWithConfig(maxdepth, proxyFunc, debug, writeResult)
	var gotValid bool
	var pageTitle string
	var themeName string
	pluginSet := make(map[string]struct{})

	c.OnResponse(func(r *colly.Response) {
		status := r.StatusCode
		if status >= 200 && status < 300 {
			gotValid = true
		}
		val, _ := statusCounts.LoadOrStore(status, int64(0))
		statusCounts.Store(status, val.(int64)+1)
	})
	c.OnHTML("title", func(e *colly.HTMLElement) {
		pageTitle = e.Text
	})
	c.OnHTML("link[href], script[src], img[src]", func(e *colly.HTMLElement) {
		attrs := []string{"href", "src"}
		for _, attr := range attrs {
			val := e.Attr(attr)
			if val == "" {
				continue
			}

			u, err := url.Parse(val)
			if err != nil {
				continue
			}

			version := u.Query().Get("ver")

			if themeName == "" {
				if idx := strings.Index(u.Path, "/wp-content/themes/"); idx != -1 {
					rest := u.Path[idx+len("/wp-content/themes/"):]
					parts := strings.SplitN(rest, "/", 2)
					if len(parts) > 0 && parts[0] != "" {
						name := parts[0]
						if version != "" {
							name += "@" + version
						}
						themeName = name
					}
				}
			}

			if idx := strings.Index(u.Path, "/wp-content/plugins/"); idx != -1 {
				rest := u.Path[idx+len("/wp-content/plugins/"):]
				parts := strings.SplitN(rest, "/", 2)
				if len(parts) > 0 && parts[0] != "" {
					name := parts[0]
					if version != "" {
						name += "@" + version
					}
					pluginSet[name] = struct{}{}
				}
			}
		}
	})
	c.OnError(func(r *colly.Response, err error) {
		status := r.StatusCode
		val, _ := statusCounts.LoadOrStore(status, int64(0))
		statusCounts.Store(status, val.(int64)+1)
		if status == 0 {
			grouped := groupStatus0Error(err.Error())
			cnt, _ := status0Errors.LoadOrStore(grouped, 0)
			status0Errors.Store(grouped, cnt.(int)+1)
		}
		if debug {
			if status == 0 {
				writeResult("Request URL: %s failed with status: %d %s (%v)\n", r.Request.URL, r.StatusCode, http.StatusText(r.StatusCode), err)
			} else {
				writeResult("Request URL: %s failed with status: %d %s\n", r.Request.URL, r.StatusCode, http.StatusText(r.StatusCode))
			}
			if len(r.Body) > 0 {
				snippet := string(r.Body)
				if len(snippet) > 200 {
					snippet = snippet[:200] + "..."
				}
				writeResult("Response body (truncated): %s\n", snippet)
			}
			writeResult("Error: %v\n", err)
		}
	})

	err = c.Visit(currenturl)
	if err != nil && debug {
		fmt.Println("Error visiting main page:", err)
	}
	c.Wait()

	// Print results
	if gotValid && themeName != "" {
		plugins := make([]string, 0, len(pluginSet))
		for p := range pluginSet {
			plugins = append(plugins, p)
		}
		sort.Strings(plugins)
		writeResult("******* Page Title: %s *******\n", pageTitle)
		writeResult("Page URL: %s\n", currenturl)
		if themeName != "" {
			writeResult("Theme: %s\n", themeName)
		} else {
			writeResult("Theme: (not found)\n")
		}
		if len(plugins) > 0 {
			writeResult("Plugins: %s\n", strings.Join(plugins, ", "))
		} else {
			writeResult("Plugins: (none found)\n")
		}
	}
	return gotValid
}

// crawlForJS crawls the site, downloads JS files, and searches for a keyword
// Returns true if a valid (2xx) response was received, false otherwise
func crawlForJS(currenturl string, maxdepth int, keyword string, writeResult func(string, ...interface{}), proxyFunc colly.ProxyFunc, debug bool, statusCounts *sync.Map, status0Errors *sync.Map) bool {
	c := newCollectorWithConfig(maxdepth, proxyFunc, debug, writeResult)
	var gotValid bool
	c.OnResponse(func(r *colly.Response) {
		status := r.StatusCode
		if status >= 200 && status < 300 {
			gotValid = true
		}
		val, _ := statusCounts.LoadOrStore(status, int64(0))
		statusCounts.Store(status, val.(int64)+1)
	})
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		jsURL := e.Request.AbsoluteURL(e.Attr("src"))
		if jsURL != "" {
			writeResult("Found JS: %s\n", jsURL)
			resp, err := http.Get(jsURL)
			if err == nil && resp.StatusCode == 200 {
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err == nil {
					if keyword == "" || strings.Contains(string(body), keyword) {
						writeResult("Keyword '%s' found in JS: %s\n", keyword, jsURL)
					}
				}
			}
		}
	})
	c.OnError(func(r *colly.Response, err error) {
		status := r.StatusCode
		val, _ := statusCounts.LoadOrStore(status, int64(0))
		statusCounts.Store(status, val.(int64)+1)
		if status == 0 {
			grouped := groupStatus0Error(err.Error())
			cnt, _ := status0Errors.LoadOrStore(grouped, 0)
			status0Errors.Store(grouped, cnt.(int)+1)
		}
		if debug {
			if status == 0 {
				writeResult("Request URL: %s failed with status: %d %s (%v)\n", r.Request.URL, r.StatusCode, http.StatusText(r.StatusCode), err)
			} else {
				writeResult("Request URL: %s failed with status: %d %s\n", r.Request.URL, r.StatusCode, http.StatusText(r.StatusCode))
			}
			if len(r.Body) > 0 {
				snippet := string(r.Body)
				if len(snippet) > 200 {
					snippet = snippet[:200] + "..."
				}
				writeResult("Response body (truncated): %s\n", snippet)
			}
			writeResult("Error: %v\n", err)
		}
	})
	err := c.Visit(currenturl)
	if err != nil && debug {
		fmt.Println("Error visiting page:", err)
	}
	c.Wait()
	return gotValid
}

// crawlForTomcat attempts to detect if a site is running Tomcat and its version.
// Returns true if the primary URL returns a 2xx status, for consistency in success/fail counts.
func crawlForTomcat(currenturl string, writeResult func(string, ...interface{}), proxyFunc colly.ProxyFunc, debug bool, statusCounts *sync.Map, status0Errors *sync.Map) bool {
	var isTomcat bool
	var tomcatVersion string
	var detectionSource string

	var primaryUrlResponded bool = false         // True if primary URL gave any HTTP response (not network error)
	var primaryUrlOkForSuccessCount bool = false // True if primary URL gave a 2xx response

	// Configure http.Client
	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if proxyFunc != nil {
		transport.Proxy = proxyFunc
	}
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects automatically
		},
	}

	// --- Primary Check: Request the root URL itself ---
	reqRoot, _ := http.NewRequest("GET", currenturl, nil)
	reqRoot.Header.Set("User-Agent", userAgents[int(time.Now().UnixNano())%len(userAgents)])
	reqRoot.Header.Set("Accept", acceptHeaders[int(time.Now().UnixNano())%len(acceptHeaders)])

	var respRoot *http.Response // Declare here to access its StatusCode in debug logging later
	var errRoot error

	respRoot, errRoot = httpClient.Do(reqRoot)

	if errRoot == nil {
		fmt.Println("Root URL responded", respRoot.StatusCode)
		defer respRoot.Body.Close()
		primaryUrlResponded = true
		val, _ := statusCounts.LoadOrStore(respRoot.StatusCode, int64(0))
		statusCounts.Store(respRoot.StatusCode, val.(int64)+1)

		if respRoot.StatusCode >= 200 && respRoot.StatusCode < 300 {
			primaryUrlOkForSuccessCount = true
		}

		serverHeader := respRoot.Header.Get("Server")
		if strings.Contains(serverHeader, "Apache-Coyote") || strings.Contains(serverHeader, "Tomcat") {
			isTomcat = true
			detectionSource = "Server Header (root URL)"
			// Regex for "Apache Tomcat/X.Y.Z" or "Apache-Coyote/X.Y"
			reVer := regexp.MustCompile(`(?:Apache Tomcat/([\d\.]+[A-Za-z\d\.-]*)|Apache-Coyote/([\d\.]+))`)
			matchesVer := reVer.FindStringSubmatch(serverHeader)
			if len(matchesVer) > 1 && matchesVer[1] != "" { // Apache Tomcat/VERSION
				tomcatVersion = matchesVer[1]
			} else if len(matchesVer) > 2 && matchesVer[2] != "" { // Apache-Coyote/VERSION (less specific for Tomcat version itself)
				// tomcatVersion could be "Coyote " + matchesVer[2] if needed, but usually doesn't map directly to Tomcat server version
			}
		}
		xPoweredByHeader := respRoot.Header.Get("X-Powered-By")
		if strings.Contains(xPoweredByHeader, "Servlet") || strings.Contains(xPoweredByHeader, "JSP") {
			if !isTomcat {
				isTomcat = true
				detectionSource = "X-Powered-By Header (root URL)"
			} else if detectionSource == "Server Header (root URL)" && tomcatVersion == "" {
				detectionSource += ", X-Powered-By Header"
			}
		}
		io.Copy(io.Discard, respRoot.Body) // Ensure body is consumed

	} else {
		fmt.Println("Error fetching root URL", errRoot)
		if debug {
			writeResult("Error fetching root URL %s: %v\n", currenturl, errRoot)
		}
		grouped := groupStatus0Error(errRoot.Error())
		cnt, _ := status0Errors.LoadOrStore(grouped, 0)
		status0Errors.Store(grouped, cnt.(int)+1)
		val, _ := statusCounts.LoadOrStore(0, int64(0))
		statusCounts.Store(0, val.(int64)+1)
		return false // Early exit if primary URL is unreachable due to network error
	}

	// --- Strategy 1: Check for Tomcat 404 error page (if not already confirmed with version) ---
	if primaryUrlResponded && (!isTomcat || tomcatVersion == "") {
		fmt.Println("Checking 404 page")
		nonExistentURL := strings.TrimRight(currenturl, "/") + "/ThisPageShouldNotExist" + fmt.Sprintf("%d", time.Now().UnixNano())
		req404, _ := http.NewRequest("GET", nonExistentURL, nil)
		req404.Header.Set("User-Agent", userAgents[int(time.Now().UnixNano())%len(userAgents)])

		resp404, err404 := httpClient.Do(req404)
		if err404 == nil {
			defer resp404.Body.Close()
			val, _ := statusCounts.LoadOrStore(resp404.StatusCode, int64(0)) // Record status for this check
			statusCounts.Store(resp404.StatusCode, val.(int64)+1)

			if resp404.StatusCode == http.StatusNotFound {
				bodyBytes, _ := io.ReadAll(resp404.Body)
				bodyString := string(bodyBytes)
				// Regex for "Apache Tomcat/X.Y.Z" or "Apache Tomcat Version X.Y.Z"
				re := regexp.MustCompile(`Apache Tomcat/(?:Version )?([\d\.]+[A-Za-z\d\.-]*)`)
				matches := re.FindStringSubmatch(bodyString)
				if len(matches) > 1 {
					isTomcat = true
					tomcatVersion = matches[1]
					detectionSource = "404 Error Page"
				} else if !isTomcat && (strings.Contains(bodyString, "Apache Tomcat") || (strings.Contains(bodyString, "Error report") && (strings.Contains(bodyString, "Apache") || strings.Contains(bodyString, "tomcat")))) {
					isTomcat = true
					detectionSource = "404 Error Page (signature)"
				}
			}
			io.Copy(io.Discard, resp404.Body)
		} else if debug {
			writeResult("Error checking 404 page for %s (%s): %v\n", currenturl, nonExistentURL, err404)
			grouped := groupStatus0Error(err404.Error())
			cnt, _ := status0Errors.LoadOrStore(grouped, 0)
			status0Errors.Store(grouped, cnt.(int)+1)
			val, _ := statusCounts.LoadOrStore(0, int64(0))
			statusCounts.Store(0, val.(int64)+1)
		}
	}

	// --- Strategy 2: Check RELEASE-NOTES.txt (if Tomcat indicated but version still missing, or to confirm/refine) ---
	if primaryUrlResponded && isTomcat && tomcatVersion == "" {
		fmt.Println("Checking RELEASE-NOTES.txt")
		releaseNotesURL := strings.TrimRight(currenturl, "/") + "/RELEASE-NOTES.txt"
		reqRN, _ := http.NewRequest("GET", releaseNotesURL, nil)
		reqRN.Header.Set("User-Agent", userAgents[int(time.Now().UnixNano())%len(userAgents)])

		respRN, errRN := httpClient.Do(reqRN)
		if errRN == nil {
			defer respRN.Body.Close()
			val, _ := statusCounts.LoadOrStore(respRN.StatusCode, int64(0)) // Record status
			statusCounts.Store(respRN.StatusCode, val.(int64)+1)

			if respRN.StatusCode == http.StatusOK {
				bodyBytes, _ := io.ReadAll(respRN.Body)
				bodyString := string(bodyBytes)
				// Example: "Apache Tomcat Version 9.0.65 Release Notes"
				re := regexp.MustCompile(`Apache Tomcat Version ([\d\.]+[A-Za-z\d\.-]*)`)
				matches := re.FindStringSubmatch(bodyString)
				if len(matches) > 1 {
					newVersion := matches[1]
					// Prioritize 404 error page for version, then RELEASE-NOTES, then headers
					if tomcatVersion == "" || detectionSource == "Server Header (root URL)" || detectionSource == "X-Powered-By Header (root URL)" || detectionSource == "404 Error Page (signature)" {
						tomcatVersion = newVersion
						detectionSource = "RELEASE-NOTES.txt"
					} else if detectionSource == "404 Error Page" && tomcatVersion != newVersion && debug {
						writeResult("Version mismatch for %s: 404 Page ('%s') vs RELEASE-NOTES.txt ('%s')\n", currenturl, tomcatVersion, newVersion)
						// Sticking with 404 page version if it was specific.
					}
				}
			}
			io.Copy(io.Discard, respRN.Body)
		} else if debug {
			writeResult("Error checking RELEASE-NOTES.txt for %s (%s): %v\n", currenturl, releaseNotesURL, errRN)
			grouped := groupStatus0Error(errRN.Error())
			cnt, _ := status0Errors.LoadOrStore(grouped, 0)
			status0Errors.Store(grouped, cnt.(int)+1)
			val, _ := statusCounts.LoadOrStore(0, int64(0))
			statusCounts.Store(0, val.(int64)+1)
		}
	}

	if isTomcat {
		writeResult("URL: %s\n", currenturl)
		writeResult("  Tomcat Detected: Yes\n")
		if tomcatVersion != "" {
			writeResult("  Tomcat Version: %s (Source: %s)\n", tomcatVersion, detectionSource)
		} else {
			writeResult("  Tomcat Version: Unknown (Detected via: %s)\n", detectionSource)
		}
	} else if debug {
		if primaryUrlResponded {
			writeResult("URL: %s - Tomcat Not Detected (primary URL status: %d)\n", currenturl, respRoot.StatusCode)
		} else {
			writeResult("URL: %s - Tomcat Not Detected (primary URL failed to respond with network error)\n", currenturl)
		}
	}
	return primaryUrlOkForSuccessCount
}

// crawlForApache attempts to detect if a site is running Apache HTTP Server and its version.
// Returns true if the primary URL returns a 2xx status for success/fail counts.
func crawlForApache(currenturl string, writeResult func(string, ...interface{}), proxyFunc colly.ProxyFunc, debug bool, statusCounts *sync.Map, status0Errors *sync.Map) bool {
	var isApache bool
	var apacheVersion string
	var apacheComment string // e.g., (Ubuntu)
	var detectionSource string

	startTime := time.Now()
	var requestCount int32
	trackRequest := func() { atomic.AddInt32(&requestCount, 1) }

	var primaryUrlResponded bool = false
	var primaryUrlOkForSuccessCount bool = false

	// Configure http.Client
	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if proxyFunc != nil {
		transport.Proxy = proxyFunc
	}
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects
		},
	}

	var rootRespStatus int
	// --- Primary Check: Request the root URL itself ---
	reqRoot, _ := http.NewRequest("GET", currenturl, nil)
	reqRoot.Header.Set("User-Agent", userAgents[int(time.Now().UnixNano())%len(userAgents)])
	reqRoot.Header.Set("Accept", acceptHeaders[int(time.Now().UnixNano())%len(acceptHeaders)])

	respRoot, errRoot := httpClient.Do(reqRoot)
	trackRequest()

	if errRoot == nil {
		defer respRoot.Body.Close()
		primaryUrlResponded = true
		rootRespStatus = respRoot.StatusCode
		val, _ := statusCounts.LoadOrStore(respRoot.StatusCode, int64(0))
		statusCounts.Store(respRoot.StatusCode, val.(int64)+1)

		if respRoot.StatusCode >= 200 && respRoot.StatusCode < 300 {
			primaryUrlOkForSuccessCount = true
		}

		serverHeader := respRoot.Header.Get("Server")
		// Regex for "Apache/X.Y.Z (Comment)" or "Apache (Comment)" or "Apache/X.Y.Z" or "Apache"
		reVerHeader := regexp.MustCompile(`^Apache(?:/([\d\.]+))?(?:\s+\(([^)]+)\))?`)
		matchesVer := reVerHeader.FindStringSubmatch(serverHeader)

		if len(matchesVer) > 0 { // Found "Apache" at the start of Server header
			isApache = true
			detectionSource = "Server Header"
			if len(matchesVer) > 1 && matchesVer[1] != "" { // Version found
				apacheVersion = matchesVer[1]
			}
			if len(matchesVer) > 2 && matchesVer[2] != "" { // Comment found
				apacheComment = matchesVer[2]
			}
		}
		io.Copy(io.Discard, respRoot.Body) // Ensure body is consumed
	} else {
		if debug {
			writeResult("Error fetching root URL %s: %v\n", currenturl, errRoot)
		}
		grouped := groupStatus0Error(errRoot.Error())
		cnt, _ := status0Errors.LoadOrStore(grouped, 0)
		status0Errors.Store(grouped, cnt.(int)+1)
		val, _ := statusCounts.LoadOrStore(0, int64(0)) // 0 for network error
		statusCounts.Store(0, val.(int64)+1)
		return false // Early exit if primary URL is unreachable
	}

	// --- Strategy: Check for Apache error page (if version not found in Server header, or to confirm) ---
	// Only proceed if the primary URL responded, and either Apache wasn't detected or version is missing.
	if primaryUrlResponded && (!isApache || apacheVersion == "") {
		nonExistentURL := strings.TrimRight(currenturl, "/") + "/ThisPageShouldNotExistAndLeadTo404-" + fmt.Sprintf("%d", time.Now().UnixNano())
		reqErrPage, _ := http.NewRequest("GET", nonExistentURL, nil)
		reqErrPage.Header.Set("User-Agent", userAgents[int(time.Now().UnixNano())%len(userAgents)])

		respErrPage, errErrPage := httpClient.Do(reqErrPage)
		trackRequest()

		if errErrPage == nil {
			defer respErrPage.Body.Close()
			val, _ := statusCounts.LoadOrStore(respErrPage.StatusCode, int64(0)) // Record status for this check
			statusCounts.Store(respErrPage.StatusCode, val.(int64)+1)

			// Check common Apache error codes
			if respErrPage.StatusCode == http.StatusNotFound || respErrPage.StatusCode == http.StatusForbidden || respErrPage.StatusCode == http.StatusInternalServerError {
				bodyBytes, _ := io.ReadAll(respErrPage.Body) // Limit read for performance?
				bodyString := string(bodyBytes)

				// Regex for "Apache/X.Y.Z (Comment) Server at" or "Apache Server at" in body
				reErrPage := regexp.MustCompile(`Apache(?:/([\d\.]+))?(?:\s+\(([^)]+)\))?\s+Server at`)
				matchesErrPage := reErrPage.FindStringSubmatch(bodyString)

				if len(matchesErrPage) > 0 {
					isApache = true // Confirm or set isApache
					// Prioritize error page version if Server header had no version
					if apacheVersion == "" && len(matchesErrPage) > 1 && matchesErrPage[1] != "" {
						apacheVersion = matchesErrPage[1]
						detectionSource = "Error Page (" + http.StatusText(respErrPage.StatusCode) + ")"
						if len(matchesErrPage) > 2 && matchesErrPage[2] != "" {
							apacheComment = matchesErrPage[2] // Update comment if found here
						}
					} else if detectionSource != "Server Header" { // If not already set by a more specific Server header version
						detectionSource = "Error Page (" + http.StatusText(respErrPage.StatusCode) + " signature)"
					}
				} else if !isApache && strings.Contains(bodyString, "<address>Apache") {
					// Fallback for less specific signature on error pages
					isApache = true
					detectionSource = "Error Page (" + http.StatusText(respErrPage.StatusCode) + " signature)"
				}
			}
			io.Copy(io.Discard, respErrPage.Body)
		} else if debug {
			writeResult("Error checking error page for %s (%s): %v\n", currenturl, nonExistentURL, errErrPage)
			grouped := groupStatus0Error(errErrPage.Error())
			cnt, _ := status0Errors.LoadOrStore(grouped, 0)
			status0Errors.Store(grouped, cnt.(int)+1)
			val, _ := statusCounts.LoadOrStore(0, int64(0))
			statusCounts.Store(0, val.(int64)+1)
		}
	}

	duration := time.Since(startTime)
	rps := 0.0
	if duration.Seconds() > 0 {
		rps = float64(requestCount) / duration.Seconds()
	}

	if isApache {
		writeResult("URL: %s\n", currenturl)
		writeResult("  Apache Detected: Yes\n")
		if apacheVersion != "" {
			versionStr := apacheVersion
			if apacheComment != "" {
				versionStr += " (" + apacheComment + ")"
			}
			writeResult("  Apache Version: %s (Source: %s)\n", versionStr, detectionSource)
		} else {
			versionStr := "Unknown"
			if apacheComment != "" { // e.g. Server: Apache (Debian)
				versionStr += " (OS/Distro Info: " + apacheComment + ")"
			}
			writeResult("  Apache Version: %s (Detected via: %s)\n", versionStr, detectionSource)
		}
		writeResult("  Requests Made: %d, Time: %.2fs, RPS: %.2f\n", requestCount, duration.Seconds(), rps)
	} else if debug {
		if primaryUrlResponded {
			writeResult("URL: %s - Apache Not Detected (primary URL status: %d)\n", currenturl, rootRespStatus)
		} else {
			writeResult("URL: %s - Apache Not Detected (primary URL failed to respond)\n", currenturl)
		}
		writeResult("  Requests Made: %d, Time: %.2fs, RPS: %.2f\n", requestCount, duration.Seconds(), rps)
	}

	return primaryUrlOkForSuccessCount
}

func newCollectorWithConfig(maxdepth int, proxyFunc colly.ProxyFunc, debug bool, writeResult func(string, ...interface{})) *colly.Collector {
	c := colly.NewCollector(
		colly.MaxDepth(maxdepth),
		colly.Async(true),
	)
	if proxyFunc != nil {
		c.SetProxyFunc(proxyFunc)
	}
	c.WithTransport(&http.Transport{
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   1000,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		DisableKeepAlives:     false,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	})
	c.SetRequestTimeout(50 * time.Second)
	cookiesJar, _ := cookiejar.New(nil)
	c.SetCookieJar(cookiesJar)
	c.OnRequest(func(r *colly.Request) {
		r.Headers.Set("User-Agent", userAgents[int(time.Now().UnixNano())%len(userAgents)])
		r.Headers.Set("Accept-Language", acceptLanguages[int(time.Now().UnixNano())%len(acceptLanguages)])
		r.Headers.Set("Accept", acceptHeaders[int(time.Now().UnixNano())%len(acceptHeaders)])
		r.Headers.Set("sec-ch-ua", secChUA[int(time.Now().UnixNano())%len(secChUA)])
		r.Headers.Set("sec-ch-ua-platform", secChUAPlatform[int(time.Now().UnixNano())%len(secChUAPlatform)])
		r.Headers.Set("sec-fetch-site", secFetchSite[int(time.Now().UnixNano())%len(secFetchSite)])
		r.Headers.Set("sec-fetch-mode", secFetchMode[0])
		r.Headers.Set("sec-fetch-user", secFetchUser[0])
		r.Headers.Set("sec-fetch-dest", secFetchDest[0])
		if debug {
			writeResult("Crawling %s\n", r.URL)
		}
	})
	if debug {
		c.OnRequest(func(r *colly.Request) {
			r.Headers.Set("User-Agent", "Mozilla/5.0 (compatible; Colly/2.1; +https://github.com/gocolly/colly)")
			writeResult("Crawling %s\n", r.URL)
		})
	}
	return c
}

// List of common browser user agents (rotated per request)
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
}

// List of common browser Accept-Language headers
var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.8",
	"en;q=0.7",
}

// List of common Accept headers
var acceptHeaders = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
}

// List of common sec-ch-ua headers
var secChUA = []string{
	"\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not:A-Brand\";v=\"99\"",
	"\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\"",
}

// List of common sec-ch-ua-platform headers
var secChUAPlatform = []string{
	"Windows",
	"macOS",
	"Linux",
}

// List of common sec-fetch headers
var secFetchSite = []string{"none", "same-origin", "cross-site"}
var secFetchMode = []string{"navigate"}
var secFetchUser = []string{"?1"}
var secFetchDest = []string{"document"}

// Helper to group status 0 errors by error type (removes domain names and variable parts)
func groupStatus0Error(errMsg string) string {
	// Common patterns
	if strings.Contains(errMsg, "dial tcp: lookup") && strings.Contains(errMsg, ": no such host") {
		return "dial tcp: lookup ...: no such host"
	}
	if strings.Contains(errMsg, "tls: failed to verify certificate: x509: certificate signed by unknown authority") {
		return "tls: failed to verify certificate: x509: certificate signed by unknown authority"
	}
	if strings.Contains(errMsg, "tls: failed to verify certificate: x509: certificate is valid for") {
		return "tls: failed to verify certificate: x509: certificate is valid for ..., not ..."
	}
	if strings.Contains(errMsg, "context deadline exceeded") {
		return "context deadline exceeded (Client.Timeout exceeded while awaiting headers)"
	}
	if strings.Contains(errMsg, "EOF") {
		return "EOF"
	}
	if strings.Contains(errMsg, "http2: timeout awaiting response headers") {
		return "http2: timeout awaiting response headers"
	}
	if strings.Contains(errMsg, "remote error: tls: illegal parameter") {
		return "remote error: tls: illegal parameter"
	}
	if strings.Contains(errMsg, "read tcp") && strings.Contains(errMsg, "wsarecv: An existing connection was forcibly closed by the remote host.") {
		return "read tcp ... wsarecv: An existing connection was forcibly closed by the remote host."
	}
	// Default: return the error message as-is
	return errMsg
}
