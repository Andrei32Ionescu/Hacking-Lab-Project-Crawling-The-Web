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

// Counter for 403 Cloudflare errors
var cloudflare403Count int64

// Set to track domains with Cloudflare 403 errors
var cloudflareDomains sync.Map

// CSP stats counters
var totalCSPChecked int64
var hasCSPHeaderCount int64
var hasMetaCSPCount int64
var inlineScriptCount int64
var inlineStyleCount int64
var externalScriptCount int64
var evalUsageCount int64
var crossOriginScriptsCount int64
var sameOriginScriptsCount int64
var modernFrameworkCount int64
var sensitiveFormsCount int64
var hdrCTOCount int64
var cookieHttpOnlyCount int64
var outputEncodingCount int64
var inputValidationCount int64
var sandboxedIframesCount int64
var unsafeInlineEventHandlersCount int64
var jsonpEndpointsCount int64
var postMessageUsageCount int64
var riskHighCount int64
var riskMediumCount int64
var riskLowCount int64
var riskMinimalCount int64

func main() {
	// Command-line flags
	mode := flag.String("mode", "title", "Mode: title, jssearch, wordpress, csp or wix")
	keyword := flag.String("keyword", "", "Keyword to search for in JS files (jssearch mode)")
	depth := flag.Int("depth", 1, "Crawl depth (1 = only main page)")
	csvfile := flag.String("file", "top-1m.csv", "CSV file with domains")
	logToConsole := flag.Bool("console", false, "Also log results to console")
	concurrency := flag.Int("concurrency", 1, "Number of sites to crawl in parallel")
	debug := flag.Bool("debug", false, "Show detailed crawl/debug logs")
	indexed := flag.Bool("indexed", true, "CSV has an index column; domain is in the second column")
	resultsFileN := flag.String("results", "results", "File to write results to")
	flag.Parse()

	// Always load the CSV file from the datasets folder
	csvFilePath := "datasets/" + *csvfile

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
	var statusCounts sync.Map
	var status0Errors sync.Map

	// Load CSV file
	file, err := os.Open(csvFilePath)
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
			} else if *mode == "csp" {
				gotValid = crawlForCSP(url, *depth, writeResult, proxyFunc, *debug, &statusCounts, &status0Errors)
			} else if *mode == "wix" {
				gotValid = crawlForWix(url, *depth, writeResult, proxyFunc, *debug, &statusCounts, &status0Errors)
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

	// Write all unique Cloudflare 403 domains to file (overwrite previous content)
	cfFile, cfErr := os.Create("cloudflare-protected-domains.csv")
	if cfErr == nil {
		cloudflareDomains.Range(func(key, _ any) bool {
			cfFile.WriteString(fmt.Sprintf("%s\n", key.(string)))
			return true
		})
		cfFile.Close()
	}

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
	// Print Cloudflare 403 Forbidden error count
	if cloudflare403Count > 0 {
		writeResult("Cloudflare 403 Forbidden errors: %d\n", cloudflare403Count)
	}

	if *mode == "csp" {
		headerCount := atomic.LoadInt64(&hasCSPHeaderCount)
		metaCount := atomic.LoadInt64(&hasMetaCSPCount)

		writeResult("\nCSP and XSS Protection Analysis over %d domains:\n", totalCrawled)
		writeResult("CSP Implementation:\n")
		writeResult("  Has CSP header: %d (%.1f%%)\n", headerCount, (float64(headerCount)/float64(successCount))*100)
		writeResult("  Has meta CSP: %d (%.1f%%)\n", metaCount, (float64(metaCount)/float64(successCount))*100)

		writeResult("\nXSS Risk Indicators (average per url):\n")
		writeResult("  Inline scripts: %.2f\n", float64(atomic.LoadInt64(&inlineScriptCount))/float64(successCount))
		writeResult("  Inline event handlers: %.2f\n", float64(atomic.LoadInt64(&unsafeInlineEventHandlersCount))/float64(successCount))
		writeResult("  Inline styles: %.2f\n", float64(atomic.LoadInt64(&inlineStyleCount))/float64(successCount))
		writeResult("  eval() usage: %.2f\n", float64(atomic.LoadInt64(&evalUsageCount))/float64(successCount))
		writeResult("  postMessage usage: %.2f\n", float64(atomic.LoadInt64(&postMessageUsageCount))/float64(successCount))
		writeResult("  JSONP endpoints: %.2f\n", float64(atomic.LoadInt64(&jsonpEndpointsCount))/float64(successCount))

		writeResult("\nScript Loading Patterns (average per url):\n")
		writeResult("  External scripts: %.2f\n", float64(atomic.LoadInt64(&externalScriptCount))/float64(successCount))
		writeResult("  Cross-origin scripts: %.2f\n", float64(atomic.LoadInt64(&crossOriginScriptsCount))/float64(successCount))
		writeResult("  Same-origin scripts: %.2f\n", float64(atomic.LoadInt64(&sameOriginScriptsCount))/float64(successCount))

		writeResult("\nXSS Protection Measures:\n")
		writeResult("  Modern frameworks: %d (%.1f%%)\n", atomic.LoadInt64(&modernFrameworkCount), (float64(atomic.LoadInt64(&modernFrameworkCount))/float64(successCount))*100)
		writeResult("  X-Content-Type-Options: %d (%.1f%%)\n", atomic.LoadInt64(&hdrCTOCount), (float64(atomic.LoadInt64(&hdrCTOCount))/float64(successCount))*100)
		writeResult("  Output encoding: %d (%.1f%%)\n", atomic.LoadInt64(&outputEncodingCount), (float64(atomic.LoadInt64(&outputEncodingCount))/float64(successCount))*100)
		writeResult("  Input validation: %d (%.1f%%)\n", atomic.LoadInt64(&inputValidationCount), (float64(atomic.LoadInt64(&inputValidationCount))/float64(successCount))*100)
		writeResult("  Sandboxed iframes: %d (%.1f%%)\n", atomic.LoadInt64(&sandboxedIframesCount), (float64(atomic.LoadInt64(&sandboxedIframesCount))/float64(successCount))*100)
		writeResult("  HttpOnly cookies: %d (%.1f%%)\n", atomic.LoadInt64(&cookieHttpOnlyCount), (float64(atomic.LoadInt64(&cookieHttpOnlyCount))/float64(successCount))*100)
		writeResult("  Sensitive forms: %d (%.1f%%)\n", atomic.LoadInt64(&sensitiveFormsCount), (float64(atomic.LoadInt64(&sensitiveFormsCount))/float64(successCount))*100)

		writeResult("\nXSS Risk Assessment (sites without CSP):\n")
		writeResult("  High risk: %d (%.1f%%)\n", atomic.LoadInt64(&riskHighCount), (float64(atomic.LoadInt64(&riskHighCount))/float64(successCount))*100)
		writeResult("  Medium risk: %d (%.1f%%)\n", atomic.LoadInt64(&riskMediumCount), (float64(atomic.LoadInt64(&riskMediumCount))/float64(successCount))*100)
		writeResult("  Low risk: %d (%.1f%%)\n", atomic.LoadInt64(&riskLowCount), (float64(atomic.LoadInt64(&riskLowCount))/float64(successCount))*100)
		writeResult("  Minimal risk: %d (%.1f%%)\n", atomic.LoadInt64(&riskMinimalCount), (float64(atomic.LoadInt64(&riskMinimalCount))/float64(successCount))*100)
	}
}

func ensureHTTPS(domain string) string {
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return domain
	}
	return "https://" + domain
}

func crawlForCSP(currenturl string, maxdepth int, writeResult func(string, ...interface{}), proxyFunc colly.ProxyFunc, debug bool, statusCounts *sync.Map, status0Errors *sync.Map) bool {
	c := newCollectorWithConfig(maxdepth, proxyFunc, debug, writeResult)
	var gotValid bool
	var hasCSPHeader bool
	var hasMetaCSP bool
	var hasInlineScript bool
	var hasInlineStyle bool
	var hasInlineEventHandlers bool
	var hasHTTPScripts bool
	var hasEvalUsage bool
	var hasCrossOriginScripts bool
	var hasModernFramework bool
	var hasSensitiveForms bool
	var hasOutputEncoding bool
	var hasInputValidation bool
	var hasXCTO bool
	var hasSandboxedIframes bool
	var hasPostMessage bool
	var hasJSONP bool
	var sameOriginScripts int
	var crossOriginScripts int
	var externalDomains = make(map[string]bool)

	// Parse the current domain for comparison
	currentURL, _ := url.Parse(currenturl)
	currentDomain := currentURL.Hostname()

	c.OnResponse(func(r *colly.Response) {
		status := r.StatusCode
		if status >= 200 && status < 300 {
			gotValid = true
		}
		// count status codes
		val, _ := statusCounts.LoadOrStore(status, int64(0))
		statusCounts.Store(status, val.(int64)+1)

		atomic.AddInt64(&totalCSPChecked, 1)
		hdrs := r.Headers

		// Check for CSP header
		if hdrs.Get("Content-Security-Policy") != "" {
			hasCSPHeader = true
			atomic.AddInt64(&hasCSPHeaderCount, 1)
		}

		// Check for X-Content-Type-Options
		if hdrs.Get("X-Content-Type-Options") == "nosniff" {
			hasXCTO = true
			atomic.AddInt64(&hdrCTOCount, 1)
		}
	})

	// Check for inline scripts
	c.OnHTML("script:not([src])", func(e *colly.HTMLElement) {
		content := strings.ToLower(e.Text)
		if len(strings.TrimSpace(content)) > 0 {
			hasInlineScript = true
			atomic.AddInt64(&inlineScriptCount, 1)
		}

		// Check for eval usage
		evalPatterns := []string{
			"eval(", "eval ", "new function(", "settimeout(\"", "setinterval(\"",
			"execscript(", "document.write(", "document.writeln(", "innerhtml",
			"outerhtml", ".html(", "dangerouslysetinnerhtml",
		}
		for _, pattern := range evalPatterns {
			if strings.Contains(content, pattern) {
				hasEvalUsage = true
				atomic.AddInt64(&evalUsageCount, 1)
				break
			}
		}

		// Check for modern frameworks
		frameworkPatterns := []string{
			"react", "angular", "vue.", "svelte", "ember",
			"_react", "_angular", "_vue", "ng-app", "v-app",
			"reactdom", "angularjs", "vuejs", "next.js", "nuxt",
		}
		for _, pattern := range frameworkPatterns {
			if strings.Contains(content, pattern) {
				hasModernFramework = true
				atomic.AddInt64(&modernFrameworkCount, 1)
				break
			}
		}

		// Check for output encoding
		encodingPatterns := []string{
			"escapehtml", "escape_html", "htmlescape", "encodeuricomponent",
			"_.escape", "handlebars.escapeexpression", "dompurify", "sanitize",
			"textcontent", "innertext", "createtextnode", "he.encode", "html-entities",
			"escape-html", "sanitize-html", "xss-filters",
		}
		for _, pattern := range encodingPatterns {
			if strings.Contains(content, pattern) {
				hasOutputEncoding = true
				atomic.AddInt64(&outputEncodingCount, 1)
				break
			}
		}

		// Check for postMessage usage
		if strings.Contains(content, "postmessage") || strings.Contains(content, "addeventlistener('message'") || strings.Contains(content, "onmessage") {
			hasPostMessage = true
			atomic.AddInt64(&postMessageUsageCount, 1)
		}

		// Check for JSONP patterns
		jsonpPatterns := []string{
			"callback=", "jsonp", "?callback", "&callback", "jsonpcallback",
			"window[", "window.", "eval(", "new function(",
		}
		patternCount := 0
		for _, pattern := range jsonpPatterns {
			if strings.Contains(content, pattern) {
				patternCount++
			}
		}
		if patternCount >= 2 {
			hasJSONP = true
			atomic.AddInt64(&jsonpEndpointsCount, 1)
		}
	})

	// Check for inline event handlers
	eventHandlers := []string{"onclick", "onload", "onerror", "onmouseover", "onmouseout", "onchange", "onsubmit", "onfocus", "onblur", "onkeyup", "onkeydown", "onkeypress"}
	for _, handler := range eventHandlers {
		c.OnHTML("["+handler+"]", func(e *colly.HTMLElement) {
			hasInlineEventHandlers = true
			atomic.AddInt64(&unsafeInlineEventHandlersCount, 1)
		})
	}

	// Check for inline styles
	c.OnHTML("style", func(e *colly.HTMLElement) {
		if len(strings.TrimSpace(e.Text)) > 0 {
			hasInlineStyle = true
			atomic.AddInt64(&inlineStyleCount, 1)
		}
	})

	// Check for elements with style attribute
	c.OnHTML("[style]", func(e *colly.HTMLElement) {
		if e.Attr("style") != "" {
			hasInlineStyle = true
		}
	})

	// Check for external scripts
	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		src := strings.TrimSpace(e.Attr("src"))
		if src == "" {
			return
		}

		scriptURL, err := url.Parse(src)
		if err != nil {
			return
		}

		if scriptURL.Host == "" {
			scriptURL = e.Request.URL.ResolveReference(scriptURL)
		}

		atomic.AddInt64(&externalScriptCount, 1)

		// Check if it's cross-origin or same-origin
		if scriptURL.Host == currentDomain {
			sameOriginScripts++
			atomic.AddInt64(&sameOriginScriptsCount, 1)
		} else {
			crossOriginScripts++
			hasCrossOriginScripts = true
			atomic.AddInt64(&crossOriginScriptsCount, 1)
			externalDomains[scriptURL.Host] = true
		}
	})

	// Check for meta CSP
	c.OnHTML("meta[http-equiv=Content-Security-Policy]", func(e *colly.HTMLElement) {
		hasMetaCSP = true
		atomic.AddInt64(&hasMetaCSPCount, 1)
	})

	// Check for forms with sensitive data
	c.OnHTML("form", func(e *colly.HTMLElement) {
		// Check for password, email, credit card, etc..
		e.ForEach("input", func(_ int, el *colly.HTMLElement) {
			inputType := strings.ToLower(el.Attr("type"))
			inputName := strings.ToLower(el.Attr("name"))
			inputId := strings.ToLower(el.Attr("id"))

			sensitiveTypes := []string{"password", "email", "tel", "ssn", "creditcard"}
			sensitivePatterns := []string{"pass", "pwd", "email", "card", "cvv", "ssn", "social", "tax", "bank", "account", "routing"}

			for _, t := range sensitiveTypes {
				if inputType == t {
					hasSensitiveForms = true
					atomic.AddInt64(&sensitiveFormsCount, 1)
					return
				}
			}

			for _, p := range sensitivePatterns {
				if strings.Contains(inputName, p) || strings.Contains(inputId, p) {
					hasSensitiveForms = true
					atomic.AddInt64(&sensitiveFormsCount, 1)
					return
				}
			}
		})
	})

	// Check for input validation
	c.OnHTML("input[pattern], input[required], input[minlength], input[maxlength], select[required], textarea[required]", func(e *colly.HTMLElement) {
		hasInputValidation = true
		atomic.AddInt64(&inputValidationCount, 1)
	})

	// Check for sandboxed iframes
	c.OnHTML("iframe[sandbox]", func(e *colly.HTMLElement) {
		hasSandboxedIframes = true
		atomic.AddInt64(&sandboxedIframesCount, 1)
	})

	// Check cookies
	c.OnResponse(func(r *colly.Response) {
		for _, cookie := range r.Headers.Values("Set-Cookie") {
			cookieLower := strings.ToLower(cookie)
			if strings.Contains(cookieLower, "httponly") {
				atomic.AddInt64(&cookieHttpOnlyCount, 1)
			}
		}
	})

	addErrorHandler(c, writeResult, statusCounts, status0Errors, debug)
	err := c.Visit(currenturl)
	if err != nil && debug {
		fmt.Println("Error visiting page:", err)
	}

	c.Wait()

	// Risk assessment based on findings
	if gotValid {
		// Determine risk level
		var riskLevel string
		if hasCSPHeader || hasMetaCSP {
			riskLevel = "PROTECTED"
		} else {
			var riskCount, mitigationCount int

			// Risk indicators
			if hasInlineScript {
				riskCount++
			}
			if hasInlineEventHandlers {
				riskCount++
			}
			if hasInlineStyle {
				riskCount++
			}
			if hasEvalUsage {
				riskCount++
			}
			if hasHTTPScripts {
				riskCount++
			}
			if hasCrossOriginScripts {
				riskCount++
			}
			if len(externalDomains) > 1 {
				riskCount++
			}
			if hasSensitiveForms {
				riskCount++
			}
			if hasPostMessage {
				riskCount++
			}
			if hasJSONP {
				riskCount++
			}

			// Mitigation indicators
			if hasModernFramework {
				mitigationCount++
			}
			if hasOutputEncoding {
				mitigationCount++
			}
			if hasInputValidation {
				mitigationCount++
			}
			if hasXCTO {
				mitigationCount++
			}
			if hasSandboxedIframes {
				mitigationCount++
			}
			// If majority of scripts are same-origin
			if sameOriginScripts > crossOriginScripts {
				mitigationCount++
			}

			netScore := riskCount - mitigationCount

			// Classify risk
			switch {
			case netScore >= 4:
				atomic.AddInt64(&riskHighCount, 1)
				riskLevel = "HIGH"
			case netScore >= 3:
				atomic.AddInt64(&riskMediumCount, 1)
				riskLevel = "MEDIUM"
			case netScore >= 2:
				atomic.AddInt64(&riskLowCount, 1)
				riskLevel = "LOW"
			default:
				atomic.AddInt64(&riskMinimalCount, 1)
				riskLevel = "MINIMAL"
			}

			var protections []string
			if hasCSPHeader {
				protections = append(protections, "CSP")
			}
			if hasMetaCSP {
				protections = append(protections, "MetaCSP")
			}
			if hasModernFramework {
				protections = append(protections, "Framework")
			}
			if hasXCTO {
				protections = append(protections, "XCTO")
			}
			if hasOutputEncoding {
				protections = append(protections, "Encoding")
			}
			if hasInputValidation {
				protections = append(protections, "Validation")
			}
			if hasSandboxedIframes {
				protections = append(protections, "Sandbox")
			}

			var risks []string
			if hasInlineScript {
				risks = append(risks, "InlineJS")
			}
			if hasInlineEventHandlers {
				risks = append(risks, "EventHandlers")
			}
			if hasEvalUsage {
				risks = append(risks, "Eval")
			}
			if hasCrossOriginScripts {
				risks = append(risks, fmt.Sprintf("XOrigin(%d)", crossOriginScripts))
			}
			if len(externalDomains) > 1 {
				risks = append(risks, fmt.Sprintf("ExtDom(%d)", len(externalDomains)))
			}
			if hasSensitiveForms {
				risks = append(risks, "SensitiveForms")
			}
			if hasPostMessage {
				risks = append(risks, "PostMessage")
			}
			if hasJSONP {
				risks = append(risks, "JSONP")
			}

			protectionStr := "none"
			if len(protections) > 0 {
				protectionStr = strings.Join(protections, ",")
			}

			riskStr := "none"
			if len(risks) > 0 {
				riskStr = strings.Join(risks, ",")
			}

			writeResult("SITE: %s | RISK LEVEL: %s | PROTECTIONS: %s | RISKS: %s | SCRIPTS: %d same-origin, %d cross-origin\n", currenturl, riskLevel, protectionStr, riskStr, sameOriginScripts, crossOriginScripts)
		}
	}

	return gotValid
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
	addErrorHandler(c, writeResult, statusCounts, status0Errors, debug)
	err := c.Visit(currenturl)
	if err != nil && debug {
		fmt.Println("Error visiting page:", err)
	}
	c.Wait()
	return gotValid
}

func crawlForWordPress(currenturl string, maxdepth int, writeResult func(string, ...interface{}), proxyFunc colly.ProxyFunc, debug bool, statusCounts *sync.Map, status0Errors *sync.Map) bool {
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
	addErrorHandler(c, writeResult, statusCounts, status0Errors, debug)

	err := c.Visit(currenturl)
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
	addErrorHandler(c, writeResult, statusCounts, status0Errors, debug)
	err := c.Visit(currenturl)
	if err != nil && debug {
		fmt.Println("Error visiting page:", err)
	}
	c.Wait()
	return gotValid
}

func crawlForWix(currenturl string, maxdepth int, writeResult func(string, ...interface{}), proxyFunc colly.ProxyFunc, debug bool, statusCounts *sync.Map, status0Errors *sync.Map) bool {
	c := newCollectorWithConfig(maxdepth, proxyFunc, debug, writeResult)
	var gotValid bool
	var pageTitle string
	var isWixSite bool
	
	// Store Wix plugins with versions
	wixPlugins := make(map[string]string)
	
	// Common Wix plugins to look for with their version patterns
	commonWixPlugins := map[string]struct{
		name string
		versionPatterns []string
	}{
		"blog": {"Blog", []string{
			"blog-version", "blogVersion", "blog_version",
			"wix-blog-version", "wixBlogVersion", "wix_blog_version",
			"version=", "v=", "ver=", "release=", "build=",
			"blog.min.js?v=", "blog.js?v=", "blog.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-blog", "wixBlog", "wix_blog",
			"blog.min.js", "blog.js", "blog.min.css",
		}},
		"forum": {"Forum", []string{
			"forum-version", "forumVersion", "forum_version",
			"wix-forum-version", "wixForumVersion", "wix_forum_version",
			"version=", "v=", "ver=", "release=", "build=",
			"forum.min.js?v=", "forum.js?v=", "forum.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-forum", "wixForum", "wix_forum",
			"forum.min.js", "forum.js", "forum.min.css",
		}},
		"members": {"Members Area", []string{
			"members-version", "membersVersion", "members_version",
			"wix-members-version", "wixMembersVersion", "wix_members_version",
			"version=", "v=", "ver=", "release=", "build=",
			"members.min.js?v=", "members.js?v=", "members.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-members", "wixMembers", "wix_members",
			"members.min.js", "members.js", "members.min.css",
		}},
		"store": {"Wix Stores", []string{
			"store-version", "storeVersion", "store_version",
			"wix-store-version", "wixStoreVersion", "wix_store_version",
			"ecommerce-version", "ecommerceVersion", "ecommerce_version",
			"version=", "v=", "ver=", "release=", "build=",
			"store.min.js?v=", "store.js?v=", "store.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-store", "wixStore", "wix_store",
			"store.min.js", "store.js", "store.min.css",
		}},
		"bookings": {"Wix Bookings", []string{
			"bookings-version", "bookingsVersion", "bookings_version",
			"wix-bookings-version", "wixBookingsVersion", "wix_bookings_version",
			"version=", "v=", "ver=", "release=", "build=",
			"bookings.min.js?v=", "bookings.js?v=", "bookings.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-bookings", "wixBookings", "wix_bookings",
			"bookings.min.js", "bookings.js", "bookings.min.css",
		}},
		"events": {"Wix Events", []string{
			"events-version", "eventsVersion", "events_version",
			"wix-events-version", "wixEventsVersion", "wix_events_version",
			"version=", "v=", "ver=", "release=", "build=",
			"events.min.js?v=", "events.js?v=", "events.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-events", "wixEvents", "wix_events",
			"events.min.js", "events.js", "events.min.css",
		}},
		"restaurants": {"Wix Restaurants", []string{
			"restaurants-version", "restaurantsVersion", "restaurants_version",
			"wix-restaurants-version", "wixRestaurantsVersion", "wix_restaurants_version",
			"version=", "v=", "ver=", "release=", "build=",
			"restaurants.min.js?v=", "restaurants.js?v=", "restaurants.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-restaurants", "wixRestaurants", "wix_restaurants",
			"restaurants.min.js", "restaurants.js", "restaurants.min.css",
		}},
		"hotels": {"Wix Hotels", []string{
			"hotels-version", "hotelsVersion", "hotels_version",
			"wix-hotels-version", "wixHotelsVersion", "wix_hotels_version",
			"version=", "v=", "ver=", "release=", "build=",
			"hotels.min.js?v=", "hotels.js?v=", "hotels.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-hotels", "wixHotels", "wix_hotels",
			"hotels.min.js", "hotels.js", "hotels.min.css",
		}},
		"music": {"Wix Music", []string{
			"music-version", "musicVersion", "music_version",
			"wix-music-version", "wixMusicVersion", "wix_music_version",
			"version=", "v=", "ver=", "release=", "build=",
			"music.min.js?v=", "music.js?v=", "music.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-music", "wixMusic", "wix_music",
			"music.min.js", "music.js", "music.min.css",
		}},
		"video": {"Wix Video", []string{
			"video-version", "videoVersion", "video_version",
			"wix-video-version", "wixVideoVersion", "wix_video_version",
			"version=", "v=", "ver=", "release=", "build=",
			"video.min.js?v=", "video.js?v=", "video.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-video", "wixVideo", "wix_video",
			"video.min.js", "video.js", "video.min.css",
		}},
		"chat": {"Wix Chat", []string{
			"chat-version", "chatVersion", "chat_version",
			"wix-chat-version", "wixChatVersion", "wix_chat_version",
			"version=", "v=", "ver=", "release=", "build=",
			"chat.min.js?v=", "chat.js?v=", "chat.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-chat", "wixChat", "wix_chat",
			"chat.min.js", "chat.js", "chat.min.css",
		}},
		"forms": {"Wix Forms", []string{
			"forms-version", "formsVersion", "forms_version",
			"wix-forms-version", "wixFormsVersion", "wix_forms_version",
			"version=", "v=", "ver=", "release=", "build=",
			"forms.min.js?v=", "forms.js?v=", "forms.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-forms", "wixForms", "wix_forms",
			"forms.min.js", "forms.js", "forms.min.css",
		}},
		"shoutout": {"Wix ShoutOut", []string{
			"shoutout-version", "shoutoutVersion", "shoutout_version",
			"wix-shoutout-version", "wixShoutoutVersion", "wix_shoutout_version",
			"version=", "v=", "ver=", "release=", "build=",
			"shoutout.min.js?v=", "shoutout.js?v=", "shoutout.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-shoutout", "wixShoutout", "wix_shoutout",
			"shoutout.min.js", "shoutout.js", "shoutout.min.css",
		}},
		"ascend": {"Wix Ascend", []string{
			"ascend-version", "ascendVersion", "ascend_version",
			"wix-ascend-version", "wixAscendVersion", "wix_ascend_version",
			"version=", "v=", "ver=", "release=", "build=",
			"ascend.min.js?v=", "ascend.js?v=", "ascend.min.css?v=",
			"data-version", "data-ver", "data-v",
			"wix-ascend", "wixAscend", "wix_ascend",
			"ascend.min.js", "ascend.js", "ascend.min.css",
		}},
	}

	c.OnResponse(func(r *colly.Response) {
		status := r.StatusCode
		if status >= 200 && status < 300 {
			gotValid = true
		}
		val, _ := statusCounts.LoadOrStore(status, int64(0))
		statusCounts.Store(status, val.(int64)+1)
		
		// Check response headers for Wix indicators
		if r.Headers.Get("X-Wix-Server-Artifact-Id") != "" {
			isWixSite = true
		}
	})

	c.OnHTML("title", func(e *colly.HTMLElement) {
		pageTitle = e.Text
	})

	// Check for Wix-specific indicators in HTML elements
	c.OnHTML("*", func(e *colly.HTMLElement) {
		// Check data attributes
		for _, attrName := range []string{"data-hook", "data-wix", "class", "id"} {
			if val := e.Attr(attrName); val != "" {
				if strings.Contains(val, "wix-") || 
				   strings.Contains(val, "_wix") || 
				   strings.Contains(val, "wix") {
					isWixSite = true
					
					// Check for plugin indicators in class names
					for pluginKey, pluginInfo := range commonWixPlugins {
						if strings.Contains(val, pluginKey) {
							version := extractVersion(val, pluginInfo.versionPatterns)
							if version != "" {
								wixPlugins[pluginInfo.name] = version
							} else {
								wixPlugins[pluginInfo.name] = "detected"
							}
						}
					}
				}
			}
		}
	})

	// Check for Wix-specific scripts
	c.OnHTML("script", func(e *colly.HTMLElement) {
		scriptContent := e.Text
		
		// Check script src
		if src := e.Attr("src"); src != "" {
			if strings.Contains(src, "wix.com") || 
			   strings.Contains(src, "wixstatic.com") || 
			   strings.Contains(src, "wixsite.com") {
				isWixSite = true
				
				// Check for plugin-specific scripts
				for pluginKey, pluginInfo := range commonWixPlugins {
					if strings.Contains(src, pluginKey) {
						version := extractVersion(src, pluginInfo.versionPatterns)
						if version != "" {
							wixPlugins[pluginInfo.name] = version
						} else {
							wixPlugins[pluginInfo.name] = "detected"
						}
					}
				}
			}
		}
		
		// Check inline script content
		if scriptContent != "" {
			if strings.Contains(scriptContent, "wix") || 
			   strings.Contains(scriptContent, "Wix") || 
			   strings.Contains(scriptContent, "_wix") {
				isWixSite = true
				
				// Check for plugin indicators in script content
				for pluginKey, pluginInfo := range commonWixPlugins {
					if strings.Contains(scriptContent, pluginKey) {
						version := extractVersion(scriptContent, pluginInfo.versionPatterns)
						if version != "" {
							wixPlugins[pluginInfo.name] = version
						} else {
							wixPlugins[pluginInfo.name] = "detected"
						}
					}
				}
			}
		}
	})

	// Check for Wix-specific meta tags
	c.OnHTML("meta", func(e *colly.HTMLElement) {
		name := e.Attr("name")
		property := e.Attr("property")
		content := e.Attr("content")
		
		if (strings.Contains(name, "wix") || 
			strings.Contains(property, "wix") || 
			strings.Contains(content, "wix")) {
			isWixSite = true
			
			// Check for plugin indicators in meta tags
			for pluginKey, pluginInfo := range commonWixPlugins {
				if strings.Contains(content, pluginKey) || 
				   strings.Contains(name, pluginKey) || 
				   strings.Contains(property, pluginKey) {
					version := extractVersion(content, pluginInfo.versionPatterns)
					if version != "" {
						wixPlugins[pluginInfo.name] = version
					} else {
						wixPlugins[pluginInfo.name] = "detected"
					}
				}
			}
		}
	})

	// Check for Wix-specific links
	c.OnHTML("link[href]", func(e *colly.HTMLElement) {
		href := e.Attr("href")
		if strings.Contains(href, "wix.com") || 
		   strings.Contains(href, "wixstatic.com") || 
		   strings.Contains(href, "wixsite.com") {
			isWixSite = true
			
			// Check for plugin indicators in links
			for pluginKey, pluginInfo := range commonWixPlugins {
				if strings.Contains(href, pluginKey) {
					version := extractVersion(href, pluginInfo.versionPatterns)
					if version != "" {
						wixPlugins[pluginInfo.name] = version
					} else {
						wixPlugins[pluginInfo.name] = "detected"
					}
				}
			}
		}
	})

	addErrorHandler(c, writeResult, statusCounts, status0Errors, debug)
	err := c.Visit(currenturl)
	if err != nil && debug {
		fmt.Println("Error visiting page:", err)
	}
	c.Wait()

	// Print results
	if gotValid {
		writeResult("******* Page Title: %s *******\n", pageTitle)
		writeResult("Page URL: %s\n", currenturl)
		
		if isWixSite {
			writeResult("Platform: Wix\n")
			
			if len(wixPlugins) > 0 {
				writeResult("\nDetected Wix Plugins:\n")
				for plugin, version := range wixPlugins {
					writeResult("  - %s: %s\n", plugin, version)
				}
			} else {
				writeResult("\nNo specific Wix plugins detected\n")
			}
		} else {
			writeResult("Platform: Not Wix\n")
		}
	}

	return gotValid
}

// Helper function to extract version from content using patterns
func extractVersion(content string, patterns []string) string {
	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			// Try to extract version after the pattern
			parts := strings.Split(content, pattern)
			if len(parts) > 1 {
				// Look for version-like strings after the pattern
				versionPart := parts[1]
				// Common version separators
				separators := []string{" ", "\"", "'", "&", "?", "=", "/", "\\", ")", "]", "}", ",", ";", "\n", "\r", "\t"}
				for _, sep := range separators {
					if strings.Contains(versionPart, sep) {
						version := strings.Split(versionPart, sep)[0]
						// Clean up the version string
						version = strings.Trim(version, " \t\n\r\"'()[]{}")
						if version != "" {
							return version
						}
					}
				}
			}
		}
	}
	return ""
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

func addErrorHandler(c *colly.Collector, writeResult func(string, ...interface{}), statusCounts *sync.Map, status0Errors *sync.Map, debug bool) {
	c.OnError(func(r *colly.Response, err error) {
		status := r.StatusCode
		val, _ := statusCounts.LoadOrStore(status, int64(0))
		statusCounts.Store(status, val.(int64)+1)
		if status == 0 {
			grouped := groupStatus0Error(err.Error())
			cnt, _ := status0Errors.LoadOrStore(grouped, 0)
			status0Errors.Store(grouped, cnt.(int)+1)
		}
		// Count Cloudflare 403 Forbidden errors and store domain (in memory only)
		if status == 403 && r.Body != nil && len(r.Body) > 0 {
			if strings.Contains(strings.ToLower(string(r.Body)), "cloudflare") || strings.Contains(strings.ToLower(string(r.Body)), "_cf_chl_opt") {
				atomic.AddInt64(&cloudflare403Count, 1)
				// Extract domain from URL
				if r.Request != nil && r.Request.URL != nil {
					domain := r.Request.URL.Hostname()
					if domain != "" {
						cloudflareDomains.LoadOrStore(domain, true)
					}
				}
			}
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
