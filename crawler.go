package main

import (
	"encoding/csv"
	"fmt"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"

	"github.com/gocolly/colly"
)

// initialize a map to store visited URLs
var visitedurls = make(map[string]bool)

func main() {
	// Start timing
	start := time.Now()

	// Open CSV file
	file, err := os.Open("domains-sample.csv")
	if err != nil {
		fmt.Println("Failed to open domains file:", err)
		return
	}
	defer file.Close()

	// Read all domains from CSV
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Failed to read CSV:", err)
		return
	}

	// Loop through the domain list
	for _, row := range records {
		if len(row) == 0 {
			continue
		}
		domain := strings.TrimSpace(row[1])
		if domain == "" {
			continue
		}
		url := ensureHTTPS(domain)
		// url := domain
		fmt.Printf("\n--- Starting crawl for: %s ---\n", url)
		crawl(url, 2)
	}

	// End timing and print duration
	elapsed := time.Since(start)
	fmt.Printf("\nScraping completed in %s\n", elapsed)
	fmt.Printf("Scraped %v urls\n", len(visitedurls))
	fmt.Printf("Scraped %v urls per second\n", float64(len(visitedurls))/elapsed.Seconds())
}

func ensureHTTPS(domain string) string {
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return domain
	}
	return "https://" + domain
}

func crawl(currenturl string, maxdepth int) {
	// instantiate  a new collector
	c := colly.NewCollector(
		// colly.AllowedDomains("www.scrapingcourse.com"),
		colly.MaxDepth(maxdepth),
		colly.Async(true),
	)

	// set concurrency limit and introduce delays between requests
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 5,
		// Delay:       0 * time.Second,
	})

	// add an OnRequest callback to track progress
	c.OnRequest(func(r *colly.Request) {
		// set custom headers
		r.Headers.Set("User-Agent", "Mozilla/5.0 (compatible; Colly/2.1; +https://github.com/gocolly/colly)")
		fmt.Println("Crawling", r.URL)
	})

	// manage cookies
	cookiesJar, _ := cookiejar.New(nil)
	c.SetCookieJar(cookiesJar)

	// extract and log the page title
	c.OnHTML("title", func(e *colly.HTMLElement) {
		fmt.Println("Page Title:", e.Text)
	})

	// ----- find and visit all links ---- //
	// select the href attribute of all anchor tags
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		// get absolute URL
		link := e.Request.AbsoluteURL(e.Attr("href"))
		// check if current URL has already been visited
		if link != "" && !visitedurls[link] {
			// add current URL to visitedURLs
			visitedurls[link] = true
			fmt.Println("Found link:", link)
			// visit current URL
			e.Request.Visit(link)
		}
	})

	// handle request errors
	c.OnError(func(e *colly.Response, err error) {
		fmt.Println("Request URL:", e.Request.URL, "failed with response:", e, "\nError:", err)
	})

	// visit the seed URL
	err := c.Visit(currenturl)
	if err != nil {
		fmt.Println("Error visiting page:", err)
	}

	// wait for all goroutines to finish
	c.Wait()

}
