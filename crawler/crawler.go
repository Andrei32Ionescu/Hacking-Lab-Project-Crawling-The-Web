package crawler

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// Crawler represents a web crawler
type Crawler struct {
	client  *http.Client
	results []Quote
	mutex   sync.Mutex
}

// NewCrawler creates a new crawler instance
func NewCrawler() *Crawler {
	return &Crawler{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		results: make([]Quote, 0),
	}
}

// Crawl crawls a list of URLs and returns quotes
func (c *Crawler) Crawl(urls []string) ([]Quote, error) {
	var wg sync.WaitGroup
	errorChan := make(chan error, len(urls))

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			if err := c.crawlURL(url); err != nil {
				errorChan <- fmt.Errorf("error crawling %s: %v", url, err)
			}
		}(url)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errorChan)

	// Check for errors
	if len(errorChan) > 0 {
		return nil, <-errorChan // Return the first error
	}

	return c.results, nil
}

// crawlURL crawls a single URL and extracts quotes
func (c *Crawler) crawlURL(url string) error {
	fmt.Printf("Crawling: %s\n", url)

	// Make the HTTP request
	resp, err := c.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("got non-200 status code: %d", resp.StatusCode)
	}

	// Parse the HTML document
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return err
	}

	// Find the quotes
	doc.Find("div.quote").Each(func(i int, s *goquery.Selection) {
		// Extract text
		text := strings.TrimSpace(s.Find("span.text").Text())
		
		// Extract author
		author := strings.TrimSpace(s.Find("small.author").Text())
		
		// Extract tags
		var tags []string
		s.Find("div.tags a.tag").Each(func(i int, s *goquery.Selection) {
			tags = append(tags, strings.TrimSpace(s.Text()))
		})

		// Create a new quote
		quote := Quote{
			Text:   text,
			Author: author,
			Tags:   tags,
		}

		// Add it to our results
		c.mutex.Lock()
		c.results = append(c.results, quote)
		c.mutex.Unlock()
	})

	return nil
}