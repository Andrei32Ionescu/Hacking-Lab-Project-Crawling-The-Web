package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"webcrawler/crawler"
)

func main() {
	// Parse command line arguments
	outputDir := flag.String("outputdir", "./output", "Directory to store output files")
	outputFile := flag.String("outputfile", "", "Filename to save results (optional)")
	flag.Parse()

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate filename with timestamp if not provided
	var outputPath string
	if *outputFile == "" {
		timestamp := time.Now().Format("2006-01-02_150405")
		outputPath = filepath.Join(*outputDir, fmt.Sprintf("results_%s.json", timestamp))
	} else {
		outputPath = filepath.Join(*outputDir, *outputFile)
	}

	// Create our crawler
	c := crawler.NewCrawler()

	// Add URLs to crawl
	urls := []string{
		"http://quotes.toscrape.com/page/1/",
		"http://quotes.toscrape.com/page/2/",
	}

	// Start crawling
	fmt.Printf("Starting crawler at %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("Output will be saved to %s\n", outputPath)

	quotes, err := c.Crawl(urls)
	if err != nil {
		log.Fatalf("Crawling failed: %v", err)
	}

	// Save results to JSON file
	if err := crawler.SaveToJSON(quotes, outputPath); err != nil {
		log.Fatalf("Failed to save results: %v", err)
	}

	fmt.Printf("Crawling completed. Scraped %d quotes.\n", len(quotes))
	fmt.Printf("Results saved to %s\n", outputPath)
}