#!/bin/bash
cd webcrawler

# Create timestamp in format YYYY-MM-DD_HHMMSS
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
OUTPUT_FILE="/app/output/results_${TIMESTAMP}.json"

echo "Starting crawler at ${TIMESTAMP}"
echo "Output will be saved to ${OUTPUT_FILE}"

scrapy crawl quotes -o "${OUTPUT_FILE}"

echo "Crawling completed. Results saved to ${OUTPUT_FILE}"