#!/bin/sh

# Create timestamp in format YYYY-MM-DD_HHMMSS
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
OUTPUT_FILE="/app/output/results_${TIMESTAMP}.json"

echo "Starting crawler at ${TIMESTAMP}"
echo "Output will be saved to ${OUTPUT_FILE}"

python /app/stealth_crawler.py --outputdir=/app/output --outputfile="results_${TIMESTAMP}.json"

echo "Crawling completed. Results saved to ${OUTPUT_FILE}"
