#!/bin/bash

echo "Starting crawler at $(date +'%Y-%m-%d_%H%M%S')"
timestamp=$(date +'%Y-%m-%d_%H%M%S')
outfile="/app/output/results_${timestamp}.json"
mkdir -p /app/output
python python_crawlers/stealth_crawler.py > "$outfile"
echo "Crawling completed. Results saved to $outfile"


##!/bin/sh
#
## Create timestamp in format YYYY-MM-DD_HHMMSS
#TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
#OUTPUT_FILE="/app/output/results_${TIMESTAMP}.json"
#
#echo "Starting python_crawlers at ${TIMESTAMP}"
#echo "Output will be saved to ${OUTPUT_FILE}"
#
#python /app/stealth_crawler.py --outputdir=/app/output --outputfile="results_${TIMESTAMP}.json"
#
#echo "Crawling completed. Results saved to ${OUTPUT_FILE}"

