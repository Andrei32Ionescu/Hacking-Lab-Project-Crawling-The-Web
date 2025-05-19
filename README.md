# Hakrawler

Fast golang web crawler for gathering URLs and JavaScript file locations with advanced headless browser detection. This is basically a simple implementation of the awesome Gocolly library with additional features.

## Docker Installation
```bash
  docker build -t hakrawler .
```


## Example usage

### Crawling
```bash
  # Crawl google.com domain
  echo https://google.com | docker run --rm -i hakrawler

  # Crawl top 100 domains from CSV with headless detection:
  docker run --rm -v $(pwd)/top-1m.csv:/app/top-1m.csv hakrawler -csv top-1m.csv -n 100 -headless

  # Advanced detection with proxy
  docker run --rm -v $(pwd)/top-1m.csv:/app/top-1m.csv hakrawler -csv top-1m.csv -n 50 -headless -proxy http://localhost:8080 -timeout 30
```

## Command-line options
```
Usage of hakrawler:
  -csv string
      Path to CSV file of domains (default "top-1m.csv")
  -d int
    	Depth to crawl. (default 2)
  -dr
    	Disable following HTTP redirects.
  -h string
    	Custom headers separated by two semi-colons. E.g. -h "Cookie: foo=bar;;Referer: http://example.com/"
  -headless
      Use headless browser for advanced detection
  -i	Only crawl inside path
  -insecure
    	Disable TLS verification.
  -json
    	Output as JSON.
  -proxy string
    	Proxy URL. E.g. -proxy http://127.0.0.1:8080
  -s	Show the source of URL based on where it was found. E.g. href, form, script, etc.
  -size int
    	Page size limit, in KB. (default -1)
  -subs
    	Include subdomains for crawling.
  -t int
    	Number of threads to utilise. (default 8)
  -timeout int
    	Maximum time to crawl each URL from stdin, in seconds. (default -1)
  -u	Show only unique urls.
  -w	Show at which link the URL is found.
```
