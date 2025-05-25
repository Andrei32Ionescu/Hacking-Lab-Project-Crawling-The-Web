# Web Security Scanner and WordPress Vulnerability Detector

A high-performance web security scanner built in Go, featuring comprehensive WordPress vulnerability detection and general security analysis capabilities.

## Features

### WordPress Security Scanning
- Detection of vulnerable WordPress plugins and themes
- WordPress version fingerprinting
- Common WordPress security misconfigurations
- Plugin and theme enumeration
- Exposed sensitive files detection

### General Security Checks
- Security headers analysis (CSP, HSTS, etc.)
- TLS/SSL configuration assessment
- Mixed content detection
- Cookie security validation
- Technology stack disclosure
- Directory listing detection
- Sensitive file exposure

## Installation

1. Make sure you have Go installed (1.16 or later)
2. Clone the repository:
```sh
git clone https://github.com/yourusername/Hacking-Lab-Project-Crawling-The-Web.git
cd Hacking-Lab-Project-Crawling-The-Web
```

3. Install dependencies:
```sh
go mod tidy
```

## Usage

### Basic Usage
```sh
go run fast_crawler.go
```

### Advanced Options
```sh
go run fast_crawler.go -max=1000 -concurrency=200 -output="scan_results.json" -file="domains.csv"
```

### Command Line Arguments
- `-max`: Maximum number of domains to scan (default: 100)
- `-concurrency`: Number of concurrent scanners (default: 200)
- `-file`: Input CSV file with domains (default: "top-1m.csv")
- `-output`: Output JSON file for results (default: "vulnerability_scan_results.json")

### Example Commands

1. Scan top 1000 domains with default settings:
```sh
go run fast_crawler.go -max 1000
```

2. Custom scan with high concurrency:
```sh
go run fast_crawler.go -max 500 -concurrency 300 -output="custom_scan.json"
```

3. Scan specific domain list:
```sh
go run fast_crawler.go -file="my_domains.csv" -output="my_results.json"
```

## Output Format

The scanner generates a detailed JSON report containing:

```json
{
  "timestamp": "2024-03-22T15:04:05Z",
  "total_scans": 1000,
  "results": {
    "example.com": {
      "domain": "example.com",
      "scan_time": "2024-03-22T15:04:05Z",
      "findings": [...],
      "wordpress": {
        "is_wordpress": true,
        "version": "6.4.2",
        "detected_plugins": {
          "plugin-name": "version"
        },
        "vulnerable_plugins": [
          {
            "name": "plugin-name",
            "version": "1.2.3",
            "cve": "CVE-2024-XXXX",
            "severity": "critical"
          }
        ]
      }
    }
  }
}
```

## Performance

The scanner is optimized for high-performance scanning:
- Concurrent domain processing
- DNS caching and optimized resolution
- Connection pooling and reuse
- Efficient HTTP client settings
- Balanced timeouts and retries

Typical performance metrics:
- 50-60 requests per second
- Average response time: ~1.7 seconds
- Successful response rate: ~25-30%
