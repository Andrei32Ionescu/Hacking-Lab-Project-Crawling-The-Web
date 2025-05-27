# Web Security Crawler

A high-performance web security crawler designed to scan websites for common vulnerabilities. The crawler can process large numbers of websites efficiently and identify various security issues.

## Features

- Concurrent scanning of multiple websites
- Proxy support for distributed scanning
- Comprehensive vulnerability detection:
  - Cross-Site Scripting (XSS)
  - SQL Injection
  - Open Redirect vulnerabilities
  - Missing security headers
  - SSL/TLS configuration issues
  - Insecure cookie settings
- CSV output of findings
- Progress tracking and statistics

## Requirements

- Go 1.16 or higher
- Required Go packages:
  - github.com/gocolly/colly
  - github.com/gocolly/colly/proxy

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd <repository-directory>
```

2. Install dependencies:

```bash
go mod init security-crawler
go get github.com/gocolly/colly
go get github.com/gocolly/colly/proxy
```

## Usage

1. Prepare your input file:

   - Create a CSV file containing the domains to scan
   - One domain per line
   - Optional: Include an index column (use -indexed flag)

2. Run the crawler:

```bash
go run security_crawler.go -file domains.csv -concurrency 50 -timeout 30 -results findings.csv
```

### Command Line Options

- `-file`: Input CSV file containing domains (default: "top-1m.csv")
- `-concurrency`: Number of sites to crawl in parallel (default: 50)
- `-timeout`: Timeout in seconds for each request (default: 30)
- `-results`: Output file for findings (default: "security-results.csv")
- `-proxies`: File containing proxy list (default: "proxies.csv")
- `-indexed`: CSV has an index column; domain is in the second column

### Proxy Configuration

To use proxies, create a `proxies.csv` file with one proxy per line in the format:

```
http://proxy1:port
http://proxy2:port
```

## Output Format

The crawler generates a CSV file with the following columns:

- URL: The URL where the vulnerability was found
- Vulnerability Type: Type of vulnerability (XSS, SQL Injection, etc.)
- Severity: Severity level (Critical, High, Medium, Low)
- Description: Detailed description of the vulnerability
- Evidence: Evidence of the vulnerability found

## Performance Considerations

- Adjust concurrency based on your system's capabilities
- Use proxies to avoid rate limiting
- Consider the timeout value based on target response times
- Monitor system resources during scanning

## Security Note

This tool is designed for security testing and research purposes only. Always:

- Obtain proper authorization before scanning any website
- Respect robots.txt and rate limits
- Use responsibly and ethically
- Do not use for malicious purposes

## License

[Your chosen license]
