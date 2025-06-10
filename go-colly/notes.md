
# Matyas
- removing browserPoolOptions doesn't cause any speed up
- blocking assets ['image', 'font', 'media', 'stylesheet', 'script'] doesn't cause any speed up

## Can print all JS file names + Find something in JS files

```ts
const scriptSrcs = await page.$$eval('script[src]', (scripts: any[]) =>
    scripts.map(s => (s as HTMLScriptElement).src)
);

for (const src of scriptSrcs) {
    try {
        // Fetch the JS file content
        const response = await page.evaluate(async (url: any) => {
            const res = await fetch(url);
            return await res.text();
        }, src);

        if (response.includes('astraGetParents')) {
            log.info(`Found astraGetParents in JS file: ${src} on ${request.url}`);
            break;
        }
    } catch (err) {
        log.warning(`Failed to fetch JS from ${src}: ${err}`);
    }
}
```

## Go (Colly)

- Alexa 30000 domains
    - Scraping completed in 30m24.8176113s
    - Scraped 0 urls
    - Scraped 29999 root domains
    - Scraped 0 urls per second
    - Root domains per second: 16.44
    - Concurrency: 32
    - Mode: title
    - Depth: 1
    - Valid responses: 7725
    - Failed responses: 22274
    - Status code breakdown:
        - 596: 1  # Custom / Unknown Status (not standard HTTP)
        - 444: 1  # No Response (Nginx) — Server returns no response and closes connection
        - 307: 2  # Temporary Redirect — Request method must not change when redirected
        - 499: 2  # Client Closed Request (Nginx) — Client closed connection before server response
        - 470: 3  # Custom / Unknown Status (not standard HTTP)
        - 406: 2  # Not Acceptable — Server cannot produce content matching Accept headers
        - 200: 7719  # OK — The request has succeeded
        - 511: 2  # Network Authentication Required — Client needs to authenticate to gain network access
        - 308: 1  # Permanent Redirect — Redirect with method and body unchanged
        - 300: 1  # Multiple Choices — Multiple options for resource available
        - 498: 2  # Invalid Token (Esri) — Token expired or invalid
        - 409: 1  # Conflict — Request conflicts with current state of the resource
        - 418: 3  # I'm a teapot — April Fools' joke; server refuses to brew coffee
        - 400: 935  # Bad Request — Malformed syntax or invalid request
        - 422: 6  # Unprocessable Entity — Well-formed request but semantic errors
        - 302: 4  # Found (Temporary Redirect) — Resource temporarily under different URI
        - 429: 8  # Too Many Requests — Rate limiting triggered
        - 464: 2  # Custom / Unknown Status (not standard HTTP)
        - 402: 3  # Payment Required — Reserved for future use
        - 530: 2  # Custom / Unknown Status (not standard HTTP)
        - 423: 1  # Locked — Resource is locked
        - 521: 2  # Web Server Is Down (Cloudflare) — Origin server refused connection
        - 501: 8  # Not Implemented — Server does not support functionality to fulfill request
        - 301: 11  # Moved Permanently — Resource has new permanent URI
        - 404: 6650  # Not Found — Resource could not be found
        - 0: 10880  # No Response / Unknown — No HTTP status code returned
        - 202: 4  # Accepted — Request accepted but not yet processed
        - 201: 2  # Created — Request successful and resource created
        - 572: 1  # Custom / Unknown Status (not standard HTTP)
        - 426: 22  # Upgrade Required — Client should switch protocols
        - 504: 8  # Gateway Timeout — Server acting as gateway timed out waiting for upstream server
        - 417: 4  # Expectation Failed — Server cannot meet Expect header requirements
        - 520: 6  # Unknown Error (Cloudflare) — Origin server returned an unknown error
        - 403: 2532  # Forbidden — Server refuses to authorize request
        - 451: 2  # Unavailable For Legal Reasons — Resource blocked due to legal demands
        - 203: 4  # Non-Authoritative Information — Meta-information from a third party
        - 415: 13  # Unsupported Media Type — Media format not supported by server
        - 401: 267  # Unauthorized — Authentication required or failed
        - 500: 115  # Internal Server Error — Server encountered an unexpected condition
        - 412: 2  # Precondition Failed — One or more conditions in request header failed
        - 503: 159  # Service Unavailable — Server currently unable to handle request
        - 525: 5  # SSL Handshake Failed (Cloudflare) — SSL handshake between Cloudflare and origin failed
        - 526: 1  # Invalid SSL Certificate (Cloudflare) — SSL certificate invalid or missing
        - 405: 89  # Method Not Allowed — Request method is not supported by resource
        - 502: 99  # Bad Gateway — Invalid response from upstream server
        - 410: 15  # Gone — Resource no longer available and will not be available again
        - 522: 2  # Connection Timed Out (Cloudflare) — TCP connection to origin timed out
        - 204: 392  # No Content — Request succeeded but no content returned
    - Status 0 error breakdown (grouped network errors):
        - dial tcp: lookup ...: no such host: 5270
        - tls: failed to verify certificate: x509: certificate is valid for ..., not ...: 3047
        - tls: failed to verify certificate: x509: certificate signed by unknown authority: 548
        - EOF: 171
        - read tcp ... wsarecv: An existing connection was forcibly closed by the remote host.: 170
        - context deadline exceeded (Client.Timeout exceeded while awaiting headers): 57
        - http2: timeout awaiting response headers: 33
        - gzip: invalid header: 13
        - Get "http://www.exelate.com": dial tcp 138.108.20.122:80: connectex: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.: 7
        - remote error: tls: illegal parameter: 7
        - ...and 1557 more
    - Status 0 errors: 10881 (48.9% of all failed responses)

### Running at different concurrencies
- files `results_c{x}` show the output of running the script `go run crawler.go -mode=title -concurrency={x} -file="cloudflare2000.csv" -depth=1 -results="results_c{x}"` 
- concurrency = 20 seems to perform the best on my machine

### Running 2 instances at the same time
- files res1 and res2 show what happens when 2 instances are run at the same time
    - res1 from `go run crawler.go -mode=title -concurrency=20 -file="cloudflare2000.csv" -depth=1 -results="res1"`
    - res2 from `go run crawler.go -mode=title -concurrency=20 -file="top-2k.csv" -depth=1 -indexed -results="res2"`
- performance drops significantly

### Running on Naxos
- performance drops for no obbious reason. 5 requests per second instead of 20 requests per second

## CVE 
 - it is hard to find websites with vulns
 - it is hard to find good vulns (CVEs)
 - should we make our own servers to test it?
 - can we look for random data on the website and just say how much JS we can see etc?
 - https://chatgpt.com/share/6828e5f0-2e8c-800c-9d6d-bd261b9d4cb6

## Python DNS checker
- given a debug output from the go-colly crawler, the `python/dns_checker.py` can check if all the domains are actually non-existent or what records the DNS has about them
- from Alexe 30k there were over 5000 bad domains with most of the records there being NS and TXT
    - this can be seen in `python/dns_results.txt`

