
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

- 2000 domains 22dps (1m33s) with concurrency 32, 1000x 0 error, 400-x 200 codes + others
    - Status code breakdown:
        - 0: 1242
        - 200: 586
        - 204: 21
        - 301: 1
        - 400: 113
        - 401: 12
        - 403: 130
        - 404: 531
        - 405: 5
        - 410: 1
        - 417: 1
        - 426: 1
        - 499: 2
        - 500: 16
        - 501: 1
        - 502: 10
        - 503: 19
- 2000 domains 1dps (33m58s) with concurrency 1
    - Status code breakdown:
        - 0: 691
        - 200: 551
        - 204: 19
        - 301: 1
        - 400: 75
        - 401: 12
        - 403: 119
        - 404: 486
        - 405: 5
        - 410: 1
        - 417: 1
        - 426: 1
        - 499: 2
        - 500: 5
        - 501: 1
        - 502: 10
        - 503: 20

## CVE 
 - it is hard to find websites with vulns
 - it is hard to find good vulns (CVEs)
 - should we make our own servers to test it?
 - can we look for random data on the website and just say how much JS we can see etc?