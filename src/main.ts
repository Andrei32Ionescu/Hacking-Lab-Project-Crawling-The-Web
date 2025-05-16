import { PlaywrightCrawler, ProxyConfiguration  } from 'crawlee';
import { chromium, firefox } from 'playwright-extra';
import stealthPlugin from 'puppeteer-extra-plugin-stealth';
import { BrowserName, DeviceCategory, OperatingSystemsName } from '@crawlee/browser-pool';
import { launchOptions } from 'camoufox-js';
import fs from 'fs';

const benchmarkStats = {
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    totalTime: 0,
    startTime: Date.now(),
    endTime: 0
};

const timings = new Map<string, { startTime: number, endTime: number | null }>();

const proxyConfiguration = new ProxyConfiguration({
    proxyUrls: [
        'http://102.222.161.143:3128',
        'http://103.111.82.134:8080',
    ]
});
var reached_url = 0
// Create an instance of the PuppeteerCrawler class - a crawler
// that automatically loads the URLs in headless Chrome / Puppeteer.
const crawler = new PlaywrightCrawler({
    // Track when each request starts
    preNavigationHooks: [
        async ({ request }) => {
            // Start timing for this request
            timings.set(request.url, {
                startTime: Date.now(),
                endTime: null
            });
            benchmarkStats.totalRequests++;
        },
    ],
    postNavigationHooks: [
        async ({ handleCloudflareChallenge }) => {
            await handleCloudflareChallenge();
        },
    ],
    // proxyConfiguration,
    maxConcurrency: 10, // Process 10 pages in parallel
    minConcurrency: 5,  // At least 5 parallel processes
    launchContext: {
        // !!! You need to specify this option to tell Crawlee to use puppeteer-extra as the launcher !!!
        launcher: firefox,
        launchOptions: await launchOptions({
            headless: true,
            blockAssets: ['image', 'font', 'media', 'stylesheet', 'script'],
            args: [
                '--disable-gpu',
                '--disable-dev-shm-usage',
                '--disable-setuid-sandbox',
                '--no-sandbox',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--disable-extensions',
            ],
        }),
    },
    browserPoolOptions: {
        useFingerprints: true, // this is the default
        fingerprintOptions: {
            fingerprintGeneratorOptions: {
                browsers: [
                    {
                        name: BrowserName.firefox,
                        minVersion: 96,
                        maxVersion: 116
                    },
                ],
                devices: [
                    DeviceCategory.desktop,
                    DeviceCategory.mobile

                ],
                operatingSystems: [
                    OperatingSystemsName.windows,
                    OperatingSystemsName.macos,
                    OperatingSystemsName.linux
                ],
            },
        },
    },

    // Stop crawling after several pages
    maxRequestsPerCrawl: 100,

    // This function will be called for each URL to crawl.
    // Here you can write the Puppeteer scripts you are familiar with,
    // with the exception that browsers and pages are automatically managed by Crawlee.
    // The function accepts a single parameter, which is an object with the following fields:
    // - request: an instance of the Request class with information such as URL and HTTP method
    // - page: Puppeteer's Page object (see https://pptr.dev/#show=api-class-page)
    async requestHandler({ request, page, log }) {
        reached_url = reached_url + 1
        const title = await page.title();
        log.info(`${reached_url}) Title of ${request.url} is ${title}`);

        // Record successful request timing
        benchmarkStats.successfulRequests++;
        const timing = timings.get(request.url);
        if (timing) {
            timing.endTime = Date.now();
            if (timing.endTime && timing.startTime) {
                benchmarkStats.totalTime += (timing.endTime - timing.startTime);
            }
        }
    },

    // This function is called if the page processing failed more than maxRequestRetries+1 times.
    failedRequestHandler({ request, log }) {
        log.error(`Request ${request.url} failed too many times.`);
        
        // Record unsuccessful request timing
        const timing = timings.get(request.url);
        if (timing) {
            timing.endTime = Date.now();
            if (timing.endTime && timing.startTime) {
                benchmarkStats.totalTime += (timing.endTime - timing.startTime);
            }
        }
    },
});

const file = fs.openSync('src/top-1m.csv', 'r');
const urls = fs.readFileSync(file, 'utf-8').split('\n').map((line) => {
    const [id, url] = line.split(',');
    return {
        id: parseInt(id),
        url,
    };
});
urls.shift();
urls.pop();

const actualUrls = urls.map((url) => 'https://' + url.url);
actualUrls[0] = 'https://cloudflare.com';
actualUrls[1] = 'https://www.scrapingcourse.com/antibot-challenge';
actualUrls[2] = 'https://vimeo.com';
actualUrls[3] = 'https://weebly.com';
actualUrls[4] = 'https://w3.org';
actualUrls[5] = 'https://namecheap.com';

// Add the urls to the crawler
await crawler.addRequests(actualUrls);

// Start the crawler
await crawler.run();

benchmarkStats.endTime = Date.now();

// Calculate and output benchmark summary
const totalCrawlTime = benchmarkStats.endTime - benchmarkStats.startTime;
const averageRequestTime = benchmarkStats.totalRequests > 0 ? benchmarkStats.totalTime / benchmarkStats.totalRequests : 0;

benchmarkStats.failedRequests = benchmarkStats.totalRequests - benchmarkStats.successfulRequests;

const successRate = benchmarkStats.totalRequests > 0 ? (benchmarkStats.successfulRequests / benchmarkStats.totalRequests) * 100 : 0;

console.log('\n=== CRAWLER BENCHMARK SUMMARY ===');
console.log(`Total Requests: ${benchmarkStats.totalRequests}`);
console.log(`Successful Requests: ${benchmarkStats.successfulRequests}`);
console.log(`Failed Requests: ${benchmarkStats.failedRequests}`);
console.log(`Success Rate: ${successRate.toFixed(2)}%`);
console.log(`Total Crawl Time: ${totalCrawlTime}ms (${(totalCrawlTime / 1000).toFixed(2)}s)`);
console.log(`Average Request Time: ${averageRequestTime.toFixed(2)}ms (${(averageRequestTime / 1000).toFixed(2)}s)`);
console.log(`Requests Per Second: ${(totalCrawlTime > 0 ? (benchmarkStats.totalRequests / (totalCrawlTime / 1000)) : 0).toFixed(2)}`);
console.log('=================================');

console.log('Crawler finished.');