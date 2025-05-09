import { PlaywrightCrawler, ProxyConfiguration  } from 'crawlee';
import { chromium, firefox } from 'playwright-extra';
import stealthPlugin from 'puppeteer-extra-plugin-stealth';
import { BrowserName, DeviceCategory, OperatingSystemsName } from '@crawlee/browser-pool';
import { launchOptions } from 'camoufox-js';
import fs from 'fs';

// First, we tell puppeteer-extra to use the plugin (or plugins) we want.
// Certain plugins might have options you can pass in - read up on their documentation!
// chromium.use(stealthPlugin());

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
    postNavigationHooks: [
        async ({ handleCloudflareChallenge }) => {
            await handleCloudflareChallenge();
        },
    ],
    // proxyConfiguration,
    launchContext: {
        // !!! You need to specify this option to tell Crawlee to use puppeteer-extra as the launcher !!!
        launcher: firefox,
        launchOptions: await launchOptions({
            headless: true,
            blockAssets: ['image', 'font', 'media'],
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
                    },
                ],
                devices: [DeviceCategory.desktop],
                operatingSystems: [OperatingSystemsName.windows],
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

        // // A function to be evaluated by Puppeteer within the browser context.
        // const data = await page.$$eval('.athing', ($posts) => {
        //     const scrapedData: { title: string; rank: string; href: string }[] = [];

        //     // We're getting the title, rank and URL of each post on Hacker News.
        //     $posts.forEach(($post) => {
        //         scrapedData.push({
        //             title: $post.querySelector('.title a').innerText,
        //             rank: $post.querySelector('.rank').innerText,
        //             href: $post.querySelector('.title a').href,
        //         });
        //     });

        //     return scrapedData;
        // });

        // // Store the results to the default dataset.
        // await pushData(data);

        // // Find a link to the next page and enqueue it if it exists.
        // const infos = await enqueueLinks({
        //     selector: '.morelink',
        // });

        // if (infos.processedRequests.length === 0) log.info(`${request.url} is the last page!`);
    },

    // This function is called if the page processing failed more than maxRequestRetries+1 times.
    failedRequestHandler({ request, log }) {
        log.error(`Request ${request.url} failed too many times.`);
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

console.log('Crawler finished.');