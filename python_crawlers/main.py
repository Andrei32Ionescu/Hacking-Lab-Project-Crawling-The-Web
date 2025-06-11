import asyncio, os, time, aiohttp, async_timeout
from playwright.async_api import async_playwright, TimeoutError

CONCURRENCY, BROWSERS, PAGE_TIMEOUT = 128, 12, 15_000

async def host_probe(domain):
    for host in (f"https://{domain}", f"https://www.{domain}"):
        try:
            async with async_timeout.timeout(5):
                async with aiohttp.ClientSession() as s:
                    async with s.head(host) as r:
                        if r.status < 500:
                            return host
        except Exception:
            pass
    return None

async def worker(q, browser):
    ctx = await browser.new_context(
        viewport={"width":1280,"height":720},
        locale="en-US", ignore_https_errors=True
    )
    await ctx.route(r"**/*.{png,jpg,jpeg,webp,gif,css,woff,woff2}",
                    lambda r: r.abort())
    page = await ctx.new_page()
    while (url := await q.get()) is not None:
        try:
            await page.goto(url, wait_until="domcontentloaded",
                            timeout=PAGE_TIMEOUT)
            print("OK  ", url)
        except TimeoutError:
            print("TIMEOUT ERROR  ", url)
        except Exception as e:
            print("GENERIC ERROR ", url, e)
        finally:
            q.task_done()
    await page.close(); await ctx.close()

async def main():
    # Ensure the screenshot directory exists
    os.makedirs("screenshots", exist_ok=True)

    # Read domains from the file and probe them
    domains = [d.strip() for d in open("urls.txt") if d.strip()]
    urls = [u async for u in asyncio.as_completed([host_probe(d) for d in domains])]
    urls = [u.result() for u in urls if u.result()]

    # Put URLs into a queue
    q = asyncio.Queue()
    for url in urls: q.put_nowait(url)
    for _ in range(CONCURRENCY): q.put_nowait(None)  #sentinels

    # Launch browsers and workers
    async with async_playwright() as pw:
        browsers = [await pw.chromium.launch(headless=True) for _ in range(BROWSERS)]
        workers = [asyncio.create_task(worker(q, browsers[i % BROWSERS])) for i in range(CONCURRENCY)]
        print(f"Starting {len(urls)} URLs with {CONCURRENCY} workers across {BROWSERS} browsers...")

        t0 = time.time()
        await asyncio.gather(*workers)
        print(f"{len(urls)/(time.time()-t0):.2f} urls/sec")
        await asyncio.gather(*(b.close() for b in browsers))

if __name__ == "__main__":
    asyncio.run(main()) 