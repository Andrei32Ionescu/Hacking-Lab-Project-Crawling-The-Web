import asyncio, random, os, time
from utils import handle_cloudflare_challenge
from camoufox.async_api import AsyncCamoufox
from browserforge.injectors.playwright import AsyncNewContext
from playwright.async_api import async_playwright
CONCURRENCY = 64

SCREENSHOT_DIR = "screenshots"

async def grab(url: str, browser, sem, outfile: str) -> None:
     async with sem:
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            locale="en-US"
        )
        page = await context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=10_000)
        except Exception as e:
            print(f"Error navigating to {url}: {e}")
            return
        print(f"{url}")
        #await handle_cloudflare_challenge(page, url, options={"verbose": True})
        # try:
        #     await page.screenshot(path=outfile, full_page=True)
        # except Exception as e:
        #     print(f"Error taking screenshot of {url}: {e}")
        await context.close()
        

async def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        sem = asyncio.Semaphore(CONCURRENCY)
        tasks = []
        for domain in open("urls.txt", "r"):
            domain = domain.strip()
            if domain:
                full_url = "https://www." + domain
                outfile = os.path.join(SCREENSHOT_DIR, f"{domain}.png")
                tasks.append(grab(full_url, browser, sem, outfile))
            else:
                print("Empty URL found, skipping...")
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    timer = time.time()
    with open("urls.txt", "r") as f:
        num_urls = sum(1 for line in f if line.strip())
    print(f"Total URLs to process: {num_urls}")
    print(f"Starting screenshot capture for {num_urls} URLs...")
    asyncio.run(main())
    print("Screenshot capture completed.")
    print(f"Total time taken: {time.time() - timer} seconds")
    print(f"URLs per second: {num_urls / (time.time() - timer)}")
