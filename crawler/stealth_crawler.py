import asyncio, random, os
from utils import handle_cloudflare_challenge
from camoufox.async_api import AsyncCamoufox
from browserforge.injectors.playwright import AsyncNewContext
from playwright.async_api import async_playwright
import time
from typing import List
import aiofiles

SCREENSHOT_DIR = "screenshots"
MAX_CONCURRENT_BROWSERS = 10  
MAX_RETRIES = 3  # Maximum number of retries for failed requests

async def grab(url: str, outfile: str) -> None:
    for attempt in range(MAX_RETRIES):
        async with AsyncCamoufox(
            headless=True,
            os=["windows","macos","linux"],
            args=['--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage', '--disable-images', '--disable-javascript'],  # Optimized browser settings
        ) as browser:
            page = await browser.new_page()
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)  
                await handle_cloudflare_challenge(page, url, options={"verbose": True})
                await page.screenshot(path=outfile, full_page=True) 
                return  
            except Exception as e:
                print(f"Attempt {attempt + 1} failed for site: {url} - {str(e)}")
                if attempt == MAX_RETRIES - 1:
                    print(f"All retries failed for site: {url}")
                await asyncio.sleep(1)  

async def process_urls(urls: List[str]):
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_BROWSERS)
    
    async def bounded_grab(url: str):
        async with semaphore:
            url_name = url.split("https://www.")[-1]
            await grab(url, f"screenshots/{url_name}.png")
            await asyncio.sleep(random.uniform(0.1, 0.5))
    
    # Create tasks for all URLs
    tasks = [bounded_grab(url) for url in urls]
    # Run all tasks concurrently
    await asyncio.gather(*tasks)

async def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    
    # Read URLs asynchronously
    async with aiofiles.open("urls.txt", "r") as f:
        urls = await f.readlines()
        urls = ["https://www." + url.strip() for url in urls]
    
    print(f"Processing {len(urls)} URLs with {MAX_CONCURRENT_BROWSERS} concurrent browsers")
    await process_urls(urls)

if __name__ == "__main__":
    timer = time.time()
    with open("urls.txt", "r") as f:
        numlines = sum(1 for line in f)
    asyncio.run(main())
    total_time = time.time() - timer
    time_per_site = total_time / numlines
    print(f"Total time: {total_time}")
    print(f"Time per site: {time_per_site:.2f} seconds")
    
    # Calculate time for 1 million sites
    million_sites_time = 1_000_000 * time_per_site
    million_sites_minutes = million_sites_time / 60
    million_sites_hours = million_sites_minutes / 60
    million_sites_days = million_sites_hours / 24
    print(f"Estimated time for 1 million sites: {million_sites_time:.2f} seconds, or {million_sites_minutes:.2f} minutes, or {million_sites_hours:.2f} hours, or {million_sites_days:.2f} days")






