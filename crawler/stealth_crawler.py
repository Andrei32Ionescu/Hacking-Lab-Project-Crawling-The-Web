import asyncio, random, os
from utils import handle_cloudflare_challenge
from camoufox.async_api import AsyncCamoufox
from browserforge.injectors.playwright import AsyncNewContext
from playwright.async_api import async_playwright
import multiprocessing, time

SCREENSHOT_DIR = "screenshots"

async def grab(url: str, outfile: str, browser) -> None:
        async with AsyncCamoufox(
        headless=True,
        os=["windows","macos","linux"],
        ) as browser:
            page = await browser.new_page()
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                # await asyncio.sleep(0.5)
            except Exception as e:
                print(f"Timeout error for site: {url}")
                return
            # print("title:", await page.title())
            await handle_cloudflare_challenge(page, url, options={"verbose": True})
            # await page.screenshot(path=outfile, full_page=True)
            # k = 1|000|000|000

def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    num_cores = multiprocessing.cpu_count()
    print(f"Running on {num_cores} cores")
    tasks = []
    with open("urls.txt", "r") as f:
        urls = f.readlines()
        for raw_url in urls:
            raw_url = raw_url.strip()
            full_url = "https://www." + raw_url
            tasks.append(full_url)
    with multiprocessing.Pool(num_cores) as pool:
        pool.map(sync_grab, tasks)

def sync_grab(full_url: str):
    url = full_url.split("https://www.")[-1]
    print(full_url)
    asyncio.run(grab(full_url, f"screenshots/{url}.png"))

if __name__ == "__main__":
    timer = time.time()
    with open("urls.txt", "r") as f:
        numlines = sum(1 for line in f)
    main()
    print(f"Total time: {time.time() - timer}")
    print(f"Time per site: {(time.time() - timer) / numlines:.2f} seconds")


