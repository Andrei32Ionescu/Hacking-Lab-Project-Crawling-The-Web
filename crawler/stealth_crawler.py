import asyncio, random, os
from utils import handle_cloudflare_challenge
from camoufox.async_api import AsyncCamoufox
from browserforge.injectors.playwright import AsyncNewContext
from playwright.async_api import async_playwright

SCREENSHOT_DIR = "screenshots"

async def grab(url: str, outfile: str) -> None:
        async with AsyncCamoufox(
        headless=False,
        os=["windows","macos","linux"],
        ) as browser:
            page = await browser.new_page()
            await page.goto(url, wait_until="networkidle")
            print("title:", await page.title())
            await handle_cloudflare_challenge(page, url, options={"verbose": True})
            await page.screenshot(path=outfile, full_page=True)

async def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    tasks = []
    with open("urls.txt", "r") as f:
        urls = f.readlines()
        for raw_url in urls:
            raw_url = raw_url.strip()
            if raw_url:
                full_url = "https://www." + raw_url
                outfile = os.path.join(SCREENSHOT_DIR, f"{raw_url}.png")
                tasks.append(grab(full_url, outfile))
            else:
                print("Empty URL found, skipping...")

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
