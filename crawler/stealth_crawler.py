import asyncio, random, os
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from playwright_stealth import stealth_async
from fake_useragent import UserAgent

SCREENSHOT_DIR = "screenshots"

async def grab(url: str, outfile: str) -> None:
    ua = UserAgent().random
    async with async_playwright() as p:
        browser: Browser = await p.firefox.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars"
            ],
        )
        context: BrowserContext = await browser.new_context(
            user_agent=ua,
            locale="en-US",
            timezone_id="Europe/Amsterdam",
            viewport={"width": random.randint(1200, 1920),
                      "height": random.randint(700, 1080)},
            device_scale_factor=1.0,
        )
        page: Page = await context.new_page()
        await stealth_async(page)
        try:
            await page.goto(url, wait_until="networkidle")
            await page.screenshot(path=outfile, full_page=True)
            print(f"Captured {url} in {outfile}")
        except Exception as e:
            print(f"Failed to grab {url}: {e}")
        await browser.close()

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
