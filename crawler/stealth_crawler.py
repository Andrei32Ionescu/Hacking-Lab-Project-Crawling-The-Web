import asyncio, random
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from playwright_stealth import stealth_async
from fake_useragent import UserAgent

async def grab(url: str, outfile: str = "page.png") -> None:
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
        except Exception as e:
            print(e)
        await page.screenshot(path=outfile, full_page=True)
        print(f"Captured {url} in {outfile}")
        await browser.close()

with open("urls.txt", "r") as f:
    urls = f.readlines()
    for url in urls:
        url = url.strip()
        if url:
            asyncio.run(grab("https://www." + url, f"{url}.png"))
        else:
            print("Empty URL found, skipping...")
