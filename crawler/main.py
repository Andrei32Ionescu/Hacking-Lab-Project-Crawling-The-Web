import asyncio
from playwright.async_api import async_playwright

async def main():
    browsers = ["chromium", "firefox", "webkit"]
    async with async_playwright() as p:
        for browser_name in browsers:
            browser = await getattr(p, browser_name).launch()


            page = await browser.new_page()
            await page.goto("https://amazon.nl")
            content = await page.content()
            # Optionally, you can apply stealth mode to the page
            # await stealth(page)
            
            print(f"Content from {browser_name}:")
            print(content)
            await browser.close()

asyncio.run(main())
