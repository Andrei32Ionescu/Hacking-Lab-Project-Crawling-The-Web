import asyncio, os, random, string, time, aiohttp, async_timeout
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse
from collections import defaultdict

from playwright.async_api import async_playwright, Page, Browser
from playwright.async_api import TimeoutError as PWTimeout
from playwright._impl._errors import TargetClosedError

CONCURRENCY        = 16
BROWSERS           = 8
PAGE_TIMEOUT       = 15_000      # ms – first navigation
POST_TIMEOUT       = 20_000       # ms – after submit/enter
SCREENSHOT_DIR     = "screenshots"
TAKE_SCREENSHOTS   = False
XSS_TOKEN_LEN      = 8
PAYLOAD_TMPL = '"><script>console.log("XSS:%s")</script>'
BLOCK_STATIC       = False

def make_payload() -> tuple[str, str]:
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=XSS_TOKEN_LEN))
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


async def safe_wait(page: Page, state: str = "domcontentloaded", timeout: int = POST_TIMEOUT):
    try:
        await page.wait_for_load_state(state, timeout=timeout)
    except Exception:
        pass


async def _discover_forms(page: Page):
    for _ in range(2):
        try:
            return await page.query_selector_all("form")
        except Exception:
            await safe_wait(page, "domcontentloaded", 15_000)
    return []


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
        await el.get_attribute("name") or await el.get_attribute("id") or f"idx-{i}"
        for i, el in enumerate(inputs)
    ]
    return inputs, names


async def fuzz_forms(page: Page, console_hits: Set[str], store_hits: Set[str]):
    for form in await _discover_forms(page):
        inputs, names = await _extract_form_inputs(form)
        if not names:
            continue
        for el, label in zip(inputs, names):
            token, payload = make_payload()
            try:
                await el.fill(payload)
            except Exception:
                continue
            try:
                await asyncio.gather(
                    form.evaluate("(f)=>{try{f.submit()}catch(e){}}"),
                    page.wait_for_load_state("domcontentloaded", timeout=POST_TIMEOUT)
                )
            except Exception:
                pass

            await safe_wait(page, "load")
            html = await page.content()
            _report_hits(page.url, token, label, console_hits, html, store_hits)
            break

    try:
        inputs = await page.query_selector_all(
            "input:not([type='hidden']):not([disabled]):not([readonly]), "
            "textarea:not([disabled]):not([readonly]), "
            "select:not([disabled]):not([readonly]), "
            "[contenteditable='true']"
        )
    except Exception:
        inputs = []
    inputs = inputs[:60]
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
            continue
        await safe_wait(page, "load")
        html = await page.content()
        _report_hits(page.url, token, None, console_hits, html, store_hits)
        break  # only first element


results: Dict[str, List[str]] = defaultdict(list)

def _record(url: str, tag: str):
    if tag not in results[url]:
        results[url].append(tag)
        print(f"{tag:<11} {url}")


def _report_hits(url: str, token: str, field: Optional[str], console_hits: Set[str],
                 html: str, store_hits: Set[str]):
    if token in console_hits:
        _record(url, f"[EXEC>{field or '-'}]")
    elif token in html:
        _record(url, f"[REFL>{field or '-'}]")
    store_hits.add(token)

async def worker(q: asyncio.Queue, browser: Browser, wid: int):
    ctx = await browser.new_context(
        viewport={"width": 1280, "height": 720},
        locale="en-US",
        ignore_https_errors=True,
    )
    if BLOCK_STATIC:
        await ctx.route(r"**/*.{png,jpg,jpeg,webp,gif,css,woff,woff2}", lambda r: r.abort())

    page: Page = await ctx.new_page()
    console_hits: Set[str] = set()
    store_hits: Set[str]   = set()

    page.on("console", lambda msg: _collect_console(msg, console_hits, store_hits))
    await page.add_init_script(
        """
        (() => {
            const send = (tag,data) => console.debug(tag+":"+data);
            ['alert','confirm','prompt'].forEach(fn => {
                window[fn] = msg => send('XSS', msg);
            });
        })();
        """
    )

    while (url := await q.get()) is not None:
        console_hits.clear()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT)
            await fuzz_forms(page, console_hits, store_hits)

            html_now = await page.content()
            for tok in list(store_hits):
                if tok in html_now:
                    # _record(url, "[STORE]")
                    store_hits.discard(tok)

            if TAKE_SCREENSHOTS:
                out = os.path.join(SCREENSHOT_DIR, f"{urlparse(url).hostname}.png")
                try:
                    await page.screenshot(path=out, full_page=True)
                except Exception:
                    pass
        except PWTimeout:
            print(f"TIMEOUT     {url}")
        except Exception as e:
            print(f"ERROR       {url}   {e}")
        finally:
            q.task_done()

    await page.close(); await ctx.close()


def _collect_console(msg, bucket: Set[str], store_bucket: Set[str]):
    if msg.type in ("debug", "log") and msg.text.startswith("XSS:"):
        tok = msg.text.split("XSS:")[-1]
        bucket.add(tok)
        store_bucket.add(tok)

async def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    raw = [l.strip() for l in open("urls.txt") if l.strip()]
    urls_direct = [l for l in raw if l.startswith("http")]
    bare = [l for l in raw if not l.startswith("http")]

    probes = await asyncio.gather(*[host_probe(d) for d in bare])
    urls = urls_direct + [u for u in probes if u]

    if not urls:
        print("No live URLs")
        return

    q: asyncio.Queue = asyncio.Queue()
    for u in urls:
        q.put_nowait(u)
    for _ in range(CONCURRENCY):
        q.put_nowait(None)

    async with async_playwright() as pw:
        browsers: List[Browser] = [await pw.chromium.launch(headless=True) for _ in range(BROWSERS)]
        workers = [asyncio.create_task(worker(q, browsers[i % BROWSERS], i)) for i in range(CONCURRENCY)]

        print(f"{len(urls)} URLs | {CONCURRENCY} workers | {BROWSERS} browsers")
        t0 = time.time()
        await asyncio.gather(*workers)
        dur = time.time() - t0
        print(f"done in {dur:.1f}s  –  {len(urls)/dur:.2f} urls/sec\n")


if __name__ == "__main__":
    asyncio.run(main())
