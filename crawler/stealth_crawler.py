import asyncio, random, os
from typing import Dict

from utils import handle_cloudflare_challenge
from camoufox.async_api import AsyncCamoufox
from browserforge.injectors.playwright import AsyncNewContext
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import multiprocessing, time
import requests
import threading
from collections import defaultdict
import aiohttp
import sys

SCREENSHOT_DIR = "screenshots"

totalCSPChecked = 0
hasCSPHeaderCount = 0
hasMetaCSPCount = 0
inlineScriptCount = 0
inlineStyleCount = 0
externalScriptCount = 0
evalUsageCount = 0
crossOriginScriptsCount = 0
sameOriginScriptsCount = 0
modernFrameworkCount = 0
sensitiveFormsCount = 0
hdrCTOCount = 0
cookieHttpOnlyCount = 0
outputEncodingCount = 0
inputValidationCount = 0
sandboxedIframesCount = 0
unsafeInlineEventHandlersCount = 0
jsonpEndpointsCount = 0
postMessageUsageCount = 0
riskHighCount = 0
riskMediumCount = 0
riskLowCount = 0
riskMinimalCount = 0
totalCrawled = 0
# crawlWG sync.WaitGroup
successCount = 0
failCount = 0
statusCounts = dict()
status0Errors = dict()

async def grab(url: str, outfile: str, mode: str, counters) -> None:
        async with AsyncCamoufox(
        headless=True,
        os=["windows","macos","linux"],
        ) as browser:
            page = await browser.new_page()
            plugin = []
            theme = None
            try:
                resp = await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                await asyncio.sleep(0.5)      

            except Exception as e:
                print(f"Timeout error for site: {url}")
                return
            # print("title:", await page.title())
            await handle_cloudflare_challenge(page, url, options={"verbose": True})
            # await page.screenshot(path=outfile, full_page=True)
            try:
                html = await page.content()
                soup = BeautifulSoup(html, "html.parser")

                if mode == "wordpress":
                    for tag in soup.find_all(["link", "script", "img"]):
                        attr = tag.get("href") or tag.get("src")
                        if not attr:
                            continue

                        asset_url = urljoin(url, attr)
                        match_theme = re.search(r"wp-content/themes/([^/]+)", asset_url)
                        if match_theme and not theme:
                            ver = re.search(r"[?&]ver=([^&]+)", asset_url)
                            theme = match_theme.group(1) + (f"@{ver.group(1)}" if ver else "")
                        
                        match_plugin = re.search(r"wp-content/plugins/([^/]+)", asset_url)
                        if match_plugin:
                            plugin_name = match_plugin.group(1)
                            ver = re.search(r"[?&]ver=([^&]+)", asset_url)
                            plugin.append(plugin_name + (f"@{ver.group(1)}" if ver else ""))

                    print(f"URL: {url}")
                    print(f"Theme: {theme}")
                    print(f"Plugins: {', '.join(plugin)}")

                elif mode == "jssearch":
                    keyword = sys.argv[2] if len(sys.argv) > 2 else None
                    if not keyword:
                        print("No keyword provided for JS search mode.")
                        return
                    seen    = set()
                    ctx_req = page.context.request

                    for tag in soup.find_all("script", src=True):
                        js_url = urljoin(url, tag["src"])
                        if js_url in seen:
                            continue
                        seen.add(js_url)

                        print(f"Found JS: {js_url}")

                        try:
                            resp = await ctx_req.get(js_url, timeout=15000)
                            if resp.status == 200:
                                body = await resp.text()
                                if not keyword or keyword in body:
                                    print(f"Keyword '{keyword}' found in JS: {js_url}")
                        except Exception as e:
                            print(f"Error fetching {js_url}: {e}")

                elif mode == "csp":
                    # global totalCSPChecked, hasCSPHeaderCount, hasMetaCSPCount, inlineScriptCount, inlineStyleCount, \
                    #     externalScriptCount, evalUsageCount, crossOriginScriptsCount, sameOriginScriptsCount, modernFrameworkCount, \
                    #     sensitiveFormsCount, hdrCTOCount, cookieHttpOnlyCount, outputEncodingCount, inputValidationCount, sandboxedIframesCount, unsafeInlineEventHandlersCount, \
                    #     jsonpEndpointsCount, postMessageUsageCount, riskHighCount, riskMediumCount, riskLowCount, riskMinimalCount, totalCrawled, successCount, failCount, statusCounts, status0Errors
                    has_csp_hdr = bool(resp and resp.headers.get("content-security-policy"))
                    has_xcto = resp and resp.headers.get("x-content-type-options", "").lower() == "nosniff"

                    has_meta_csp = bool(soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"}))
                    inline_scripts = len(soup.find_all("script", src=False))
                    inline_styles = len(soup.find_all("style")) + \
                                    sum(bool(t.get("style")) for t in soup.find_all(attrs={"style": True}))

                    evt_attrs = ["onclick", "onload", "onerror", "onmouseover", "onmouseout",
                                 "onchange", "onsubmit", "onfocus", "onblur", "onkeyup",
                                 "onkeydown", "onkeypress"]
                    inline_evt_handlers = sum(
                        1 for t in soup.find_all(attrs=lambda attr: attr and any(a in attr for a in evt_attrs))
                    )

                    same_origin_scripts = 0
                    cross_origin_scripts = 0
                    current_host = urlparse(url).hostname
                    eval_usage = False
                    post_msg = False
                    jsonp = False
                    modern_fw = False
                    sensitive_form = False
                    sandbox_ifr = bool(soup.find("iframe", sandbox=True))

                    framework_re = re.compile(r"(react|angular|vue\.|svelte|ember|next\.js|nuxt)", re.I)
                    eval_re = re.compile(r"\b(eval\s*\(|new\s+Function\s*\()", re.I)
                    postmsg_re = re.compile(r"\bpostMessage\b", re.I)
                    jsonp_re = re.compile(r"callback=", re.I)

                    for tag in soup.find_all("script"):
                        content = tag.string or ""
                        if not tag.get("src"):
                            if eval_re.search(content):
                                eval_usage = True
                            if framework_re.search(content):
                                modern_fw = True
                            if postmsg_re.search(content):
                                post_msg = True
                            if jsonp_re.search(content) and "jsonp" in content.lower():
                                jsonp = True
                        else:
                            src = urljoin(url, tag["src"])
                            host = urlparse(src).hostname
                            if host == current_host:
                                same_origin_scripts += 1
                            else:
                                cross_origin_scripts += 1

                    for form in soup.find_all("form"):
                        for inp in form.find_all("input"):
                            tp = (inp.get("type") or "").lower()
                            nm = (inp.get("name") or "").lower()
                            fid = (inp.get("id") or "").lower()
                            if tp in ("password", "email", "tel") or \
                                    any(k in nm for k in ("pass", "card", "cvv", "ssn")) or \
                                    any(k in fid for k in ("pass", "card", "cvv", "ssn")):
                                sensitive_form = True
                                break

                    risk = 0
                    mitigation = 0

                    risk += inline_scripts > 0
                    risk += inline_evt_handlers > 0
                    risk += inline_styles > 0
                    risk += eval_usage
                    risk += cross_origin_scripts > 0
                    risk += sensitive_form
                    risk += post_msg
                    risk += jsonp

                    mitigation += has_csp_hdr or has_meta_csp
                    mitigation += modern_fw
                    mitigation += has_xcto
                    mitigation += sandbox_ifr
                    mitigation += same_origin_scripts > cross_origin_scripts

                    net = risk - mitigation
                    if net >= 4:
                        risk_level = "High"
                    elif net >= 3:
                        risk_level = "Medium"
                    elif net >= 2:
                        risk_level = "Low"
                    else:
                        risk_level = "Minimal"

                    # print(
                    #     f"[CSP]\t{url}\t"
                    #     f"CSP_Header={int(has_csp_hdr)}\tMeta_CSP={int(has_meta_csp)}\t"
                    #     f"InlineJS={inline_scripts}\tInlineCSS={inline_styles}\tEvtAttr={inline_evt_handlers}\t"
                    #     f"SameJS={same_origin_scripts}\tXSiteJS={cross_origin_scripts}\t"
                    #     f"Eval={int(eval_usage)}\tpostMessage={int(post_msg)}\tJSONP={int(jsonp)}\t"
                    #     f"ModernFW={int(modern_fw)}\tXCTO={int(has_xcto)}\tSandboxIFR={int(sandbox_ifr)}\t"
                    #     f"SensitiveForm={int(sensitive_form)}\tRisk={risk_level}"
                    # )

                    counters['totalCrawled'] += 1
                    counters['successCount'] += 1

                    counters['hasCSPHeaderCount'] += has_csp_hdr
                    counters['hasMetaCSPCount'] += has_meta_csp
                    counters['inlineScriptCount'] += inline_scripts
                    counters['unsafeInlineEventHandlersCount'] += inline_evt_handlers
                    counters['inlineStyleCount'] += inline_styles
                    counters['evalUsageCount'] += int(eval_usage)
                    counters['postMessageUsageCount'] += int(post_msg)
                    counters['jsonpEndpointsCount'] += int(jsonp)
                    counters['externalScriptCount'] += same_origin_scripts + cross_origin_scripts
                    counters['sameOriginScriptsCount'] += same_origin_scripts
                    counters['crossOriginScriptsCount'] += cross_origin_scripts
                    counters['modernFrameworkCount'] += int(modern_fw)
                    counters['hdrCTOCount'] += int(has_xcto)
                    counters['sandboxedIframesCount'] += int(sandbox_ifr)
                    counters['sensitiveFormsCount'] += int(sensitive_form)
                    if not (has_csp_hdr or has_meta_csp):
                        if risk_level == "High":
                            counters['riskHighCount'] += 1
                        elif risk_level == "Medium":
                            counters['riskMediumCount'] += 1
                        elif risk_level == "Low":
                            counters['riskLowCount'] += 1
                        elif risk_level == "Minimal":
                            counters['riskMinimalCount'] += 1

                    protections = []
                    if has_csp_hdr or has_meta_csp:
                        protections.append("CSP")
                    if has_xcto:
                        protections.append("XCTO")
                    if modern_fw:
                        protections.append("Framework")
                    if sandbox_ifr:
                        protections.append("Sandbox")

                    risks = []
                    if inline_scripts:
                        risks.append("InlineJS")
                    if inline_evt_handlers:
                        risks.append("EventHandlers")
                    if inline_styles:
                        risks.append("InlineCSS")
                    if eval_usage:
                        risks.append("Eval")
                    if cross_origin_scripts:
                        risks.append(f"XOrigin({cross_origin_scripts})")
                    if sensitive_form:
                        risks.append("SensitiveForms")
                    if post_msg:
                        risks.append("PostMessage")
                    if jsonp:
                        risks.append("JSONP")

                    prot_str = ", ".join(protections) if protections else "None"
                    risk_str = ", ".join(risks) if risks else "None"

                    print(
                        f"SITE: {url} | "
                        f"RISK LEVEL: {risk_level.upper()} | "
                        f"PROTECTIONS: {prot_str} | "
                        f"RISKS: {risk_str} | "
                        f"SCRIPTS: {same_origin_scripts} same-origin, {cross_origin_scripts} cross-origin"
                    )

                elif mode == "apache":
                    start = time.time()
                    request_counter = 0
                    ctx_req = page.context.request
                    
                    async def fetch_once(u:str):
                        nonlocal request_counter
                        try:
                            resp = await ctx_req.get(u, timeout=15000)
                            request_counter += 1
                            return resp
                        except Exception as e:
                            print(f"Error fetching {u}: {e}")
                        return None
                    
                    is_apache = False
                    apache_version = None
                    apache_comment = None
                    detection_source = None

                    #Probe root URL
                    root_body = await fetch_once(url)
                    if root_body:
                        server_header = page.context.headers.get("server", "")
                        matei = re.match(r"Apache(?:/([\d.]+))?(?:\s+\(([^)]+)\))?", server_header, re.I)
                        if matei:
                            is_apache = True
                            apache_version = matei.group(1) or ""
                            apache_comment = matei.group(2) or ""
                            detection_source = "Server Header"

                    if (not is_apache or not apache_version) and root_body:
                        #Craft fake 404 URL
                        fake_url = urljoin(url, f"/ThisPageShouldNotExist-{int(time.time()*1e6)}")
                        err_resp = await fetch_once(fake_url)
                        if err_resp and err_resp.status in (404,403,500):
                            body = await err_resp.text()

                            m = re.search(r"Apache(?:/([\d.]+))?(?:\s+\(([^)]+)\))?\s+Server at", body, re.I)
                            if m:
                                is_apache = True
                                detection_source = f"Error Page({err_resp.status})"
                                if not apache_version and m.group(1):
                                    apache_version = m.group(1)
                                if not apache_comment and m.group(2):
                                    apache_comment = m.group(2)
                            elif not is_apache and "<address>Apache" in body:
                                is_apache = True
                                detection_source = "Error Page"
                    
                    duration = time.time() - start
                    rps = request_counter / duration if duration > 0 else 0

                    print(f"URL: {url}")
                    if is_apache:
                        print(f"Apache Version: {apache_version or 'Unknown'}")
                        print(f"Apache Comment: {apache_comment or 'None'}")
                        print(f"Detection Source: {detection_source}")
                        print(f"Requests Made: {request_counter} in {duration:.2f}s ({rps:.2f} RPS)")
                    else:
                        print("Not an Apache server or version could not be determined.")
                        print(f"Requests Made: {request_counter} in {duration:.2f}s ({rps:.2f} RPS)")

            except Exception as e:
                print(e)
                print(f"Error processing {url}: {e}")
                return

            await page.close()
            await browser.close()
            

            # k = 1|000|000|000


def writeResult(fmt, *args):
    print(fmt % args)

def main():
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    curr_mode = sys.argv[1] if len(sys.argv) > 1 else "wordpress"
    if curr_mode not in ["wordpress", "jssearch", "csp"]:
        print("Usage: python stealth_crawler.py <mode>")
        print("Modes: wordpress, jssearch, csp")
        return
    if curr_mode == "jssearch":
        if len(sys.argv) < 3:
            print("Usage: python stealth_crawler.py jssearch <keyword>")
            return
    if curr_mode == "csp":
        if len(sys.argv) >= 3:
            print("Usage: python stealth_crawler.py csp")
            return


    num_cores = multiprocessing.cpu_count()
    num_cores = 14
    print(f"Running on {num_cores} cores")

    manager = multiprocessing.Manager()
    counters = manager.dict({'totalCrawled': 0, 'hasCSPHeaderCount': 0, 'successCount': 0,
                             'hasMetaCSPCount': 0, 'inlineScriptCount': 0, 'unsafeInlineEventHandlersCount': 0,
                             'inlineStyleCount': 0, 'evalUsageCount': 0, 'postMessageUsageCount': 0,
                             'jsonpEndpointsCount': 0, 'externalScriptCount': 0, 'sameOriginScriptsCount': 0,
                             'crossOriginScriptsCount': 0, 'modernFrameworkCount': 0, 'hdrCTOCount': 0,
                             'outputEncodingCount': 0, 'inputValidationCount': 0, 'sandboxedIframesCount': 0,
                             'cookieHttpOnlyCount': 0, 'sensitiveFormsCount': 0, 'riskHighCount': 0, 'riskMediumCount': 0,
                             'riskLowCount': 0, 'riskMinimalCount': 0, 'protections': []
                             })

    tasks = []
    with open("urls.txt", "r") as f:
        urls = f.readlines()
        for raw_url in urls:
            raw_url = raw_url.strip()
            full_url = "https://www." + raw_url
            tasks.append(full_url)
    with multiprocessing.Pool(num_cores) as pool:
        pool.starmap(sync_grab, [(tasks, counters) for tasks in tasks])

    if curr_mode == "csp":
        writeResult("\nCSP and XSS Protection Analysis over %d domains:\n", counters['totalCrawled'])
        writeResult("CSP Implementation:\n")
        writeResult("  Has CSP header: %d (%.1f%%)\n", counters['hasCSPHeaderCount'],
                    (counters['hasCSPHeaderCount'] / counters['successCount']) * 100)
        writeResult("  Has meta CSP: %d (%.1f%%)\n", counters['hasMetaCSPCount'],
                    (counters['hasMetaCSPCount'] / counters['successCount']) * 100)

        writeResult("\nXSS Risk Indicators (average per url):\n")
        writeResult("  Inline scripts: %.2f\n", counters['inlineScriptCount'] / counters['successCount'])
        writeResult("  Inline event handlers: %.2f\n",
                    counters['unsafeInlineEventHandlersCount'] / counters['successCount'])
        writeResult("  Inline styles: %.2f\n", counters['inlineStyleCount'] / counters['successCount'])
        writeResult("  eval() usage: %.2f\n", counters['evalUsageCount'] / counters['successCount'])
        writeResult("  postMessage usage: %.2f\n", counters['postMessageUsageCount'] / counters['successCount'])
        writeResult("  JSONP endpoints: %.2f\n", counters['jsonpEndpointsCount'] / counters['successCount'])

        writeResult("\nScript Loading Patterns (average per url):\n")
        writeResult("  External scripts: %.2f\n", counters['externalScriptCount'] / counters['successCount'])
        writeResult("  Cross-origin scripts: %.2f\n", counters['crossOriginScriptsCount'] / counters['successCount'])
        writeResult("  Same-origin scripts: %.2f\n", counters['sameOriginScriptsCount'] / counters['successCount'])

        writeResult("\nXSS Protection Measures:\n")
        writeResult("  Modern frameworks: %d (%.1f%%)\n", counters['modernFrameworkCount'],
                    (counters['modernFrameworkCount'] / counters['successCount']) * 100)
        writeResult("  X-Content-Type-Options: %d (%.1f%%)\n", counters['hdrCTOCount'],
                    (counters['hdrCTOCount'] / counters['successCount']) * 100)
        writeResult("  Output encoding: %d (%.1f%%)\n", counters['outputEncodingCount'],
                    (counters['outputEncodingCount'] / counters['successCount']) * 100)
        writeResult("  Input validation: %d (%.1f%%)\n", counters['inputValidationCount'],
                    (counters['inputValidationCount'] / counters['successCount']) * 100)
        writeResult("  Sandboxed iframes: %d (%.1f%%)\n", counters['sandboxedIframesCount'],
                    (counters['sandboxedIframesCount'] / counters['successCount']) * 100)
        writeResult("  HttpOnly cookies: %d (%.1f%%)\n", counters['cookieHttpOnlyCount'],
                    (counters['cookieHttpOnlyCount'] / counters['successCount']) * 100)
        writeResult("  Sensitive forms: %d (%.1f%%)\n", counters['sensitiveFormsCount'],
                    (counters['sensitiveFormsCount'] / counters['successCount']) * 100)

        writeResult("\nXSS Risk Assessment (sites without CSP):\n")
        writeResult("  High risk: %d (%.1f%%)\n", counters['riskHighCount'],
                    (counters['riskHighCount'] / counters['successCount']) * 100)
        writeResult("  Medium risk: %d (%.1f%%)\n", counters['riskMediumCount'],
                    (counters['riskMediumCount'] / counters['successCount']) * 100)
        writeResult("  Low risk: %d (%.1f%%)\n", counters['riskLowCount'],
                    (counters['riskLowCount'] / counters['successCount']) * 100)
        writeResult("  Minimal risk: %d (%.1f%%)\n", counters['riskMinimalCount'],
                    (counters['riskMinimalCount'] / counters['successCount']) * 100)

def sync_grab(full_url, counters):
    url = full_url.split("https://www.")[-1]
    # print(full_url)
    asyncio.run(grab(full_url, f"screenshots/{url}.png", sys.argv[1], counters))

if __name__ == "__main__":
    timer = time.time()
    with open("urls.txt", "r") as f:
        numlines = sum(1 for line in f)
    main()
    print(f"Total time: {time.time() - timer}")
    print(f"Time per site: {(time.time() - timer) / numlines:.2f} seconds")