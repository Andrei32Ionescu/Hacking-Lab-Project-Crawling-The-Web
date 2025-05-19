import asyncio
import logging
import random
from typing import Any, Awaitable, Callable, Dict, Optional

from playwright.async_api import Page

log = logging.getLogger(__name__)


class SessionError(RuntimeError):
    """Raised when a Cloudflare block cannot be bypassed."""
    pass


# Typing helpers
IsPageBool = Callable[[Page], Awaitable[bool]]
ClickCb   = Callable[[Page, Dict[str, float]], Awaitable[None]]

async def safe_eval(page: Page, js: str, *, retries=2):
    for _ in range(retries):
        try:
            return await page.evaluate(js)
        except Exception as e:
            # if "context was destroyed" not in
            await page.wait_for_load_state("domcontentloaded")

    return None

async def handle_cloudflare_challenge(
    page: Page,
    url: str,
    session: Optional[Any] = None,
    options: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Rough Python port of Crawlee's handleCloudflareChallenge.
    Designed for Playwright-Python (async) with no external dependencies.

    Parameters
    ----------
    page : playwright.async_api.Page
        The page that might be stuck behind a CF challenge.
    url  : str
        Only used for logging / error messages.
    session : Any, optional
        Pass your own session‐tracking object if you keep one; may be None.
        If you hand in the original Crawlee Session, its .sessionPool
        structure will be honoured (the 403-unblock logic).
    options : dict, optional
        Keys (all optional):
            verbose : bool  -> use INFO instead of DEBUG level logs
            sleep_secs : int -> seconds to wait after clicking (default 10)
            click_callback(page, coords) -> custom click impl
            is_challenge_callback(page)  -> custom detector
            is_blocked_callback(page)    -> custom detector
    """
    if options is None:
        options = {}
    verbose: bool = options.get("verbose", False)
    sleep_secs: int = options.get("sleep_secs", 0.1)
    click_callback: Optional[ClickCb] = options.get("click_callback")
    is_challenge_callback: Optional[IsPageBool] = options.get("is_challenge_callback")
    is_blocked_callback: Optional[IsPageBool] = options.get("is_blocked_callback")

    # ------------------------------------------------------------------
    # 1)  Remove 403 from session-level "blocked status codes" (Crawlee quirk)
    # ------------------------------------------------------------------
    try:
        blocked_status_codes = (
            session.get("sessionPool", {}).get("blockedStatusCodes", [])  # type: ignore
            if session
            else None
        )
        if blocked_status_codes and 403 in blocked_status_codes:
            blocked_status_codes.remove(403)
    except Exception:
        pass  # Not critical if structure differs

    # ------------------------------------------------------------------
    # 2)  Default detectors when none supplied
    # ------------------------------------------------------------------
    if is_blocked_callback is None:
        async def is_blocked_callback(page: Page) -> bool:  # type: ignore[assignment]
            return await safe_eval(page, """
                () => {
                    const h1 = document.querySelector('h1');
                    return !!h1 && h1.textContent.trim().includes('Sorry, you have been blocked');
                }
            """)

    if is_challenge_callback is None:
        async def is_challenge_callback(page: Page) -> bool:  # type: ignore[assignment]
            return await safe_eval(page, """
                () => !!document.querySelector('.footer > .footer-inner > .diagnostic-wrapper > .ray-id')
            """)

    # ------------------------------------------------------------------
    async def retry_blocked() -> None:
        if await is_blocked_callback(page):
            raise SessionError(f"Blocked by Cloudflare when processing {url}")

    async def is_challenge() -> bool:
        return await is_challenge_callback(page)

    # ------------------------------------------------------------------
    # 3)  Short-circuit if we are NOT on a challenge page
    # ------------------------------------------------------------------
    if not await is_challenge():
        await retry_blocked()
        return

    # ------------------------------------------------------------------
    # 4)  Log what we’re about to do
    # ------------------------------------------------------------------
    lvl = logging.INFO if verbose else logging.DEBUG
    log.log(
        lvl,
        "Detected Cloudflare challenge at %s, trying to solve it. "
        "This can take up to %s seconds.",
        url,
        10 + sleep_secs,
    )

    # ------------------------------------------------------------------
    # 5)  Find checkbox bounding box (.main-content div)
    # ------------------------------------------------------------------
    bb = await safe_eval(page, """
        () => {
            const div = document.querySelector('.main-content div');
            return div ? div.getBoundingClientRect() : null;
        }
    """)
    if not bb:
        return

    x = bb["x"] + 20
    y = bb["y"] + 20

    rand = lambda rng: round(random.random() * rng * 100) / 100  # noqa: E731

    # ------------------------------------------------------------------
    # 6)  Attempt to click up to 10 times (1× sec)
    # ------------------------------------------------------------------
    for _ in range(100):
        await asyncio.sleep(1)

        # Break early if page already solved itself
        if not await is_challenge():
            break

        if click_callback:
            await click_callback(page, {"x": x, "y": y})
            continue

        xr = x + rand(10)
        yr = y + rand(10)
        log.log(lvl, "Trying to click Cloudflare checkbox at %s (%.2f, %.2f)", url, xr, yr)
        await page.mouse.click(xr, yr)
        await asyncio.sleep(0.35)
        await page.mouse.click(xr , yr + 35)

    # ------------------------------------------------------------------
    # 7)  Wait extra seconds for CF to redirect
    # ------------------------------------------------------------------
    await asyncio.sleep(sleep_secs)

    if await is_challenge():
        raise SessionError(f"Blocked by Cloudflare when processing {url}")

    await retry_blocked()