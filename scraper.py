"""Evidence collection for a suspicious domain (Playwright async API).

Opens the site in an isolated headless Chromium, saves a full-page screenshot and the raw HTML, hashes both
(SHA-256 chain of custody) and looks for the company's REGISTERED assets: an exact copy of a registered file, a
hidden LSB serial number extracted with OpenCV/NumPy (src/stego.py), or a registered serial printed on the page.
Safety: the domain must resolve to public addresses only, the browser is pinned to that address, and every
request to any other host is blocked (certificate names are attacker-controlled).
"""
import asyncio
import hashlib
import ipaddress
import logging
import os
import re
import socket
from urllib.parse import urlparse

from src import db, stego

logger = logging.getLogger("DRP-Scraper")
SERIAL_RE = re.compile(r"RGD-\d{4}-[0-9A-F]{8}")
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGES = 30


def artifact_dir():
    return os.getenv("ARTIFACT_DIR", "./artifacts")


def is_public_ip(ip):
    return ipaddress.ip_address(ip).is_global            # false for private, loopback, link-local, reserved


def resolve_public(domain, resolver=socket.getaddrinfo):
    """Returns one public IP for the domain or raises ValueError (never lets the browser reach internal hosts)."""
    infos = resolver(domain, 443, type=socket.SOCK_STREAM)
    ips = sorted({i[4][0] for i in infos}, key=lambda x: ":" in x)      # IPv4 first
    if not ips:
        raise ValueError("domain does not resolve")
    for ip in ips:
        if not is_public_ip(ip):
            raise ValueError(f"refused: resolves to a non-public address ({ip})")
    return ips[0]


def find_serials(text):
    return sorted(set(SERIAL_RE.findall(text or "")))


async def detect_registered_serial(images, html):
    """Looks for a REGISTERED serial. Returns (serial, how) or (None, None). `images` is a list of image bytes.
    A serial counts only if it is registered to some company, so a planted fake serial proves nothing."""
    for body in images:                                          # 1. exact copy of a registered file
        found = await asyncio.to_thread(db.serial_by_hash, hashlib.sha256(body).hexdigest())
        if found:
            return found, "exact-copy"
    marks = await asyncio.gather(*(asyncio.to_thread(stego.extract_serial, body) for body in images))
    for mark in marks:                                           # 2. hidden LSB mark (OpenCV + NumPy)
        if mark and await asyncio.to_thread(db.serial_owner, mark) is not None:
            return mark, "hidden-mark"
    for text_serial in find_serials(html):                       # 3. serial printed in the page
        if await asyncio.to_thread(db.serial_owner, text_serial) is not None:
            return text_serial, "printed-text"
    return None, None


async def process_suspicious_domain(domain):
    """Returns {"sha256", "html_sha256", "serial_detected", "serial_source", "screenshot", "html_file"}
    or {"error": "..."}."""
    domain = (domain or "").strip().lower()
    if not db.DOMAIN_RE.match(domain):
        return {"error": "invalid domain"}
    try:
        ip = await asyncio.to_thread(resolve_public, domain)
    except Exception as e:
        return {"error": str(e)}
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "playwright is not installed"}

    timeout_ms = int(os.getenv("SCRAPE_TIMEOUT_SECONDS", "20")) * 1000
    os.makedirs(artifact_dir(), exist_ok=True)
    shot_path = os.path.join(artifact_dir(), f"{domain.replace('.', '_')}.png")
    html_path = os.path.splitext(shot_path)[0] + ".html"
    images, tasks, html, last_error = [], [], "", None
    rule_ip = f"[{ip}]" if ":" in ip else ip
    args = [f"--host-resolver-rules=MAP {domain} {rule_ip}"]
    if os.getenv("PLAYWRIGHT_NO_SANDBOX", "false").lower() == "true":
        args.append("--no-sandbox")
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=args)
            try:
                ctx = await browser.new_context(accept_downloads=False, ignore_https_errors=True,
                                                viewport={"width": 1280, "height": 900}, permissions=[])
                page = await ctx.new_page()

                async def gate(route):                    # only the suspicious domain itself may be contacted
                    if (urlparse(route.request.url).hostname or "") == domain:
                        await route.continue_()
                    else:
                        await route.abort()
                await page.route("**/*", gate)

                async def grab(resp):
                    try:
                        if resp.request.resource_type == "image":
                            body = await resp.body()
                            if body and len(body) <= MAX_IMAGE_BYTES and len(images) < MAX_IMAGES:
                                images.append(body)
                    except Exception:
                        pass
                page.on("response", lambda r: tasks.append(asyncio.ensure_future(grab(r))))

                loaded = False
                for scheme in ("https", "http"):
                    try:
                        await page.goto(f"{scheme}://{domain}", wait_until="load", timeout=timeout_ms)
                        loaded = True
                        break
                    except Exception as e:
                        last_error = e
                if not loaded:
                    return {"error": f"could not load site: {last_error}"}
                await page.wait_for_timeout(1500)
                await asyncio.gather(*tasks, return_exceptions=True)
                html = (await page.content())[:2_000_000]
                await page.screenshot(path=shot_path, full_page=True)
            finally:
                await browser.close()
    except Exception as e:
        return {"error": f"browser error: {e}"}

    with open(html_path, "w", encoding="utf-8") as f:     # raw DOM dump kept as evidence
        f.write(html)
    with open(shot_path, "rb") as f:
        shot_hash = hashlib.sha256(f.read()).hexdigest()
    serial, how = await detect_registered_serial(images, html)
    return {"sha256": shot_hash, "html_sha256": hashlib.sha256(html.encode()).hexdigest(),
            "serial_detected": serial, "serial_source": how, "screenshot": shot_path, "html_file": html_path}
