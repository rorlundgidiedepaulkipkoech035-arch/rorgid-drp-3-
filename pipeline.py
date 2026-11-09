"""The evidence pipeline for one flagged domain (asyncio). Runs inside a Celery worker."""
import asyncio
import logging
import os

from src import db, reporting
from src.workers import scraper

log = logging.getLogger("DRP-Pipeline")
AUTO_REPORT = os.getenv("DRP_AUTO_REPORT", "false").lower() == "true"


async def handle_threat(domain, reason="", company_id=None, company_auto_report=False, scrape=None):
    """Collect evidence, store the finding for the company's dashboard, optionally auto-report.
    Returns "exists", "error" or "stored"."""
    scrape = scrape or scraper.process_suspicious_domain
    if await asyncio.to_thread(db.finding_exists, company_id, domain):
        return "exists"
    log.info("[*] Collecting evidence for %s (company %s)", domain, company_id)
    try:
        result = await scrape(domain)
    except Exception as e:
        log.error("[-] Scrape crashed for %s: %r", domain, e)
        return "error"
    if "error" in result:
        log.error("[-] Scrape failed for %s: %s", domain, result["error"])
        return "error"

    serial = result.get("serial_detected")
    if serial:
        owner = await asyncio.to_thread(db.serial_owner, serial)
        if owner is None:
            pass                                        # serial from an older watermark checker: keep as before
        elif owner == company_id:
            reason += " | key serial matches this company's registered asset"
        else:
            serial = None                               # another company's asset is not evidence for this company
    screenshot = result.get("screenshot") or os.path.join(scraper.artifact_dir(), f"{domain.replace('.', '_')}.png")
    fid = await asyncio.to_thread(db.add_finding, company_id, domain, reason, result.get("sha256"), serial, screenshot)
    if fid is None:
        return "exists"
    if serial:
        log.critical("[!] CONFIRMED WATERMARK MATCH! %s on %s (company %s)", serial, domain, company_id)
    else:
        log.info("[+] %s stored for company %s; awaiting review.", domain, company_id)

    if serial and AUTO_REPORT and company_auto_report:
        finding = {"domain": domain, "sha256": result.get("sha256"), "serial": serial, "screenshot": screenshot}
        ok = await asyncio.to_thread(reporting.send_finding_report, finding)
        await asyncio.to_thread(db.mark_reported, fid, ok)
    return "stored"
