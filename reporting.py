"""Builds the KE-CIRT/CC reporter from environment settings and sends one finding's report."""
import logging
import os

from src.remediation.reporting_bot import ThreatReporter

log = logging.getLogger("DRP-Reporting")


def build_reporter():
    server, sender, password = (os.getenv(k) for k in ("SMTP_SERVER", "SMTP_SENDER", "SMTP_PASSWORD"))
    if not (server and sender and password):
        log.warning("SMTP_SERVER / SMTP_SENDER / SMTP_PASSWORD not set; email reporting is disabled.")
        return None
    return ThreatReporter(smtp_server=server, smtp_port=int(os.getenv("SMTP_PORT", "587")),
                          sender_email=sender, sender_password=password)


def send_finding_report(finding):
    """finding: a dict with domain, sha256, serial, screenshot. Returns True when the email was sent."""
    reporter = build_reporter()
    if reporter is None:
        return False
    try:
        reporter.dispatch_kecirt_report(target_domain=finding["domain"], sha256_hash=finding["sha256"],
                                        serial_number=finding["serial"], screenshot_path=finding["screenshot"])
        log.info("Takedown notice sent to KE-CIRT/CC for %s", finding["domain"])
        return True
    except Exception as e:
        log.error("Failed to send the KE-CIRT report for %s: %r", finding["domain"], e)
        return False
