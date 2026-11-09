"""Sends takedown reports by email (starter version). Set KECIRT_REPORT_TO to the official KE-CIRT/CC address."""
import mimetypes
import os
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage


class ThreatReporter:
    def __init__(self, smtp_server, smtp_port, sender_email, sender_password, recipient=None):
        self.smtp_server, self.smtp_port = smtp_server, int(smtp_port)
        self.sender_email, self.sender_password = sender_email, sender_password
        self.recipient = recipient or os.getenv("KECIRT_REPORT_TO")

    def dispatch_kecirt_report(self, target_domain, sha256_hash, serial_number, screenshot_path, html_path=None):
        if not self.recipient:
            raise RuntimeError("KECIRT_REPORT_TO is not set. Set it to the official KE-CIRT/CC reporting address.")
        msg = EmailMessage()
        msg["From"], msg["To"] = self.sender_email, self.recipient
        msg["Subject"] = f"Takedown request: suspected brand impersonation at {target_domain}"
        msg.set_content(
            "Dear KE-CIRT/CC team,\n\n"
            f"We are reporting a suspected brand-impersonation website: {target_domain}\n\n"
            f"Evidence captured (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"SHA-256 of the attached screenshot: {sha256_hash}\n"
            f"Registered key serial found on the site: {serial_number or 'none'}\n\n"
            "Please assess the site and arrange takedown or suspension where appropriate.\n\n"
            f"Reporter: {self.sender_email}\n")
        if not html_path and screenshot_path:
            html_path = os.path.splitext(screenshot_path)[0] + ".html"
        for path in (screenshot_path, html_path):          # screenshot and raw HTML dump
            if path and os.path.isfile(path):
                ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
                with open(path, "rb") as f:
                    msg.add_attachment(f.read(), maintype=ctype.split("/")[0], subtype=ctype.split("/")[1],
                                       filename=os.path.basename(path))
        with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(self.sender_email, self.sender_password)
            s.send_message(msg)
