"""Sends email through the SMTP account configured in SMTP_SERVER / SMTP_SENDER / SMTP_PASSWORD."""
import logging
import os
import smtplib
from email.message import EmailMessage

log = logging.getLogger("DRP-Mailer")


def send_mail(to, subject, body):
    server, sender, password = (os.getenv(k) for k in ("SMTP_SERVER", "SMTP_SENDER", "SMTP_PASSWORD"))
    if not (server and sender and password):
        log.warning("SMTP is not configured; email to %s was not sent.", to)
        return False
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, to, subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(server, int(os.getenv("SMTP_PORT", "587")), timeout=15) as s:
            s.starttls()
            s.login(sender, password)
            s.send_message(msg)
        return True
    except Exception as e:
        log.error("Could not send email to %s: %r", to, e)
        return False
