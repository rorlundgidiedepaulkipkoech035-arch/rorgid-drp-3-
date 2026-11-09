"""Detection check against a FAKE company. No network, database or browser needed.
Run:  python detection_check.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.detection import assess_domain  # noqa: E402

FAKE = {
    "legal_name": "Pwani Fresh Ltd (FAKE, for testing)",
    "registration_number": "PVT-2025-99001",
    "kra_pin": "P053456789C",
    "brands": ["pwanifresh"],
    "domains": ["pwanifresh.co.ke", "pwanifresh.com"],      # the domains the company really owns
    "admin_email": "manager@pwanifresh.co.ke",
}

# (domain seen in a certificate, should it be flagged?, what it demonstrates)
CASES = [
    ("pwanifresh.co.ke", False, "company's own domain"),
    ("www.pwanifresh.com", False, "own subdomain"),
    ("mail.pwanifresh.co.ke", False, "own subdomain"),
    ("shop.pwanifresh.com", False, "own subdomain"),
    ("*.pwanifresh.com", False, "own wildcard certificate"),
    ("google.com", False, "unrelated site"),
    ("freshmart.co.ke", False, "shares only the word 'fresh'"),
    ("pwani.co.ke", False, "shares only the word 'pwani'"),
    ("example.org", False, "unrelated site"),
    ("pwanifresh-login.com", True, "brand + 'login' (phishing style)"),
    ("secure-pwanifresh.net", True, "'secure-' prefix"),
    ("pwanifresh-support.shop", True, "brand + 'support'"),
    ("pwanifresh-kenya.co.ke", True, "brand + country"),
    ("pwanifresh.xyz", True, "exact brand on another TLD"),
    ("pwanifresh.co.ke.verify-account.top", True, "brand hidden in the subdomain"),
    ("login.pwanifresh.evil-site.com", True, "brand as a subdomain of someone else's domain"),
    ("pwanifrech.co.ke", True, "one letter changed"),
    ("pwaniffresh.com", True, "one letter added"),
    ("pwanifrseh.com", True, "two letters swapped"),
    ("pwani-fresh.com", True, "hyphen inserted"),
    ("pwan1fresh.com", True, "digit 1 instead of i"),
    ("pwаnifresh.com", True, "Cyrillic 'а' instead of Latin 'a'"),
]

if __name__ == "__main__":
    print(f"Fake company: {FAKE['legal_name']}  |  brand: {FAKE['brands'][0]}  |  owns: {', '.join(FAKE['domains'])}\n")
    print(f"{'domain seen in certificate':<40}{'expected':<10}{'result':<9}why / note")
    print("-" * 110)
    bad = 0
    for domain, expect, note in CASES:
        reason = assess_domain(domain, FAKE["brands"], FAKE["domains"])
        got = reason is not None
        bad += got != expect
        print(f"{domain:<40}{'FLAG' if expect else 'ignore':<10}{'FLAGGED' if got else 'ignored':<9}"
              f"{'OK   ' if got == expect else 'WRONG'} {reason or note}")
    print(f"\n{len(CASES) - bad}/{len(CASES)} as expected")
    sys.exit(1 if bad else 0)
