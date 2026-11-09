"""One-command demo: seeds sample companies/findings and starts the dashboard.
No certstream, Playwright or SMTP needed.   Run:  python demo.py   then open http://127.0.0.1:5000
The forgot-password code is shown on screen in demo mode (normally it is only emailed)."""
import os
import struct
import zlib

os.environ.setdefault("DRP_DB", "./demo.db")      # SQLite file; a real install uses DATABASE_URL (PostgreSQL)
os.environ.setdefault("CELERY_ALWAYS_EAGER", "true")   # no Redis needed: tasks run immediately
os.environ.setdefault("STEGO_KEY", "demo-only-stego-key")
os.environ.setdefault("SECRET_KEY", "demo-only-secret-change-me")
os.environ.setdefault("ARTIFACT_DIR", "./artifacts")
os.environ.setdefault("UPLOAD_DIR", "./uploads")
os.environ.setdefault("DRP_SHOW_RESET_CODE", "true")

from werkzeug.security import generate_password_hash  # noqa: E402
from src import assets, db, documents, reporting  # noqa: E402
from dashboard.app import create_app  # noqa: E402

PASSWORDS = {
    "admin@demo.local": "Platform-Admin-2026!",
    "boss@acme.co.ke": "Boss-Acme-2026!",
    "analyst@acme.co.ke": "Analyst-Acme-2026!",
    "ceo@betapay.com": "BetaPay-CEO-2026!",
    "manager@pwanifresh.co.ke": "Pwani-Fresh-2026!",
}
PW = PASSWORDS["boss@acme.co.ke"]  # kept for older scripts


def png_bytes(w=640, h=360, shift=0):
    """A simple gradient PNG (stands in for screenshots and the trademark photo)."""
    rows = b"".join(b"\x00" + b"".join(bytes(((40 + x * 60 // w + shift) % 256, 70 + y * 90 // h, 140)) for x in range(w))
                    for y in range(h))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def pdf_bytes(title):
    return b"%PDF-1.4\n% " + title.encode() + b"\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"


def seed_fake_company():
    """FAKE company 'Pwani Fresh Ltd': verified, with findings produced by running the real detector on test domains."""
    from detection_check import CASES, FAKE
    from src.detection import assess_domain
    if db.get_user_by_email(FAKE["admin_email"]):
        return
    cid = db.create_company(
        {"legal_name": "Pwani Fresh Ltd", "registration_number": FAKE["registration_number"],
         "official_email": "info@pwanifresh.co.ke", "phone": "+254 722 000 111", "website": "https://pwanifresh.co.ke",
         "address": "Mombasa Road, Nairobi", "country": "Kenya"},
        FAKE["brands"], FAKE["domains"], FAKE["admin_email"], generate_password_hash(PASSWORDS[FAKE["admin_email"]]))
    db.save_kra(cid, FAKE["kra_pin"], "TM-2025-0310")
    for t, data in [("kra_pin_cert", pdf_bytes("Pwani KRA")), ("registration_cert", pdf_bytes("Pwani CR12")),
                    ("trademark_cert", pdf_bytes("Pwani TM")), ("trademark_photo", png_bytes(shift=200))]:
        documents.store_document(cid, t, f"pwani_{t}.{'png' if t == 'trademark_photo' else 'pdf'}", data)
    db.try_auto_verify(cid)
    os.makedirs(os.environ["ARTIFACT_DIR"], exist_ok=True)
    statuses = ["pending_review", "pending_review", "confirmed", "pending_review", "dismissed"]
    n = 0
    for domain, expect, _ in CASES:
        reason = assess_domain(domain, FAKE["brands"], FAKE["domains"])   # the real detector decides
        if not reason:
            continue
        shot = f"{domain.replace('.', '_')}.png"
        with open(os.path.join(os.environ["ARTIFACT_DIR"], shot), "wb") as f:
            f.write(png_bytes(shift=n * 17))
        fid = db.add_finding(cid, domain, reason, os.urandom(32).hex(), None, shot)
        st = statuses[n % len(statuses)]
        if fid and st in ("confirmed", "dismissed"):
            db.set_finding_status(cid, fid, st)
        if fid:
            db.backdate_finding(fid, n % 12)
        n += 1


class DemoReporter:
    """The demo never emails anyone: an approved report is just logged and marked as sent."""
    def dispatch_kecirt_report(self, target_domain, **kw):
        print(f"  [demo] would email KE-CIRT/CC about {target_domain}")


reporting.build_reporter = lambda: DemoReporter()


def seed():
    db.init_db()
    if db.get_user_by_email("admin@demo.local"):
        seed_fake_company()
        return
    H = {e: generate_password_hash(p) for e, p in PASSWORDS.items()}
    db.create_user(None, "admin@demo.local", H["admin@demo.local"], "platform_admin")

    acme = db.create_company(
        {"legal_name": "Acme Ltd", "registration_number": "PVT-2019-00421", "official_email": "info@acme.co.ke",
         "phone": "+254 700 000 000", "website": "https://acme.co.ke", "address": "Ruiru, Kiambu", "country": "Kenya"},
        ["acme"], ["acme.co.ke"], "boss@acme.co.ke", H["boss@acme.co.ke"])
    db.create_user(acme, "analyst@acme.co.ke", H["analyst@acme.co.ke"], "analyst")
    db.save_kra(acme, "P051234567A", "TM-2019-1187")
    for i, (t, data) in enumerate([("kra_pin_cert", pdf_bytes("Acme KRA PIN")), ("registration_cert", pdf_bytes("Acme CR12")),
                                   ("trademark_cert", pdf_bytes("Acme trademark")), ("trademark_photo", png_bytes(shift=90))]):
        documents.store_document(acme, t, f"acme_{t}.{'png' if t == 'trademark_photo' else 'pdf'}", data)
    db.try_auto_verify(acme)          # Acme is already verified

    db.create_company(                # Beta Pay stays pending so you can test the upload flow
        {"legal_name": "Beta Pay Ltd", "registration_number": "PVT-2022-01177", "official_email": "info@betapay.com",
         "phone": "+254 711 111 111", "website": "https://betapay.com", "address": "Westlands, Nairobi",
         "country": "Kenya"}, ["betapay"], ["betapay.com"], "ceo@betapay.com", H["ceo@betapay.com"])

    os.makedirs(os.environ["ARTIFACT_DIR"], exist_ok=True)
    sample = [
        ("acme-kenya-login.com", "brand embedded in domain (acme)", "SN-48213", "confirmed", 0),
        ("acrne.co.ke", "typosquat of brand, edit distance <= 1 (acme)", None, "pending_review", 1),
        ("secure-acme.net", "brand embedded in domain (acme)", None, "pending_review", 2),
        ("acme.xyz", "brand label on unowned domain/TLD (acme)", None, "pending_review", 3),
        ("acme-support.top", "brand embedded in domain (acme)", None, "dismissed", 4),
        ("acme-payments.shop", "brand embedded in domain (acme)", "SN-48199", "reported", 5),
    ]
    for dom, reason, serial, status, k in sample:
        shot = f"{dom.replace('.', '_')}.png"
        with open(os.path.join(os.environ["ARTIFACT_DIR"], shot), "wb") as f:
            f.write(png_bytes(shift=k * 30))
        fid = db.add_finding(acme, dom, reason, os.urandom(32).hex(), serial, shot)
        if status in ("confirmed", "reported"):
            db.set_finding_status(acme, fid, "confirmed")
        if status == "dismissed":
            db.set_finding_status(acme, fid, "dismissed")
        if status == "reported":
            db.set_finding_status(acme, fid, "approved_for_report")
            db.mark_reported(fid, True)
    # spread detections over the last days so the chart has shape
    for fid, back in ((1, 1), (2, 2), (3, 2), (4, 4), (5, 6), (6, 9)):
        db.backdate_finding(fid, back)
    assets.protect_asset(acme, "acme_logo.png", png_bytes(shift=40))          # a protected logo with a hidden serial
    seed_fake_company()


if __name__ == "__main__":
    seed()
    print("\nDemo ready -> http://127.0.0.1:5000   (each account has its own password)")
    for email, pw in PASSWORDS.items():
        print(f"  {email:<22} {pw}")
    print("  Pwani Fresh (manager@pwanifresh.co.ke) is a FAKE verified company whose findings come from detection_check.py's test domains.")
    print("  Beta Pay (ceo@betapay.com) is unverified: log in and upload documents on the Verification page.")
    print("  Forgot password? The code is shown on screen in demo mode.\n")
    create_app().run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
