"""Back-end demo: walks the whole platform through its real code (no browser) and prints what happened.
Run:  python demo_backend.py      (temporary database, a stand-in for the scraper, a captured email)
Uses the real SQLAlchemy layer and Celery when they are installed (Celery runs in eager mode, no Redis needed)."""
import asyncio
import hashlib
import io
import os
import re
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tests_support  # noqa: E402

USING = tests_support.install()
tmp = tempfile.mkdtemp()
os.environ.update(DRP_DB=f"{tmp}/demo.db", UPLOAD_DIR=f"{tmp}/uploads", ARTIFACT_DIR=f"{tmp}/art", SECRET_KEY="demo-backend",
                  STEGO_KEY="demo-backend-stego", CELERY_ALWAYS_EAGER="true", REGISTRY_REFRESH_SECONDS="0", ALLOW_DB_RESET="true")
sys.modules["certstream"] = types.SimpleNamespace(listen_for_events=lambda *a, **k: None)

import cv2  # noqa: E402
import numpy as np  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402
from dashboard.app import create_app  # noqa: E402
from src import db, mailer, reporting, security, stego  # noqa: E402
from src.workers import scraper, tasks  # noqa: E402
import main  # noqa: E402

PW = "Savannah-Admin-2026!"
ok_count = fail_count = 0
reports, inbox = [], []


def step(title):
    print(f"\n=== {title}")


def check(label, cond, detail=""):
    global ok_count, fail_count
    ok_count += bool(cond)
    fail_count += (not cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  -> {detail}" if detail else ""))


def token(c, path="/login"):
    return re.search(r'name="csrf_token" value="([^"]+)"', c.get(path).get_data(as_text=True)).group(1)


def logo_png(seed=7):
    return cv2.imencode(".png", np.random.default_rng(seed).integers(0, 256, (300, 400, 3), dtype=np.uint8))[1].tobytes()


class FakeReporter:
    def dispatch_kecirt_report(self, **kw):
        reports.append(kw)


reporting.build_reporter = lambda: FakeReporter()
mailer.send_mail = lambda to, subject, body: inbox.append((to, subject, body)) or True
rogue_site_images = []                                  # what the "scraper" finds on the suspicious site


async def stand_in_scraper(domain):                     # replaces Playwright (no network here)
    serial, how = await scraper.detect_registered_serial(rogue_site_images, "")
    return {"sha256": hashlib.sha256(domain.encode()).hexdigest(), "serial_detected": serial, "serial_source": how,
            "screenshot": f"{tmp}/art/{domain.replace('.', '_')}.png"}


scraper.process_suspicious_domain = stand_in_scraper
app = create_app()
db.reset_all()
db.create_user(None, "root@platform.io", generate_password_hash("Platform-Root-1!"), "platform_admin")
client = app.test_client()
print(f"database layer: {USING['db']} | task queue: {USING['celery']}")

step("1. Password rules (8+ chars, upper, lower, special)")
for pw in ("short", "alllowercase1!", "NoSpecial123", PW):
    p = security.password_problem(pw)
    check(f"{pw!r}", (p is None) == (pw == PW), p or "accepted")

step("2. Company registration")
form = dict(legal_name="Savannah Tech Ltd", registration_number="PVT-2024-05512", official_email="info@savannahtech.co.ke",
            phone="0700", website="https://savannahtech.co.ke", address="Thika Road, Nairobi", country="Kenya",
            brands="savannahtech, savannahpay", domains="savannahtech.co.ke, savannahpay.com",
            admin_email="wanjiku@savannahtech.co.ke", password=PW, password2=PW)
bad = client.post("/register", data={**form, "admin_email": "wanjiku@gmail.com", "csrf_token": token(client, "/register")})
check("admin email outside company domains is rejected", bad.status_code == 400)
r = client.post("/register", data={**form, "csrf_token": token(client, "/register")})
cid = db.get_user_by_email("wanjiku@savannahtech.co.ke")["company_id"]
check("registration accepted", r.status_code == 302)
check("company starts pending and is not monitored", db.get_company(cid)["status"] == "pending" and db.registry_snapshot() == [])

step("3. Login sends a pending company admin to the verification page")
client.post("/login", data={"email": "wanjiku@savannahtech.co.ke", "password": PW, "csrf_token": token(client)})
r = client.get("/dashboard")
check("redirected to /verification", r.status_code == 302 and r.headers["Location"].endswith("/verification"))

step("4. Upload KRA PIN and documents (back end hashes each file and issues a key serial)")
files = {"kra_pin_cert": (b"%PDF-1.4 KRA certificate of Savannah", "kra.pdf"), "registration_cert": (b"%PDF-1.4 Certificate of incorporation", "cr12.pdf"),
         "trademark_cert": (b"%PDF-1.4 Trademark registration certificate", "tm.pdf"), "trademark_photo": (logo_png(1), "logo.png")}
client.post("/verification/details", data={"kra_pin": "P051234567A", "trademark_number": "TM-2024-0042", "csrf_token": token(client, "/verification")})
check("KRA PIN P051234567A saved", db.get_company(cid)["kra_pin"] == "P051234567A")
for t, (data, name) in files.items():
    client.post(f"/verification/upload/{t}", content_type="multipart/form-data",
                data={"csrf_token": token(client, "/verification"), "file": (io.BytesIO(data), name)})
    d = [x for x in db.documents(cid) if x["doc_type"] == t][0]
    stored = open(os.path.join(os.environ["UPLOAD_DIR"], d["stored_name"]), "rb").read()
    check(f"{t}: serial {d['serial']}, stored file re-hashes to {d['sha256'][:16]}...", d["sha256"] == hashlib.sha256(data).hexdigest() == hashlib.sha256(stored).hexdigest())
check("company verified automatically after the last upload", db.get_company(cid)["status"] == "approved")
check("monitoring started for its brands", db.registry_snapshot()[0]["brands"] == ["savannahpay", "savannahtech"])

step("5. Fraud checks")
other = app.test_client()
other.post("/register", data={**form, "legal_name": "Copycat Ltd", "registration_number": "PVT-1", "official_email": "x@copy.co.ke",
                              "brands": "copycat", "domains": "copy.co.ke", "admin_email": "b@copy.co.ke", "csrf_token": token(other, "/register")})
other.post("/login", data={"email": "b@copy.co.ke", "password": PW, "csrf_token": token(other)})
r = other.post("/verification/upload/trademark_photo", content_type="multipart/form-data", follow_redirects=True,
               data={"csrf_token": token(other, "/verification"), "file": (io.BytesIO(files["trademark_photo"][0]), "stolen.png")})
check("the same trademark photo cannot be registered by another company", "already registered" in r.get_data(as_text=True))
r = other.post("/verification/details", data={"kra_pin": "P051234567A", "csrf_token": token(other, "/verification")}, follow_redirects=True)
check("the same KRA PIN cannot be registered twice", "already registered to another company" in r.get_data(as_text=True))
r = other.post("/verification/upload/kra_pin_cert", content_type="multipart/form-data", follow_redirects=True,
               data={"csrf_token": token(other, "/verification"), "file": (io.BytesIO(b"MZ evil.exe"), "kra.pdf")})
check("an .exe renamed .pdf is rejected (real file type is checked)", "Unsupported file" in r.get_data(as_text=True))
check("another company cannot download Savannah's documents", other.get(f"/documents/{db.documents(cid)[0]['id']}").status_code == 404)

step("6. Steganography: hide a serial number inside the company logo (OpenCV + NumPy)")
original = logo_png(7)
client.post("/assets/upload", content_type="multipart/form-data",
            data={"csrf_token": token(client, "/assets"), "file": (io.BytesIO(original), "savannah_logo.png")})
[asset] = db.list_assets(cid)
protected = client.get(f"/assets/{asset['id']}/download").data
diff = np.abs(cv2.imdecode(np.frombuffer(original, np.uint8), 1).astype(int) - cv2.imdecode(np.frombuffer(protected, np.uint8), 1).astype(int))
check(f"serial {asset['serial']} embedded; no pixel changed by more than {diff.max()} grey level", diff.max() <= 1)
check("the serial is extracted back from the protected PNG", stego.extract_serial(protected) == asset["serial"])
lossy = cv2.imencode(".jpg", cv2.imdecode(np.frombuffer(protected, np.uint8), 1), [cv2.IMWRITE_JPEG_QUALITY, 90])[1].tobytes()
check("a lossy JPEG copy loses the mark (documented limit)", stego.extract_serial(lossy) is None)
os.environ["STEGO_KEY"] = "some-other-key"
check("without the secret key the mark cannot be read", stego.extract_serial(protected) is None)
os.environ["STEGO_KEY"] = "demo-backend-stego"

step("7. Engine: certificate stream -> detection -> Celery queue -> worker -> evidence -> finding")
resaved = cv2.imencode(".png", cv2.imdecode(np.frombuffer(protected, np.uint8), cv2.IMREAD_UNCHANGED), [cv2.IMWRITE_PNG_COMPRESSION, 9])[1].tobytes()
rogue_site_images.append(resaved)                       # the rogue site re-saved our logo (so the file hash differs)
main.registry.reload()
message = {"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": [
    "savannahtech-login.com", "savannahtec.co.ke", "www.savannahtech.co.ke", "unrelated.org"]}}}
asyncio.run(main.handle_message(message))               # default dispatch = Celery task (eager here)
found = sorted(f["domain"] for f in db.list_findings(cid))
check("typosquats flagged; own sub-domain and unrelated domains ignored", found == ["savannahtec.co.ke", "savannahtech-login.com"], str(found))
f = [x for x in db.list_findings(cid) if x["domain"] == "savannahtech-login.com"][0]
check("the hidden serial was found on the rogue site and recorded as evidence", f["serial"] == asset["serial"] and "key serial matches" in f["reason"])
page = client.get("/dashboard").get_data(as_text=True)
check("overview shows KPI cards, donut and 14-day chart", "kpi" in page and "stroke-dasharray" in page and page.count('class="bar"') == 14)

step("8. Takedown only after a company admin approves")
check("nothing sent automatically", reports == [])
client.post(f"/findings/{f['id']}/confirm", data={"csrf_token": token(client, "/dashboard")})
client.post(f"/findings/{f['id']}/report", data={"csrf_token": token(client, "/dashboard")})
check("report queued on Celery, sent once to KE-CIRT/CC", len(reports) == 1 and reports[0]["target_domain"] == "savannahtech-login.com")
check("finding marked reported", db.get_finding(cid, f["id"])["status"] == "reported")
check("a second send of the same report does nothing", tasks.send_report_task(f["id"]) == "skipped" and len(reports) == 1)

step("9. Forgot password (code sent to the registered email)")
client2 = app.test_client()
client2.post("/forgot-password", data={"email": "wanjiku@savannahtech.co.ke", "csrf_token": token(client2, "/forgot-password")})
to, subject, body = inbox[-1]
code = re.search(r"code is (\d{6})", body).group(1)
check(f"6-digit code emailed to {to}", to == "wanjiku@savannahtech.co.ke" and len(code) == 6, f"subject: {subject}")
r = client2.post("/reset-password", data={"email": to, "code": code, "new": "weakpass", "new2": "weakpass", "csrf_token": token(client2, "/reset-password")})
check("right code but weak new password is refused", r.status_code == 400)
r = client2.post("/reset-password", data={"email": to, "code": code, "new": "Brand-New-Pass9!", "new2": "Brand-New-Pass9!", "csrf_token": token(client2, "/reset-password")})
check("password reset with the code", r.status_code == 302)
r = client2.post("/login", data={"email": to, "password": "Brand-New-Pass9!", "csrf_token": token(client2)})
check("login works with the new password", r.status_code == 302 and r.headers["Location"].endswith("/dashboard"))

print(f"\nResult: {ok_count} passed, {fail_count} failed")
sys.exit(1 if fail_count else 0)
