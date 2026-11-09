"""Dashboard tests with Flask's test client (registration, login, approval, tenant isolation, CSRF)."""
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tests_support  # noqa: E402

tests_support.install()
DB_FILE = os.path.join(tempfile.mkdtemp(), "dash.db")
os.environ.update(DRP_DB=DB_FILE, CELERY_ALWAYS_EAGER="true", ALLOW_DB_RESET="true", STEGO_KEY="dashboard-test-key")
os.environ["SECRET_KEY"] = "test-secret"
os.environ["UPLOAD_DIR"] = os.path.join(tempfile.mkdtemp(), "uploads")

from werkzeug.security import generate_password_hash  # noqa: E402
from dashboard.app import create_app, _failures  # noqa: E402
from src import db, mailer, reporting, security, stego  # noqa: E402
from src.workers import tasks  # noqa: E402

PW = "Strong-Pass-123!"


def token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, email, pw=PW):
    return client.post("/login", data={"email": email, "password": pw, "csrf_token": token(client)})


def reg_data(**over):
    d = dict(legal_name="Acme Ltd", registration_number="PVT-123", official_email="info@acme.co.ke",
             phone="0700", website="https://acme.co.ke", address="Nairobi", country="Kenya",
             brands="acme", domains="acme.co.ke", admin_email="boss@acme.co.ke", password=PW, password2=PW)
    d.update(over)
    return d


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["DRP_DB"] = DB_FILE
        cls.app = create_app()
        cls.app.testing = True
        db.reset_all()
        db.create_user(None, "root@platform.io", generate_password_hash(PW), "platform_admin")

    def setUp(self):
        _failures.clear()

    def client(self):
        return self.app.test_client()

    def register(self, **over):
        c = self.client()
        return c, c.post("/register", data={**reg_data(**over), "csrf_token": token(c, "/register")})

    def test_01_registration_validation(self):
        c, r = self.register(admin_email="boss@gmail.com")          # not on a company domain
        self.assertEqual(r.status_code, 400)
        self.assertIn("company domains", r.get_data(as_text=True))
        c, r = self.register(password="short", password2="short")
        self.assertEqual(r.status_code, 400)
        for weak in ("alllowercase1!", "ALLUPPERCASE1!", "NoSpecial123"):
            c, r = self.register(password=weak, password2=weak)
            self.assertEqual(r.status_code, 400, weak)
        c, r = self.register(brands="ab")
        self.assertEqual(r.status_code, 400)

    def test_02_register_login_pending_then_approved(self):
        c, r = self.register()
        self.assertEqual(r.status_code, 302)
        self.assertEqual(db.registry_snapshot(), [])                # pending: not monitored
        self.assertEqual(login(c, "boss@acme.co.ke").status_code, 302)
        page = c.get("/dashboard", follow_redirects=True).get_data(as_text=True)
        self.assertIn("Company verification", page)               # pending admin is sent to the verification page
        _, dup = self.register()                                    # duplicate registration number/email
        self.assertEqual(dup.status_code, 400)

        admin = self.client()
        login(admin, "root@platform.io")
        cid = db.get_user_by_email("boss@acme.co.ke")["company_id"]
        admin.post(f"/admin/companies/{cid}/approve", data={"csrf_token": token(admin, "/admin")})
        snap = db.registry_snapshot()
        self.assertEqual(snap[0]["brands"], ["acme"])
        self.assertEqual(snap[0]["domains"], ["acme.co.ke"])

    def test_03_changes_need_admin_approval(self):
        c = self.client()
        login(c, "boss@acme.co.ke")
        c.post("/company/brands/add", data={"brand": "acmepay", "csrf_token": token(c, "/company")})
        self.assertEqual(db.registry_snapshot()[0]["brands"], ["acme"])      # not active yet
        cid = db.get_user_by_email("boss@acme.co.ke")["company_id"]
        admin = self.client()
        login(admin, "root@platform.io")
        admin.post(f"/admin/companies/{cid}/approve-changes", data={"csrf_token": token(admin, "/admin")})
        self.assertEqual(sorted(db.registry_snapshot()[0]["brands"]), ["acme", "acmepay"])

    def test_04_isolation_roles_and_csrf(self):
        a_cid = db.get_user_by_email("boss@acme.co.ke")["company_id"]
        _, r = self.register(legal_name="Beta Ltd", registration_number="PVT-999", official_email="i@beta.com",
                             brands="betabrand", domains="beta.com", admin_email="x@beta.com")
        b_cid = db.get_user_by_email("x@beta.com")["company_id"]
        fid = db.add_finding(a_cid, "acme-login.com", "typosquat", "ab" * 32, None, "x.png")

        b = self.client()
        login(b, "x@beta.com")
        self.assertEqual(b.get(f"/findings/{fid}").status_code, 404)          # other tenant's finding
        self.assertEqual(b.post(f"/findings/{fid}/confirm", data={"csrf_token": token(b, "/verification")}).status_code, 404)
        self.assertNotIn("acme-login.com", b.get("/findings").get_data(as_text=True))
        self.assertEqual(b.get("/admin").status_code, 403)

        a = self.client()
        login(a, "boss@acme.co.ke")
        self.assertEqual(a.post(f"/findings/{fid}/confirm", data={}).status_code, 400)  # no CSRF token
        t = token(a, "/dashboard")
        a.post(f"/findings/{fid}/confirm", data={"csrf_token": t})
        self.assertEqual(db.get_finding(a_cid, fid)["status"], "confirmed")

        # analyst can review but cannot authorise a takedown report
        db.create_user(a_cid, "analyst@acme.co.ke", generate_password_hash(PW), "analyst")
        an = self.client()
        login(an, "analyst@acme.co.ke")
        self.assertEqual(an.post(f"/findings/{fid}/report", data={"csrf_token": token(an, "/dashboard")}).status_code, 403)
        self.assertEqual(an.get("/company").status_code, 403)
        sent = []

        class _Reporter:
            def dispatch_kecirt_report(self, **kw):
                sent.append(kw)
        real_reporter = reporting.build_reporter
        reporting.build_reporter = lambda: _Reporter()
        try:
            a.post(f"/findings/{fid}/report", data={"csrf_token": token(a, "/dashboard")})
        finally:
            reporting.build_reporter = real_reporter
        self.assertEqual(db.get_finding(a_cid, fid)["status"], "reported")        # the Celery task (eager here) sent it
        self.assertEqual([r["target_domain"] for r in sent], ["acme-login.com"])
        # if the queue is unreachable the approval is kept and the beat sweep sends it later
        fid2 = db.add_finding(a_cid, "acme-second.com", "r", "cd" * 32, None, "s.png")
        db.set_finding_status(a_cid, fid2, "confirmed")

        class _Down:
            def delay(self, *a, **k):
                raise ConnectionError("redis is down")
        real_task = tasks.send_report_task
        tasks.send_report_task = _Down()
        try:
            a.post(f"/findings/{fid2}/report", data={"csrf_token": token(a, "/dashboard")})
        finally:
            tasks.send_report_task = real_task
        self.assertEqual(db.get_finding(a_cid, fid2)["status"], "approved_for_report")

    def test_05_login_throttle_and_logout(self):
        c = self.client()
        for _ in range(5):
            self.assertEqual(login(c, "boss@acme.co.ke", "wrong-password-x").status_code, 401)
        self.assertEqual(login(c, "boss@acme.co.ke").status_code, 429)
        _failures.clear()
        login(c, "boss@acme.co.ke")
        c.post("/logout", data={"csrf_token": token(c, "/dashboard")})
        self.assertEqual(c.get("/dashboard").status_code, 302)

    def test_07_session_is_permanent_and_password_change(self):
        _failures.clear()
        c = self.client()
        login(c, "analyst@acme.co.ke")
        with c.session_transaction() as sess:
            self.assertTrue(sess.permanent)                      # rolling idle-timeout session
        self.assertIn("Session active", c.get("/dashboard").get_data(as_text=True))
        t = token(c, "/account/password")
        bad = c.post("/account/password", data={"current": "nope-nope-nope", "new": "Another-Long-Pass-1!", "new2": "Another-Long-Pass-1!", "csrf_token": t})
        self.assertEqual(bad.status_code, 400)
        ok = c.post("/account/password", data={"current": PW, "new": "Another-Long-Pass-1!", "new2": "Another-Long-Pass-1!", "csrf_token": t})
        self.assertEqual(ok.status_code, 302)
        c2 = self.client()
        self.assertEqual(login(c2, "analyst@acme.co.ke", PW).status_code, 401)           # old password no longer works
        self.assertEqual(login(c2, "analyst@acme.co.ke", "Another-Long-Pass-1!").status_code, 302)

    def test_06_unauthenticated_redirects(self):
        c = self.client()
        for p in ("/dashboard", "/company", "/admin"):
            self.assertEqual(c.get(p).status_code, 302)



# ------------------------------------------------------------------ verification documents + password reset
import hashlib  # noqa: E402
import io  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"fake-png-body-"
PDF = b"%PDF-1.4\n% fake pdf "


def upload(client, doc_type, data, name="file.pdf", token_path="/verification"):
    return client.post(f"/verification/upload/{doc_type}", content_type="multipart/form-data", follow_redirects=True,
                       data={"csrf_token": token(client, token_path), "file": (io.BytesIO(data), name)})


class VerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["DRP_DB"] = DB_FILE
        cls.app = create_app()
        cls.app.testing = True

    def setUp(self):
        _failures.clear()

    def reg(self, n, brand, domain, kra="P051234567A"):
        c = self.app.test_client()
        c.post("/register", data={**reg_data(legal_name=f"{n} Ltd", registration_number=f"REG-{n}",
                                             official_email=f"i@{domain}", brands=brand, domains=domain,
                                             admin_email=f"boss@{domain}"), "csrf_token": token(c, "/register")})
        login(c, f"boss@{domain}")
        return c, db.get_user_by_email(f"boss@{domain}")["company_id"]

    def test_01_full_verification_records_serial_and_hash(self):
        c, cid = self.reg("Zeta", "zetabrand", "zeta.co.ke")
        self.assertEqual(db.get_company(cid)["status"], "pending")
        bad = c.post("/verification/details", data={"kra_pin": "A123", "csrf_token": token(c, "/verification")}, follow_redirects=True)
        self.assertIn("valid company KRA PIN", bad.get_data(as_text=True))
        # wrong types are rejected: an executable renamed .pdf, and a PDF as the trademark photo
        self.assertIn("Unsupported file", upload(c, "kra_pin_cert", b"MZ\x90\x00 evil", "kra.pdf").get_data(as_text=True))
        self.assertIn("Unsupported file", upload(c, "trademark_photo", PDF + b"zeta", "logo.pdf").get_data(as_text=True))
        docs = {"kra_pin_cert": PDF + b"zeta-kra", "registration_cert": PDF + b"zeta-cr", "trademark_cert": PDF + b"zeta-tm",
                "trademark_photo": PNG + b"zeta-logo"}
        for t, data in list(docs.items())[:3]:
            upload(c, t, data)
        self.assertEqual(db.get_company(cid)["status"], "pending")               # still incomplete
        c.post("/verification/details", data={"kra_pin": "p051234567z", "trademark_number": "TM-9", "csrf_token": token(c, "/verification")})
        self.assertEqual(db.get_company(cid)["status"], "pending")               # photo missing
        page = upload(c, "trademark_photo", docs["trademark_photo"], "logo.png").get_data(as_text=True)
        self.assertEqual(db.get_company(cid)["status"], "approved")              # verified automatically
        self.assertIn("now verified", page)
        for d in db.documents(cid):                                              # serial + hash recorded for every file
            self.assertRegex(d["serial"], r"^RGD-\d{4}-[0-9A-F]{8}$")
            self.assertEqual(d["sha256"], hashlib.sha256(docs[d["doc_type"]]).hexdigest())
        self.assertEqual(db.registry_snapshot()[-1]["brands"], ["zetabrand"])    # monitoring started
        self.assertIn("locked", upload(c, "kra_pin_cert", PDF + b"other").get_data(as_text=True))

    def test_02_duplicates_and_permissions(self):
        c1, cid1 = self.reg("Eta", "etabrand", "eta.co.ke", )
        upload(c1, "trademark_cert", PDF + b"shared-file")
        c2, cid2 = self.reg("Theta", "thetabrand", "theta.co.ke")
        self.assertIn("already registered", upload(c2, "trademark_cert", PDF + b"shared-file").get_data(as_text=True))
        # KRA PIN can't be claimed twice
        c1.post("/verification/details", data={"kra_pin": "P099999999K", "csrf_token": token(c1, "/verification")})
        r = c2.post("/verification/details", data={"kra_pin": "P099999999K", "csrf_token": token(c2, "/verification")}, follow_redirects=True)
        self.assertIn("already registered to another company", r.get_data(as_text=True))
        # documents are private to their company (and the platform admin)
        doc = db.documents(cid1)[0]
        self.assertEqual(c2.get(f"/documents/{doc['id']}").status_code, 404)
        self.assertEqual(c1.get(f"/documents/{doc['id']}").status_code, 200)
        admin = self.app.test_client()
        login(admin, "root@platform.io")
        self.assertEqual(admin.get(f"/documents/{doc['id']}").status_code, 200)
        # analysts can look but not upload
        db.create_user(cid1, "an@eta.co.ke", generate_password_hash(PW), "analyst")
        an = self.app.test_client()
        login(an, "an@eta.co.ke")
        self.assertEqual(an.post("/verification/upload/kra_pin_cert", data={"csrf_token": token(an, "/verification")}).status_code, 403)

    def test_03_forgot_password_code_flow(self):
        sent = []
        real = mailer.send_mail
        mailer.send_mail = lambda to, subject, body: sent.append((to, body)) or True
        try:
            db.create_user(None, "reset-me@platform.io", generate_password_hash(PW), "platform_admin")
            c = self.app.test_client()

            def ask(email):
                return c.post("/forgot-password", data={"email": email, "csrf_token": token(c, "/forgot-password")}, follow_redirects=True)
            r_unknown = ask("nobody@nowhere.io")
            self.assertEqual(sent, [])                                            # unknown email: nothing sent...
            self.assertIn("If that email has an account", r_unknown.get_data(as_text=True))   # ...same message shown
            ask("reset-me@platform.io")
            to, body = sent[-1]
            self.assertEqual(to, "reset-me@platform.io")
            code = re.search(r"code is (\d{6})", body).group(1)

            def reset(code_, pw):
                return c.post("/reset-password", data={"email": "reset-me@platform.io", "code": code_, "new": pw, "new2": pw,
                                                       "csrf_token": token(c, "/reset-password")})
            self.assertEqual(reset("000000" if code != "000000" else "111111", "Fresh-Pass-99!").status_code, 400)
            self.assertEqual(reset(code, "weakpass").status_code, 400)            # right code, weak password: not consumed
            self.assertEqual(reset(code, "Fresh-Pass-99!").status_code, 302)      # success
            self.assertEqual(reset(code, "Other-Pass-99!").status_code, 400)      # code can't be reused
            c2 = self.app.test_client()
            self.assertEqual(login(c2, "reset-me@platform.io", PW).status_code, 401)
            self.assertEqual(login(c2, "reset-me@platform.io", "Fresh-Pass-99!").status_code, 302)
            for _ in range(2):                                                    # request limit: 3 codes per hour
                ask("reset-me@platform.io")
            n = len(sent)
            ask("reset-me@platform.io")
            self.assertEqual(len(sent), n)
            # five wrong guesses burn the code
            code2 = re.search(r"code is (\d{6})", sent[-1][1]).group(1)
            wrong = "123456" if code2 != "123456" else "654321"
            for _ in range(5):
                reset(wrong, "Fresh-Pass-99!")
            self.assertEqual(reset(code2, "Fresh-Pass-99!").status_code, 400)
        finally:
            mailer.send_mail = real


import cv2  # noqa: E402
import numpy as np  # noqa: E402


def image(seed=1, w=240, h=180, ext=".png"):
    return cv2.imencode(ext, np.random.default_rng(seed).integers(0, 256, (h, w, 3), dtype=np.uint8))[1].tobytes()


class AssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["DRP_DB"] = DB_FILE
        cls.app = create_app()
        cls.app.testing = True
        db.reset_all()
        h = generate_password_hash(PW)
        mk = lambda reg, brand, dom, status: db.create_company({"legal_name": f"{reg} Ltd", "registration_number": reg, "official_email": f"i@{dom}"}, [brand], [dom], f"boss@{dom}", h)
        cls.a, cls.b, cls.p = mk("AS-A", "assetabrand", "asseta.com", 0), mk("AS-B", "assetbbrand", "assetb.com", 0), mk("AS-P", "assetpbrand", "assetp.com", 0)
        db.set_company_status(cls.a, "approved")
        db.set_company_status(cls.b, "approved")                                  # AS-P stays pending
        db.create_user(cls.a, "analyst@asseta.com", h, "analyst")

    def setUp(self):
        _failures.clear()

    def session_for(self, email):
        c = self.app.test_client()
        login(c, email)
        return c

    def upload(self, c, data, name="logo.png", path="/assets/upload"):
        return c.post(path, content_type="multipart/form-data", follow_redirects=True,
                      data={"csrf_token": token(c, "/assets"), "file": (io.BytesIO(data), name)})

    def test_01_protect_download_and_extract(self):
        c = self.session_for("boss@asseta.com")
        page = self.upload(c, image(1)).get_data(as_text=True)
        self.assertIn("Protected. Serial RGD-", page)
        [asset] = db.list_assets(self.a)
        self.assertRegex(asset["serial"], r"^RGD-\d{4}-[0-9A-F]{8}$")
        dl = c.get(f"/assets/{asset['id']}/download")
        self.assertEqual((dl.status_code, dl.mimetype), (200, "image/png"))
        self.assertEqual(stego.extract_serial(dl.data), asset["serial"])          # the hidden mark is really in the file
        self.assertEqual(security.sha256_hex(dl.data), asset["watermarked_sha256"])
        self.assertEqual(db.serial_owner(asset["serial"]), self.a)
        an = self.session_for("analyst@asseta.com")                                # analysts download but cannot protect
        self.assertEqual(an.get(f"/assets/{asset['id']}/download").status_code, 200)
        self.assertEqual(an.post("/assets/upload", data={"csrf_token": token(an, "/assets")}).status_code, 403)

    def test_02_other_company_cannot_download(self):
        [asset] = db.list_assets(self.a)
        self.assertEqual(self.session_for("boss@assetb.com").get(f"/assets/{asset['id']}/download").status_code, 404)

    def test_03_check_an_image(self):
        c = self.session_for("boss@asseta.com")
        [asset] = db.list_assets(self.a)
        marked = c.get(f"/assets/{asset['id']}/download").data
        self.assertIn("carries your hidden serial " + asset["serial"], self.upload(c, marked, path="/assets/check").get_data(as_text=True))
        resaved = cv2.imencode(".png", cv2.imdecode(np.frombuffer(marked, np.uint8), 1), [cv2.IMWRITE_PNG_COMPRESSION, 9])[1].tobytes()
        self.assertIn("carries your hidden serial", self.upload(c, resaved, path="/assets/check").get_data(as_text=True))
        lossy = cv2.imencode(".jpg", cv2.imdecode(np.frombuffer(marked, np.uint8), 1), [cv2.IMWRITE_JPEG_QUALITY, 90])[1].tobytes()
        self.assertIn("No hidden RORGID serial", self.upload(c, lossy, "x.jpg", "/assets/check").get_data(as_text=True))
        self.assertIn("No hidden RORGID serial", self.upload(c, image(7), path="/assets/check").get_data(as_text=True))
        b = self.session_for("boss@assetb.com")                                    # company B learns nothing about A's serial
        page = self.upload(b, marked, path="/assets/check").get_data(as_text=True)
        self.assertIn("does not belong to your company", page)
        self.assertNotIn(asset["serial"], page)

    def test_04_bad_files_and_unverified_company(self):
        c = self.session_for("boss@asseta.com")
        self.assertIn("Only PNG and JPG", self.upload(c, b"%PDF-1.4 not an image", "x.pdf").get_data(as_text=True))
        self.assertIn("too small", self.upload(c, image(2, 5, 5)).get_data(as_text=True))
        before = db.list_assets(self.a)
        again = c.get(f"/assets/{before[0]['id']}/download").data                   # protecting a protected image gives it a NEW serial
        self.upload(c, again)
        after = db.list_assets(self.a)
        self.assertEqual(len(after), len(before) + 1)
        newest = after[0]
        self.assertNotIn(newest["serial"], [x["serial"] for x in before])
        self.assertEqual(stego.extract_serial(c.get(f"/assets/{newest['id']}/download").data), newest["serial"])
        p = self.session_for("boss@assetp.com")
        self.assertIn("available once your company is verified", self.upload(p, image(3)).get_data(as_text=True))
        self.assertEqual(db.list_assets(self.p), [])


class PasswordPolicyTests(unittest.TestCase):
    def test_policy(self):
        ok = ["Good-pass1", "Abcdef1!", "Zz#zzzzz"]
        bad = ["short1!A", "alllowercase1!", "ALLUPPERCASE1!", "NoSpecial123", "Ab1!", "a" * 5]
        self.assertTrue(all(security.password_problem(p) is None for p in ok if len(p) >= 8))
        self.assertTrue(all(security.password_problem(p) for p in bad[1:]))
        self.assertIsNotNone(security.password_problem("Sh0rt!"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
