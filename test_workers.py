"""Scraper helpers, hidden-mark detection and the KE-CIRT reporter (no browser or real email needed)."""
import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tests_support  # noqa: E402

tests_support.install()
os.environ.update(DRP_DB=os.path.join(tempfile.mkdtemp(), "w.db"), STEGO_KEY="workers-test-key", ALLOW_DB_RESET="true")

import hashlib  # noqa: E402
import smtplib  # noqa: E402

import cv2  # noqa: E402
import numpy as np  # noqa: E402
from src import db, stego  # noqa: E402
from src.remediation import reporting_bot  # noqa: E402
from src.workers import scraper as tasks  # noqa: E402


class ScraperHelperTests(unittest.TestCase):
    def test_public_vs_private_addresses(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.20", "172.16.3.4", "169.254.169.254", "::1", "0.0.0.0"):
            self.assertFalse(tasks.is_public_ip(ip), ip)
        for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertTrue(tasks.is_public_ip(ip), ip)

    def test_resolve_refuses_internal_hosts(self):
        fake = lambda ip: (lambda *a, **k: [(2, 1, 6, "", (ip, 443))])
        self.assertEqual(tasks.resolve_public("ok.example", resolver=fake("93.184.216.34")), "93.184.216.34")
        for bad in ("127.0.0.1", "10.1.2.3", "169.254.169.254"):
            with self.assertRaises(ValueError):
                tasks.resolve_public("evil.example", resolver=fake(bad))
        mixed = lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("10.0.0.9", 443))]
        with self.assertRaises(ValueError):                       # one internal address is enough to refuse
            tasks.resolve_public("sneaky.example", resolver=mixed)

    def test_find_serials(self):
        html = "<p>RGD-2026-9F3A1C7E and rgd-2026-9f3a1c7e and RGD-26-1 and RGD-2026-ABCDEF12</p>"
        self.assertEqual(tasks.find_serials(html), ["RGD-2026-9F3A1C7E", "RGD-2026-ABCDEF12"])

    def test_process_rejects_bad_and_internal_domains(self):
        self.assertEqual(asyncio.run(tasks.process_suspicious_domain("not a domain"))["error"], "invalid domain")
        real = tasks.resolve_public
        tasks.resolve_public = lambda d: (_ for _ in ()).throw(ValueError("refused: resolves to a non-public address (10.0.0.1)"))
        try:
            self.assertIn("non-public", asyncio.run(tasks.process_suspicious_domain("internal.example.com"))["error"])
        finally:
            tasks.resolve_public = real

    def test_registered_photo_hash_lookup(self):
        db.init_db()
        cid = db.create_company({"legal_name": "W", "registration_number": "W-1", "official_email": "a@w.com"},
                                ["wbrand"], ["w.com"], "a@w.com", "x")
        db.save_document(cid, "trademark_photo", "logo.png", f"{cid}/h.png", "image/png", 1, "ab" * 32, "RGD-2026-11112222")
        db.save_document(cid, "kra_pin_cert", "kra.pdf", f"{cid}/k.pdf", "application/pdf", 1, "cd" * 32, "RGD-2026-33334444")
        self.assertEqual(db.serial_by_hash("ab" * 32), "RGD-2026-11112222")
        self.assertIsNone(db.serial_by_hash("cd" * 32))               # only trademark photos count as logo copies
        self.assertIsNone(db.serial_by_hash("ef" * 32))


def png(seed=1, w=240, h=180):
    return cv2.imencode(".png", np.random.default_rng(seed).integers(0, 256, (h, w, 3), dtype=np.uint8))[1].tobytes()


class HiddenMarkDetectionTests(unittest.TestCase):
    """What the scraper does with the images and text it collected from a suspicious page."""

    @classmethod
    def setUpClass(cls):
        db.init_db()
        db.reset_all()
        cls.cid = db.create_company({"legal_name": "M", "registration_number": "M-1", "official_email": "a@m.com"}, ["mbrand"], ["m.com"], "a@m.com", "x")
        cls.other = db.create_company({"legal_name": "N", "registration_number": "N-1", "official_email": "a@n.com"}, ["nbrand"], ["n.com"], "a@n.com", "x")
        from src import assets
        os.environ["UPLOAD_DIR"] = os.path.join(tempfile.mkdtemp(), "up")
        res = assets.protect_asset(cls.cid, "logo.png", png(1))
        cls.serial = res["serial"]
        cls.protected = open(os.path.join(os.environ["UPLOAD_DIR"], db.get_asset(cls.cid, res["id"])["stored_name"]), "rb").read()

    def run_detect(self, images, html=""):
        return asyncio.run(tasks.detect_registered_serial(images, html))

    def test_exact_copy_of_a_protected_asset(self):
        self.assertEqual(self.run_detect([png(9), self.protected]), (self.serial, "exact-copy"))

    def test_hidden_mark_survives_a_lossless_resave(self):
        resaved = cv2.imencode(".png", cv2.imdecode(np.frombuffer(self.protected, np.uint8), cv2.IMREAD_UNCHANGED), [cv2.IMWRITE_PNG_COMPRESSION, 9])[1].tobytes()
        self.assertNotEqual(hashlib.sha256(resaved).hexdigest(), hashlib.sha256(self.protected).hexdigest())   # not an exact copy
        self.assertEqual(self.run_detect([resaved]), (self.serial, "hidden-mark"))

    def test_lossy_copy_and_unrelated_images_find_nothing(self):
        lossy = cv2.imencode(".jpg", cv2.imdecode(np.frombuffer(self.protected, np.uint8), 1), [cv2.IMWRITE_JPEG_QUALITY, 90])[1].tobytes()
        self.assertEqual(self.run_detect([lossy, png(5), b"not an image"]), (None, None))

    def test_a_planted_unregistered_serial_proves_nothing(self):
        fake = stego.embed_serial(png(3), "RGD-2026-DEADBEEF")                     # a genuine-looking mark nobody registered
        self.assertEqual(self.run_detect([fake], "<p>RGD-2026-DEADBEEF</p>"), (None, None))

    def test_registered_serial_printed_in_the_page(self):
        self.assertEqual(self.run_detect([], f"<footer>ref {self.serial}</footer>"), (self.serial, "printed-text"))


class ReporterTests(unittest.TestCase):
    def test_report_email_contents_and_attachment(self):
        sent = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=0): sent["conn"] = (host, port)
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self, context=None): sent["tls"] = True
            def login(self, u, p): sent["login"] = u
            def send_message(self, m): sent["msg"] = m
        real = smtplib.SMTP
        smtplib.SMTP = FakeSMTP
        shot = os.path.join(tempfile.mkdtemp(), "evil_com.png")
        open(shot, "wb").write(b"\x89PNG\r\n\x1a\nfake")
        open(shot[:-4] + ".html", "w").write("<html>evidence</html>")
        try:
            r = reporting_bot.ThreatReporter("smtp.example", 587, "sec@brand.co.ke", "pw", recipient="cert@example.go.ke")
            r.dispatch_kecirt_report("evil.com", "ab" * 32, "RGD-2026-11112222", shot)
        finally:
            smtplib.SMTP = real
        m = sent["msg"]
        self.assertEqual((m["To"], m["From"]), ("cert@example.go.ke", "sec@brand.co.ke"))
        self.assertIn("evil.com", m["Subject"])
        body = m.get_body().get_content()
        self.assertIn("ab" * 32, body)
        self.assertIn("RGD-2026-11112222", body)
        self.assertEqual([p.get_filename() for p in m.iter_attachments()], ["evil_com.png", "evil_com.html"])   # screenshot + raw HTML
        self.assertTrue(sent["tls"] and sent["login"] == "sec@brand.co.ke")

    def test_refuses_without_recipient(self):
        os.environ.pop("KECIRT_REPORT_TO", None)
        with self.assertRaises(RuntimeError):
            reporting_bot.ThreatReporter("s", 587, "a@b.c", "p").dispatch_kecirt_report("x.com", "h", None, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
