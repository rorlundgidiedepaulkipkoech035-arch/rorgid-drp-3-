"""Detection rules, the asyncio engine and the Celery pipeline (no network, browser, Redis or SMTP needed)."""
import asyncio
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tests_support  # noqa: E402

tests_support.install()
DB_FILE = os.path.join(tempfile.mkdtemp(), "engine.db")
os.environ.update(DRP_DB=DB_FILE, CELERY_ALWAYS_EAGER="true", REGISTRY_REFRESH_SECONDS="0", ALLOW_DB_RESET="true")
sys.modules["certstream"] = types.SimpleNamespace(listen_for_events=lambda *a, **k: None)   # the live feed is never opened

from src import db, pipeline, reporting  # noqa: E402
from src.detection import assess_domain, split_domain  # noqa: E402
from src.workers import scraper, tasks  # noqa: E402
import main  # noqa: E402

sent_reports = []


class FakeReporter:
    def dispatch_kecirt_report(self, **kw):
        sent_reports.append(kw)


async def fake_scrape(domain):
    if "boom" in domain:
        raise RuntimeError("playwright died")
    if "fail" in domain:
        return {"error": "timeout"}
    if "owned" in domain:
        return {"sha256": "cd" * 32, "serial_detected": os.environ["TEST_OWNED_SERIAL"], "screenshot": f"./a/{domain}.png"}
    return {"sha256": "ab" * 32, "serial_detected": "SN-12345" if "login" in domain else None, "screenshot": f"./a/{domain}.png"}


scraper.process_suspicious_domain = fake_scrape      # the pipeline looks the scraper up at call time
reporting.build_reporter = lambda: FakeReporter()

BRANDS, LEGIT = ["yourbrand"], ["yourbrand.com", "yourbrand.co.ke"]


class DetectionTests(unittest.TestCase):
    def flagged(self, d):
        return assess_domain(d, BRANDS, LEGIT) is not None

    def test_legit_not_flagged(self):
        for d in ["yourbrand.com", "www.yourbrand.com", "mail.yourbrand.co.ke", "*.yourbrand.com", "google.com", "example.org", "brandnew.com"]:
            self.assertFalse(self.flagged(d), d)

    def test_typosquats_flagged(self):
        for d in ["yourbrnad.com", "yourbrand.xyz", "yourbrand-login.com", "secure-yourbrand.net", "y0urbrand.com",
                  "yourbrannd.com", "yourbrand.com.evil.xyz", "login.yourbrand.evil.top"]:
            self.assertTrue(self.flagged(d), d)

    def test_cyrillic_homoglyph(self):
        self.assertTrue(self.flagged("yоurbrand.com"))

    def test_split_domain(self):
        self.assertEqual(split_domain("a.b.brand.co.ke")[1:], ("brand", "co.ke"))


def make_company(reg, brand, domain, approve=True):
    cid = db.create_company({"legal_name": f"Co {reg}", "registration_number": reg, "official_email": f"info@{domain}"},
                            [brand], [domain], f"admin@{domain}", "x")
    if approve:
        db.set_company_status(cid, "approved")
    return cid


def run_inline(domain, reason, company_id, auto):
    """What a Celery worker does with a queued job."""
    asyncio.run(pipeline.handle_threat(domain, reason, company_id, auto))


def cert(*names):
    return {"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": list(names)}}}


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        db.reset_all()
        cls.a = make_company("A-1", "yourbrand", "yourbrand.com")
        cls.b = make_company("B-1", "otherbrand", "otherbrand.com")
        cls.c = make_company("C-1", "pendingbrand", "pendingbrand.com", approve=False)
        main.registry.reload()

    def feed(self, *names, dispatch_fn=run_inline):
        main.registry.reload()
        asyncio.run(main.handle_message(cert(*names), dispatch_fn))

    def test_1_findings_are_tenant_scoped(self):
        self.feed("yourbrand-login.com", "www.yourbrand.com", "yourbrnad.net", "otherbrand-shop.com",
                  "pendingbrand-login.com", "yourbrand-login.com")
        self.assertEqual(sorted(f["domain"] for f in db.list_findings(self.a)), ["yourbrand-login.com", "yourbrnad.net"])
        self.assertEqual([f["domain"] for f in db.list_findings(self.b)], ["otherbrand-shop.com"])
        self.assertEqual(db.list_findings(self.c), [])               # an unverified company is not monitored
        self.assertEqual(sent_reports, [])                           # nothing is emailed without approval

    def test_2_scrape_errors_do_not_stop_the_engine(self):
        self.feed("yourbrand-fail.com", "yourbrand-boom.com", "yourbrand-ok.com")
        doms = [f["domain"] for f in db.list_findings(self.a)]
        self.assertIn("yourbrand-ok.com", doms)
        self.assertNotIn("yourbrand-fail.com", doms)
        self.assertNotIn("yourbrand-boom.com", doms)

    def test_3_flagged_domain_is_queued_once_and_dispatch_failures_are_retried(self):
        calls = []
        self.feed("yourbrand-queue.com", "yourbrand-queue.com", dispatch_fn=lambda *a: calls.append(a))
        self.assertEqual([c[0] for c in calls], ["yourbrand-queue.com"])           # duplicate sightings queue one job
        self.assertEqual(calls[0][2], self.a)

        def broken(*a):
            raise ConnectionError("redis is down")
        before = main.stats["dispatch_errors"]
        self.feed("yourbrand-retry.com", dispatch_fn=broken)
        self.assertEqual(main.stats["dispatch_errors"], before + 1)
        calls.clear()
        self.feed("yourbrand-retry.com", dispatch_fn=lambda *a: calls.append(a))   # forgotten, so a later sighting is queued again
        self.assertEqual(len(calls), 1)

    def test_4_default_dispatch_goes_through_celery(self):
        tasks.handle_threat_task.calls.clear() if hasattr(tasks.handle_threat_task, "calls") else None
        self.feed("yourbrand-celery.com", dispatch_fn=main.dispatch)               # real Celery (eager) or the fake
        self.assertTrue(db.finding_exists(self.a, "yourbrand-celery.com"))

    def test_5_report_is_sent_once_after_approval(self):
        f = [x for x in db.list_findings(self.a) if x["domain"] == "yourbrand-login.com"][0]
        self.assertFalse(db.set_finding_status(self.a, f["id"], "approved_for_report"))      # confirmation comes first
        self.assertTrue(db.set_finding_status(self.a, f["id"], "confirmed"))
        self.assertTrue(db.set_finding_status(self.a, f["id"], "approved_for_report"))
        sent_reports.clear()
        self.assertEqual(tasks.send_report_task(f["id"]), "sent")
        self.assertEqual(tasks.send_report_task(f["id"]), "skipped")                         # a second worker does nothing
        self.assertEqual(len(sent_reports), 1)
        self.assertEqual(sent_reports[0]["serial_number"], "SN-12345")
        self.assertEqual(db.get_finding(self.a, f["id"])["status"], "reported")

    def test_6_sweep_picks_up_lost_approvals_and_stuck_sends(self):
        fid = db.add_finding(self.a, "yourbrand-sweep.com", "r", "ab" * 32, None, "./a/s.png")
        db.set_finding_status(self.a, fid, "confirmed")
        db.set_finding_status(self.a, fid, "approved_for_report")                            # message to Redis was lost
        sent_reports.clear()
        result = tasks.sweep_reports_task()
        self.assertGreaterEqual(result["queued"], 1)
        self.assertEqual(db.get_finding(self.a, fid)["status"], "reported")
        self.assertEqual([r["target_domain"] for r in sent_reports], ["yourbrand-sweep.com"])
        fid2 = db.add_finding(self.a, "yourbrand-stuck.com", "r", "ab" * 32, None, "./a/t.png")
        db.set_finding_status(self.a, fid2, "confirmed")
        db.set_finding_status(self.a, fid2, "approved_for_report")
        self.assertTrue(db.claim_report(fid2))                                               # a worker died while sending
        self.assertEqual(db.requeue_stale_reports(minutes=-5), 1)
        self.assertEqual(db.get_finding(self.a, fid2)["status"], "approved_for_report")

    def test_7_registered_key_serial_is_recognised_and_other_companys_is_ignored(self):
        db.save_document(self.a, "trademark_photo", "logo.png", f"{self.a}/x.png", "image/png", 1, "ef" * 32, "RGD-2026-0000AAAA")
        db.save_document(self.b, "trademark_photo", "logo.png", f"{self.b}/y.png", "image/png", 1, "12" * 32, "RGD-2026-0000BBBB")
        os.environ["TEST_OWNED_SERIAL"] = "RGD-2026-0000AAAA"
        self.feed("yourbrand-owned.com")
        own = [x for x in db.list_findings(self.a) if x["domain"] == "yourbrand-owned.com"][0]
        self.assertIn("key serial matches this company's registered asset", own["reason"])
        self.assertEqual(own["serial"], "RGD-2026-0000AAAA")
        os.environ["TEST_OWNED_SERIAL"] = "RGD-2026-0000BBBB"                                # company B's serial on a site flagged for A
        self.feed("yourbrand-owned2.com")
        other = [x for x in db.list_findings(self.a) if x["domain"] == "yourbrand-owned2.com"][0]
        self.assertIsNone(other["serial"])

    def test_8_auto_report_needs_every_switch(self):
        sent_reports.clear()
        os.environ["TEST_OWNED_SERIAL"] = "RGD-2026-0000AAAA"
        pipeline.AUTO_REPORT = False
        asyncio.run(pipeline.handle_threat("yourbrand-owned3.com", "r", self.a, True))       # platform switch off
        self.assertEqual(sent_reports, [])
        pipeline.AUTO_REPORT = True
        try:
            asyncio.run(pipeline.handle_threat("yourbrand-owned4.com", "r", self.a, False))  # company switch off
            self.assertEqual(sent_reports, [])
            asyncio.run(pipeline.handle_threat("yourbrand-owned5.com", "r", self.a, True))   # both on + registered serial
            self.assertEqual([r["target_domain"] for r in sent_reports], ["yourbrand-owned5.com"])
        finally:
            pipeline.AUTO_REPORT = False


if __name__ == "__main__":
    unittest.main(verbosity=2)
