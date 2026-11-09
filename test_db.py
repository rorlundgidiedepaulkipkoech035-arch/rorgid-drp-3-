"""Database contract tests. They run against src/db.py (SQLAlchemy) when SQLAlchemy is installed, otherwise
against the reference sqlite3 layer, so both layers are held to the same behaviour."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tests_support  # noqa: E402

USING = tests_support.install()
os.environ.setdefault("DRP_DB", os.path.join(tempfile.mkdtemp(), "contract.db"))
from src import db  # noqa: E402


def company(reg, brand, domain, status=None):
    cid = db.create_company({"legal_name": f"Co {reg}", "registration_number": reg, "official_email": f"i@{domain}"},
                            [brand], [domain], f"a@{domain}", "hash")
    if status:
        db.set_company_status(cid, status)
    return cid


class DbContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        db.reset_all()
        print("database layer under test:", USING["db"], file=sys.stderr)

    def test_01_company_user_and_uniqueness(self):
        cid = company("R1", "alphabrand", "alpha.com")
        self.assertEqual(db.get_company(cid)["status"], "pending")
        self.assertEqual(db.get_company(cid)["legal_name"], "Co R1")           # item access
        self.assertEqual(db.get_company(cid).legal_name, "Co R1")              # attribute access (templates)
        with self.assertRaises(ValueError):
            company("R1", "other", "other.com")                                # same registration number
        with self.assertRaises(ValueError):
            db.create_company({"legal_name": "X", "registration_number": "R9", "official_email": "x@x.com"}, ["xbrand"], ["x.com"], "a@alpha.com", "h")
        u = db.get_user_by_email("a@alpha.com")
        self.assertEqual((u["role"], u["company_id"]), ("company_admin", cid))
        self.assertIsNone(db.get_user_by_email("nobody@x.com"))
        users = db.company_users(cid)
        self.assertEqual(users[0]["email"], "a@alpha.com")
        self.assertNotIn("password_hash", users[0])                            # the hash never leaves the layer
        db.update_password(u["id"], "newhash")
        self.assertEqual(db.get_user(u["id"])["password_hash"], "newhash")
        with self.assertRaises(ValueError):
            db.create_user(cid, "a@alpha.com", "h", "analyst")

    def test_02_status_registry_and_pending_items(self):
        cid = company("R2", "betabrand", "beta.com")
        self.assertNotIn(cid, [t["company_id"] for t in db.registry_snapshot()])          # pending: not monitored
        db.set_company_status(cid, "approved")
        snap = {t["company_id"]: t for t in db.registry_snapshot()}[cid]
        self.assertEqual((snap["brands"], snap["domains"], snap["auto_report"]), (["betabrand"], ["beta.com"], False))
        db.add_brand(cid, "betapay")
        db.add_brand(cid, "betapay")                                                       # duplicate is ignored
        db.add_domain(cid, "betapay.com")
        self.assertEqual({t["company_id"]: t for t in db.registry_snapshot()}[cid]["brands"], ["betabrand"])
        self.assertEqual(db.approve_pending_items(cid), 2)
        self.assertEqual(sorted({t["company_id"]: t for t in db.registry_snapshot()}[cid]["brands"]), ["betabrand", "betapay"])
        item = [b for b in db.brands(cid) if b["brand"] == "betapay"][0]
        db.remove_brand(cid + 999, item["id"])                                             # other company: no effect
        self.assertEqual(len(db.brands(cid)), 2)
        db.remove_brand(cid, item["id"])
        self.assertEqual(len(db.brands(cid)), 1)
        listed = [c for c in db.list_companies() if c["id"] == cid][0]
        self.assertEqual((listed["pending_brands"], listed["pending_domains"], listed["findings"]), (0, 0, 0))
        other = company("R2b", "betabrand", "betaclone.com")
        self.assertEqual([c["legal_name"] for c in db.brand_conflicts(cid)], ["Co R2b"])
        self.assertEqual(other, db.get_user_by_email("a@betaclone.com")["company_id"])

    def test_03_findings_lifecycle(self):
        cid, other = company("R3", "gammabrand", "gamma.com", "approved"), company("R3b", "deltabrand", "delta.com", "approved")
        fid = db.add_finding(cid, "gammabrand-login.com", "embedded", "ab" * 32, None, "a.png")
        self.assertIsNotNone(fid)
        self.assertIsNone(db.add_finding(cid, "gammabrand-login.com", "again", "cd" * 32, None, "b.png"))    # unique per company
        self.assertIsNotNone(db.add_finding(other, "gammabrand-login.com", "other company", "ab" * 32, None, "c.png"))
        self.assertTrue(db.finding_exists(cid, "gammabrand-login.com"))
        self.assertFalse(db.finding_exists(cid, "nothing.com"))
        self.assertIsNone(db.get_finding(other, fid))                                       # tenant scoping
        self.assertEqual(db.get_finding_any(fid)["domain"], "gammabrand-login.com")
        self.assertFalse(db.set_finding_status(cid, fid, "approved_for_report"))            # must be confirmed first
        self.assertFalse(db.set_finding_status(other, fid, "confirmed"))
        self.assertTrue(db.set_finding_status(cid, fid, "confirmed"))
        self.assertTrue(db.set_finding_status(cid, fid, "approved_for_report"))
        self.assertEqual([f["id"] for f in db.fetch_approved_findings() if f["company_id"] == cid], [fid])
        self.assertTrue(db.claim_report(fid))                                               # exactly one claimant wins
        self.assertFalse(db.claim_report(fid))
        self.assertEqual(db.get_finding(cid, fid)["status"], "sending")
        self.assertEqual(db.requeue_stale_reports(minutes=-5), 1)                           # a stuck send goes back to the queue
        self.assertEqual(db.get_finding(cid, fid)["status"], "approved_for_report")
        db.mark_reported(fid, False)
        self.assertEqual(db.get_finding(cid, fid)["status"], "report_failed")
        self.assertTrue(db.set_finding_status(cid, fid, "approved_for_report"))             # retry after a failure
        db.mark_reported(fid, True)
        self.assertEqual(db.finding_counts(cid), {"reported": 1})

    def test_04_search_counts_and_daily_chart(self):
        cid = company("R4", "epsilonbrand", "epsilon.com", "approved")
        ids = [db.add_finding(cid, d, r, "e" * 64, None, "s.png") for d, r in
               (("epsilonbrand-login.com", "brand embedded"), ("epsilonbrnad.com", "typosquat"), ("unrelated.org", "other"))]
        self.assertEqual({f["domain"] for f in db.list_findings(cid, search="LOGIN")}, {"epsilonbrand-login.com"})   # case-insensitive
        self.assertEqual({f["domain"] for f in db.list_findings(cid, search="typosquat")}, {"epsilonbrnad.com"})     # matches reason too
        self.assertEqual(len(db.list_findings(cid, limit=2)), 2)
        db.set_finding_status(cid, ids[0], "dismissed")
        self.assertEqual([f["id"] for f in db.list_findings(cid, status="dismissed")], [ids[0]])
        db.backdate_finding(ids[1], 3)
        daily = db.daily_counts(cid)
        self.assertEqual(len(daily), 14)
        self.assertEqual(sum(n for _, n in daily), 3)
        self.assertEqual(daily[-1][1], 2)                                                   # two detected today
        self.assertEqual(daily[-4][1], 1)                                                   # one three days ago
        self.assertEqual(db.finding_counts(cid), {"pending_review": 2, "dismissed": 1})

    def test_05_documents_serials_assets_and_verification(self):
        cid, other = company("R5", "zetabrand", "zeta.com"), company("R5b", "etabrand", "etab.com")
        self.assertFalse(db.try_auto_verify(cid))                                           # nothing yet
        db.save_kra(cid, "P011111111A", "TM-1")
        with self.assertRaises(ValueError):
            db.save_kra(other, "P011111111A", None)                                         # PIN used by another company
        for i, t in enumerate(db.REQUIRED):
            _, old = db.save_document(cid, t, f"{t}.pdf", f"{cid}/{i}.pdf", "application/pdf", 10, f"{i}" * 64, f"RGD-2026-0000000{i}")
            self.assertEqual(old, [])
        with self.assertRaises(ValueError):
            db.save_document(other, "kra_pin_cert", "x.pdf", "x", "application/pdf", 1, "0" * 64, "RGD-2026-FFFFFFFF")   # same hash
        _, old = db.save_document(cid, "kra_pin_cert", "new.pdf", f"{cid}/new.pdf", "application/pdf", 10, "9" * 64, "RGD-2026-0000000A")
        self.assertEqual(old, [f"{cid}/0.pdf"])                                              # replaced file reported for deletion
        self.assertEqual(len(db.documents(cid)), 4)
        self.assertEqual(db.serial_owner("RGD-2026-0000000A"), cid)
        self.assertIsNone(db.serial_owner("RGD-2026-NOPE0000"))
        self.assertEqual(db.serial_by_hash("3" * 64), "RGD-2026-00000003")                  # trademark_photo only
        self.assertIsNone(db.serial_by_hash("1" * 64))
        self.assertTrue(db.try_auto_verify(cid))
        self.assertEqual(db.get_company(cid)["status"], "approved")
        self.assertIsNotNone(db.get_company(cid)["verified_at"])
        self.assertFalse(db.try_auto_verify(cid))                                            # only once
        aid = db.add_asset(cid, "logo.png", f"{cid}/assets/x.png", "RGD-2026-AAAA0001", "1" * 64, "a" * 64, 99)
        with self.assertRaises(ValueError):
            db.add_asset(other, "dup.png", "y", "RGD-2026-AAAA0002", "2" * 64, "a" * 64, 1)  # same protected file
        self.assertEqual(db.get_asset(cid, aid)["serial"], "RGD-2026-AAAA0001")
        self.assertIsNone(db.get_asset(other, aid))
        self.assertEqual([a["id"] for a in db.list_assets(cid)], [aid])
        self.assertEqual(db.serial_owner("RGD-2026-AAAA0001"), cid)
        self.assertEqual(db.serial_by_hash("a" * 64), "RGD-2026-AAAA0001")                   # exact copy of a protected asset
        self.assertEqual(db.get_document(db.documents(cid)[0]["id"])["company_id"], cid)

    def test_06_password_reset_codes(self):
        cid = company("R6", "thetabrand", "theta.com")
        uid = db.get_user_by_email("a@theta.com")["id"]
        self.assertIsNone(db.active_reset(uid))
        db.create_reset(uid, "code1")
        db.create_reset(uid, "code2")                                                        # the newer code replaces the older
        r = db.active_reset(uid)
        self.assertEqual(r["code_hash"], "code2")
        self.assertEqual(db.recent_reset_count(uid), 2)
        for _ in range(5):
            db.bump_reset_attempts(r["id"])
        self.assertIsNone(db.active_reset(uid))                                              # five wrong guesses cancel it
        db.create_reset(uid, "code3")
        db.use_reset(db.active_reset(uid)["id"])
        self.assertIsNone(db.active_reset(uid))
        db.audit(uid, cid, "test_event", "detail")                                           # must not raise


if __name__ == "__main__":
    unittest.main(verbosity=2)
