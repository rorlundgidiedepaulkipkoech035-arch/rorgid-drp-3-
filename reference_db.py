"""TEST-ONLY reference implementation of src/db.py on plain sqlite3.

Used by the tests when SQLAlchemy is not installed, so the application logic can still be tested. The real
database layer is src/db.py (SQLAlchemy). Both must offer exactly the same functions (see test_db_contract.py)."""
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

BRAND_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,61}[a-z0-9]$")  # 4-63 chars
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
ROLES = ("platform_admin", "company_admin", "analyst")

SCHEMA = """
CREATE TABLE IF NOT EXISTS companies(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  legal_name TEXT NOT NULL,
  registration_number TEXT NOT NULL UNIQUE,
  website TEXT, official_email TEXT NOT NULL, phone TEXT, address TEXT, country TEXT,
  status TEXT NOT NULL DEFAULT 'pending',          -- pending | approved | suspended
  verification_token TEXT NOT NULL,
  auto_report INTEGER NOT NULL DEFAULT 0,
  kra_pin TEXT, trademark_number TEXT, verified_at TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS company_documents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  doc_type TEXT NOT NULL, filename TEXT NOT NULL, stored_name TEXT NOT NULL,
  mime TEXT NOT NULL, size INTEGER NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,                     -- the same file can only be registered once, platform-wide
  serial TEXT NOT NULL UNIQUE,                     -- key serial number issued for this file
  uploaded_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS protected_assets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  filename TEXT NOT NULL, stored_name TEXT NOT NULL,
  serial TEXT NOT NULL UNIQUE,
  original_sha256 TEXT NOT NULL, watermarked_sha256 TEXT NOT NULL UNIQUE,
  size INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS password_resets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  code_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS company_brands(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  brand TEXT NOT NULL, approved INTEGER NOT NULL DEFAULT 0,
  UNIQUE(company_id, brand));
CREATE TABLE IF NOT EXISTS company_domains(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  domain TEXT NOT NULL, approved INTEGER NOT NULL DEFAULT 0,
  UNIQUE(company_id, domain));
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER REFERENCES companies(id),     -- NULL for platform admins
  email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  role TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  domain TEXT NOT NULL, reason TEXT, sha256 TEXT, serial TEXT, screenshot TEXT,
  status TEXT NOT NULL DEFAULT 'pending_review',
  detected_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(company_id, domain));
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, user_id INTEGER, company_id INTEGER, action TEXT NOT NULL, detail TEXT);
"""


def _path():
    return os.getenv("DRP_DB", "./drp.db")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Rec(dict):
    """A row that works as row["name"] and row.name, like the SQLAlchemy layer's records."""
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


@contextmanager
def conn():
    c = sqlite3.connect(_path(), timeout=15)
    c.row_factory = lambda cur, row: Rec(zip([d[0] for d in cur.description], row))
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init_db():
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        have = {r["name"] for r in c.execute("PRAGMA table_info(companies)")}   # upgrade older databases
        for col in ("kra_pin", "trademark_number", "verified_at"):
            if col not in have:
                c.execute(f"ALTER TABLE companies ADD COLUMN {col} TEXT")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_companies_kra ON companies(kra_pin) WHERE kra_pin IS NOT NULL")


def audit(user_id, company_id, action, detail=""):
    with conn() as c:
        c.execute("INSERT INTO audit_log(ts,user_id,company_id,action,detail) VALUES(?,?,?,?,?)",
                  (now(), user_id, company_id, action, detail))


# ---------------------------------------------------------------- companies / users
def create_company(details, brands, domains, admin_email, password_hash):
    try:
        with conn() as c:
            cur = c.execute(
                "INSERT INTO companies(legal_name,registration_number,website,official_email,phone,address,"
                "country,verification_token,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (details["legal_name"], details["registration_number"], details.get("website"),
                 details["official_email"], details.get("phone"), details.get("address"),
                 details.get("country"), secrets.token_hex(16), now()))
            cid = cur.lastrowid
            for b in brands:
                c.execute("INSERT OR IGNORE INTO company_brands(company_id,brand) VALUES(?,?)", (cid, b))
            for d in domains:
                c.execute("INSERT OR IGNORE INTO company_domains(company_id,domain) VALUES(?,?)", (cid, d))
            c.execute("INSERT INTO users(company_id,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                      (cid, admin_email, password_hash, "company_admin", now()))
        return cid
    except sqlite3.IntegrityError:
        raise ValueError("A company with this registration number, or an account with this email, already exists.")


def create_user(company_id, email, password_hash, role):
    assert role in ROLES
    try:
        with conn() as c:
            return c.execute("INSERT INTO users(company_id,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                             (company_id, email, password_hash, role, now())).lastrowid
    except sqlite3.IntegrityError:
        raise ValueError("An account with this email already exists.")


def get_user_by_email(email):
    with conn() as c:
        return c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()


def update_password(uid, password_hash):
    with conn() as c:
        c.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, uid))


def get_user(uid):
    with conn() as c:
        return c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def company_users(cid):
    with conn() as c:
        return c.execute("SELECT id,email,role,created_at FROM users WHERE company_id=? ORDER BY id", (cid,)).fetchall()


def get_company(cid):
    with conn() as c:
        return c.execute("SELECT * FROM companies WHERE id=?", (cid,)).fetchone()


def update_company_details(cid, d):
    with conn() as c:
        c.execute("UPDATE companies SET website=?,official_email=?,phone=?,address=?,country=?,auto_report=? WHERE id=?",
                  (d.get("website"), d["official_email"], d.get("phone"), d.get("address"), d.get("country"),
                   1 if d.get("auto_report") else 0, cid))


def set_company_status(cid, status):
    assert status in ("pending", "approved", "suspended")
    with conn() as c:
        c.execute("UPDATE companies SET status=? WHERE id=?", (status, cid))
    if status == "approved":
        approve_pending_items(cid)


def list_companies():
    with conn() as c:
        return c.execute(
            "SELECT co.*, "
            "(SELECT COUNT(*) FROM company_brands b WHERE b.company_id=co.id AND b.approved=0) AS pending_brands,"
            "(SELECT COUNT(*) FROM company_domains d WHERE d.company_id=co.id AND d.approved=0) AS pending_domains,"
            "(SELECT COUNT(*) FROM findings f WHERE f.company_id=co.id) AS findings "
            "FROM companies co ORDER BY co.id DESC").fetchall()


# ---------------------------------------------------------------- brands / domains
def brands(cid):
    with conn() as c:
        return c.execute("SELECT * FROM company_brands WHERE company_id=? ORDER BY brand", (cid,)).fetchall()


def domains(cid):
    with conn() as c:
        return c.execute("SELECT * FROM company_domains WHERE company_id=? ORDER BY domain", (cid,)).fetchall()


def add_brand(cid, brand):
    with conn() as c:  # new items need platform-admin approval before they affect detection
        c.execute("INSERT OR IGNORE INTO company_brands(company_id,brand,approved) VALUES(?,?,0)", (cid, brand))


def add_domain(cid, domain):
    with conn() as c:
        c.execute("INSERT OR IGNORE INTO company_domains(company_id,domain,approved) VALUES(?,?,0)", (cid, domain))


def remove_brand(cid, item_id):
    with conn() as c:
        c.execute("DELETE FROM company_brands WHERE id=? AND company_id=?", (item_id, cid))


def remove_domain(cid, item_id):
    with conn() as c:
        c.execute("DELETE FROM company_domains WHERE id=? AND company_id=?", (item_id, cid))


def approve_pending_items(cid):
    with conn() as c:
        a = c.execute("UPDATE company_brands SET approved=1 WHERE company_id=? AND approved=0", (cid,)).rowcount
        b = c.execute("UPDATE company_domains SET approved=1 WHERE company_id=? AND approved=0", (cid,)).rowcount
    return a + b


def brand_conflicts(cid):
    """Brands this company claims that another company has also claimed (admin should check)."""
    with conn() as c:
        return c.execute(
            "SELECT b.brand, co.legal_name FROM company_brands b JOIN companies co ON co.id=b.company_id "
            "WHERE b.company_id!=? AND b.brand IN (SELECT brand FROM company_brands WHERE company_id=?)",
            (cid, cid)).fetchall()


def registry_snapshot():
    """What the engine monitors: approved companies, approved brands, approved legit domains."""
    out = []
    with conn() as c:
        for co in c.execute("SELECT id, auto_report FROM companies WHERE status='approved'").fetchall():
            bs = [r["brand"] for r in c.execute(
                "SELECT brand FROM company_brands WHERE company_id=? AND approved=1", (co["id"],))]
            ds = [r["domain"] for r in c.execute(
                "SELECT domain FROM company_domains WHERE company_id=? AND approved=1", (co["id"],))]
            if bs:
                out.append({"company_id": co["id"], "brands": bs, "domains": ds,
                            "auto_report": bool(co["auto_report"])})
    return out


# ---------------------------------------------------------------- findings
def add_finding(company_id, domain, reason, sha256, serial, screenshot):
    with conn() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO findings(company_id,domain,reason,sha256,serial,screenshot,detected_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,?)", (company_id, domain, reason, sha256, serial, screenshot, now(), now()))
        return cur.lastrowid if cur.rowcount else None


def list_findings(cid, status=None, limit=200, search=None):
    q, args = "SELECT * FROM findings WHERE company_id=?", [cid]
    if status:
        q += " AND status=?"
        args.append(status)
    if search:
        q += " AND (domain LIKE ? OR reason LIKE ?)"
        args += [f"%{search}%", f"%{search}%"]
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with conn() as c:
        return c.execute(q, args).fetchall()


def get_finding(cid, fid):
    with conn() as c:  # always scoped by company: tenants can never read each other's data
        return c.execute("SELECT * FROM findings WHERE id=? AND company_id=?", (fid, cid)).fetchone()


def finding_counts(cid):
    with conn() as c:
        rows = c.execute("SELECT status, COUNT(*) n FROM findings WHERE company_id=? GROUP BY status", (cid,))
        return {r["status"]: r["n"] for r in rows}


_TRANSITIONS = {
    "confirmed": ("pending_review", "dismissed"),
    "dismissed": ("pending_review", "confirmed"),
    "pending_review": ("dismissed", "confirmed"),
    "approved_for_report": ("confirmed", "report_failed"),
}


def set_finding_status(cid, fid, new_status):
    """Returns True if the transition was allowed and applied."""
    allowed_from = _TRANSITIONS.get(new_status)
    if not allowed_from:
        return False
    with conn() as c:
        marks = ",".join("?" * len(allowed_from))
        cur = c.execute(f"UPDATE findings SET status=?, updated_at=? WHERE id=? AND company_id=? "
                        f"AND status IN ({marks})", (new_status, now(), fid, cid, *allowed_from))
        return cur.rowcount == 1


def fetch_approved_findings():
    with conn() as c:
        return c.execute("SELECT * FROM findings WHERE status='approved_for_report' ORDER BY id").fetchall()


def mark_reported(fid, ok):
    with conn() as c:
        c.execute("UPDATE findings SET status=?, updated_at=? WHERE id=?",
                  ("reported" if ok else "report_failed", now(), fid))


def daily_counts(cid, days=14):
    """[(YYYY-MM-DD, number of detections)] for the last `days` days, oldest first, zeros included."""
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=days - 1)
    with conn() as c:
        rows = c.execute("SELECT substr(detected_at,1,10) d, COUNT(*) n FROM findings "
                         "WHERE company_id=? AND substr(detected_at,1,10)>=? GROUP BY d",
                         (cid, start.isoformat())).fetchall()
    got = {r["d"]: r["n"] for r in rows}
    return [((start + timedelta(days=i)).isoformat(), got.get((start + timedelta(days=i)).isoformat(), 0))
            for i in range(days)]


# ---------------------------------------------------------------- verification documents
REQUIRED = ("kra_pin_cert", "registration_cert", "trademark_cert", "trademark_photo")


def save_kra(cid, kra_pin, trademark_number):
    try:
        with conn() as c:
            c.execute("UPDATE companies SET kra_pin=?, trademark_number=? WHERE id=?",
                      (kra_pin, trademark_number or None, cid))
    except sqlite3.IntegrityError:
        raise ValueError("This KRA PIN is already registered to another company.")


def save_document(cid, doc_type, filename, stored_name, mime, size, sha256, serial):
    """Records the file with its hash and key serial. Replaces an earlier file of the same type.
    Returns (new_id, [stored names of replaced files])."""
    try:
        with conn() as c:
            old = [r["stored_name"] for r in c.execute(
                "SELECT stored_name FROM company_documents WHERE company_id=? AND doc_type=?", (cid, doc_type))]
            c.execute("DELETE FROM company_documents WHERE company_id=? AND doc_type=?", (cid, doc_type))
            new_id = c.execute(
                "INSERT INTO company_documents(company_id,doc_type,filename,stored_name,mime,size,sha256,serial,uploaded_at)"
                " VALUES(?,?,?,?,?,?,?,?,?)", (cid, doc_type, filename, stored_name, mime, size, sha256, serial, now())
            ).lastrowid
        return new_id, old
    except sqlite3.IntegrityError:
        raise ValueError("This exact file is already registered (by another company or for another document).")


def documents(cid):
    with conn() as c:
        return c.execute("SELECT * FROM company_documents WHERE company_id=? ORDER BY id", (cid,)).fetchall()


def get_document(doc_id):
    with conn() as c:
        return c.execute("SELECT * FROM company_documents WHERE id=?", (doc_id,)).fetchone()


def serial_owner(serial):
    with conn() as c:
        r = c.execute("SELECT company_id FROM company_documents WHERE serial=?", (serial,)).fetchone()
        if r is None:
            r = c.execute("SELECT company_id FROM protected_assets WHERE serial=?", (serial,)).fetchone()
        return r["company_id"] if r else None


def serial_by_hash(sha256):
    """Key serial of a REGISTERED trademark photo with exactly this hash (None if not registered)."""
    with conn() as c:
        r = c.execute("SELECT serial FROM company_documents WHERE sha256=? AND doc_type='trademark_photo'", (sha256,)).fetchone()
        if r is None:
            r = c.execute("SELECT serial FROM protected_assets WHERE watermarked_sha256=?", (sha256,)).fetchone()
        return r["serial"] if r else None


def try_auto_verify(cid):
    """Verifies a pending company once its KRA PIN and all required documents are on file."""
    with conn() as c:
        co = c.execute("SELECT status, kra_pin FROM companies WHERE id=?", (cid,)).fetchone()
        if not co or co["status"] != "pending" or not co["kra_pin"]:
            return False
        have = {r["doc_type"] for r in c.execute("SELECT doc_type FROM company_documents WHERE company_id=?", (cid,))}
        if not all(t in have for t in REQUIRED):
            return False
        c.execute("UPDATE companies SET status='approved', verified_at=? WHERE id=?", (now(), cid))
    approve_pending_items(cid)
    return True


# ---------------------------------------------------------------- password reset codes
def create_reset(uid, code_hash, minutes=15):
    expires = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with conn() as c:
        c.execute("UPDATE password_resets SET used=1 WHERE user_id=? AND used=0", (uid,))
        c.execute("INSERT INTO password_resets(user_id,code_hash,expires_at,created_at) VALUES(?,?,?,?)",
                  (uid, code_hash, expires, now()))


def recent_reset_count(uid, minutes=60):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with conn() as c:
        return c.execute("SELECT COUNT(*) n FROM password_resets WHERE user_id=? AND created_at>=?",
                         (uid, since)).fetchone()["n"]


def active_reset(uid):
    with conn() as c:
        return c.execute("SELECT * FROM password_resets WHERE user_id=? AND used=0 AND attempts<5 AND expires_at>=? "
                         "ORDER BY id DESC LIMIT 1", (uid, now())).fetchone()


def bump_reset_attempts(rid):
    with conn() as c:
        c.execute("UPDATE password_resets SET attempts=attempts+1 WHERE id=?", (rid,))


def use_reset(rid):
    with conn() as c:
        c.execute("UPDATE password_resets SET used=1 WHERE id=?", (rid,))


# ---------------------------------------------------------------- functions added with the SQLAlchemy layer
def reset_all():
    """Empties every table (tests only)."""
    if os.getenv("ALLOW_DB_RESET", "").lower() != "true":
        raise RuntimeError("set ALLOW_DB_RESET=true to reset the database")
    with conn() as c:
        for t in ("audit_log", "password_resets", "protected_assets", "findings", "company_documents",
                  "company_domains", "company_brands", "users", "companies"):
            c.execute(f"DROP TABLE IF EXISTS {t}")
    init_db()


def finding_exists(company_id, domain):
    with conn() as c:
        return c.execute("SELECT 1 FROM findings WHERE company_id=? AND domain=?", (company_id, domain)).fetchone() is not None


def get_finding_any(fid):
    """A finding by id without company scoping (for background workers only)."""
    with conn() as c:
        return c.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()


def backdate_finding(fid, days):
    """Moves a finding's detection time `days` days into the past (demo data only)."""
    when = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT10:00:00Z")
    with conn() as c:
        c.execute("UPDATE findings SET detected_at=? WHERE id=?", (when, fid))


def add_asset(company_id, filename, stored_name, serial, original_sha256, watermarked_sha256, size):
    try:
        with conn() as c:
            return c.execute(
                "INSERT INTO protected_assets(company_id,filename,stored_name,serial,original_sha256,watermarked_sha256,size,created_at)"
                " VALUES(?,?,?,?,?,?,?,?)", (company_id, filename, stored_name, serial, original_sha256, watermarked_sha256, size, now())
            ).lastrowid
    except sqlite3.IntegrityError:
        raise ValueError("This exact file is already registered.")


def list_assets(cid):
    with conn() as c:
        return c.execute("SELECT * FROM protected_assets WHERE company_id=? ORDER BY id DESC", (cid,)).fetchall()


def get_asset(cid, asset_id):
    with conn() as c:
        return c.execute("SELECT * FROM protected_assets WHERE id=? AND company_id=?", (asset_id, cid)).fetchone()


def claim_report(fid):
    """Atomically moves approved_for_report -> sending. Returns True only for the one worker that wins."""
    with conn() as c:
        return c.execute("UPDATE findings SET status='sending', updated_at=? WHERE id=? AND status='approved_for_report'",
                         (now(), fid)).rowcount == 1


def requeue_stale_reports(minutes=15):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with conn() as c:
        return c.execute("UPDATE findings SET status='approved_for_report', updated_at=? WHERE status='sending' AND updated_at<?",
                         (now(), cutoff)).rowcount
