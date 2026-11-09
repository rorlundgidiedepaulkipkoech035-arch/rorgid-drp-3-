"""Database layer: SQLAlchemy 2.0 sessions over PostgreSQL (production) or SQLite (development and tests).

Every function opens its own short session, converts rows to plain records (`Rec`, a dict that also allows
attribute access) and closes the session, so no ORM object ever leaves this module. Every company query is
scoped by company id. Connection: DATABASE_URL (postgresql://user:pass@host/db) or, if unset, the SQLite file
in DRP_DB (default ./drp.db).
"""
import os
import re
import secrets
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, delete, event, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.models import (AuditLog, Base, Company, CompanyBrand, CompanyDocument, CompanyDomain, Finding,
                        PasswordReset, ProtectedAsset, User)

BRAND_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,61}[a-z0-9]$")  # 4-63 chars
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
ROLES = ("platform_admin", "company_admin", "analyst")
REQUIRED = ("kra_pin_cert", "registration_cert", "trademark_cert", "trademark_photo")
_ISO = "%Y-%m-%dT%H:%M:%SZ"


class Rec(dict):
    """A database row: works as row["name"] and as row.name (Jinja templates use both)."""
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


def rec(obj):
    return None if obj is None else Rec({c.key: getattr(obj, c.key) for c in obj.__table__.columns})


def now():
    return datetime.now(timezone.utc).strftime(_ISO)


def _cut(value, n):
    """PostgreSQL refuses text longer than the column; SQLite does not. Trim free text to the column size."""
    return None if value is None else str(value)[:n]


# ---------------------------------------------------------------- engine and sessions
_engines = {}


def _url():
    url = os.getenv("DATABASE_URL")
    if not url:
        return "sqlite:///" + os.path.abspath(os.getenv("DRP_DB", "./drp.db"))
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


def engine():
    url = _url()
    eng = _engines.get(url)
    if eng is None:
        if url.startswith("sqlite"):
            eng = create_engine(url, connect_args={"check_same_thread": False, "timeout": 15})

            @event.listens_for(eng, "connect")
            def _sqlite_pragmas(dbapi_conn, _record):
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.close()
        else:
            eng = create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=10)
        _engines[url] = eng
    return eng


@contextmanager
def session():
    s = Session(engine(), expire_on_commit=False)
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def init_db():
    """Creates any missing tables. (Use Alembic migrations for later schema changes in production.)"""
    Base.metadata.create_all(engine())


def reset_all():
    """Drops and recreates every table (tests only; needs ALLOW_DB_RESET=true)."""
    if os.getenv("ALLOW_DB_RESET", "").lower() != "true":
        raise RuntimeError("set ALLOW_DB_RESET=true to reset the database")
    Base.metadata.drop_all(engine())
    Base.metadata.create_all(engine())


def audit(user_id, company_id, action, detail=""):
    with session() as s:
        s.add(AuditLog(ts=now(), user_id=user_id, company_id=company_id, action=action, detail=detail))


# ---------------------------------------------------------------- companies and users
def create_company(details, brands, domains, admin_email, password_hash):
    try:
        with session() as s:
            co = Company(legal_name=_cut(details["legal_name"], 200), registration_number=_cut(details["registration_number"], 64),
                         website=_cut(details.get("website"), 255), official_email=_cut(details["official_email"], 255),
                         phone=_cut(details.get("phone"), 64), address=_cut(details.get("address"), 255),
                         country=_cut(details.get("country"), 64),
                         verification_token=secrets.token_hex(16), created_at=now())
            s.add(co)
            s.flush()
            for b in sorted(set(brands)):
                s.add(CompanyBrand(company_id=co.id, brand=b, approved=0))
            for d in sorted(set(domains)):
                s.add(CompanyDomain(company_id=co.id, domain=d, approved=0))
            s.add(User(company_id=co.id, email=admin_email, password_hash=password_hash, role="company_admin",
                       created_at=now()))
            s.flush()
            return co.id
    except IntegrityError:
        raise ValueError("A company with this registration number, or an account with this email, already exists.")


def create_user(company_id, email, password_hash, role):
    assert role in ROLES
    try:
        with session() as s:
            u = User(company_id=company_id, email=email, password_hash=password_hash, role=role, created_at=now())
            s.add(u)
            s.flush()
            return u.id
    except IntegrityError:
        raise ValueError("An account with this email already exists.")


def get_user_by_email(email):
    with session() as s:
        return rec(s.scalars(select(User).where(User.email == email)).first())


def get_user(uid):
    with session() as s:
        return rec(s.get(User, uid))


def update_password(uid, password_hash):
    with session() as s:
        s.execute(update(User).where(User.id == uid).values(password_hash=password_hash))


def company_users(cid):
    with session() as s:
        rows = s.scalars(select(User).where(User.company_id == cid).order_by(User.id)).all()
        return [Rec(id=u.id, email=u.email, role=u.role, created_at=u.created_at) for u in rows]   # never the hash


def get_company(cid):
    with session() as s:
        return rec(s.get(Company, cid))


def update_company_details(cid, d):
    with session() as s:
        s.execute(update(Company).where(Company.id == cid).values(
            website=_cut(d.get("website"), 255), official_email=_cut(d["official_email"], 255), phone=_cut(d.get("phone"), 64),
            address=_cut(d.get("address"), 255), country=_cut(d.get("country"), 64), auto_report=1 if d.get("auto_report") else 0))


def set_company_status(cid, status):
    assert status in ("pending", "approved", "suspended")
    with session() as s:
        s.execute(update(Company).where(Company.id == cid).values(status=status))
    if status == "approved":
        approve_pending_items(cid)


def list_companies():
    with session() as s:
        pb = (select(func.count()).select_from(CompanyBrand)
              .where(CompanyBrand.company_id == Company.id, CompanyBrand.approved == 0).scalar_subquery())
        pd = (select(func.count()).select_from(CompanyDomain)
              .where(CompanyDomain.company_id == Company.id, CompanyDomain.approved == 0).scalar_subquery())
        fc = select(func.count()).select_from(Finding).where(Finding.company_id == Company.id).scalar_subquery()
        out = []
        for co, a, b, c in s.execute(select(Company, pb, pd, fc).order_by(Company.id.desc())).all():
            r = rec(co)
            r.update(pending_brands=a, pending_domains=b, findings=c)
            out.append(r)
        return out


# ---------------------------------------------------------------- brands and domains
def brands(cid):
    with session() as s:
        return [rec(x) for x in s.scalars(select(CompanyBrand).where(CompanyBrand.company_id == cid).order_by(CompanyBrand.brand))]


def domains(cid):
    with session() as s:
        return [rec(x) for x in s.scalars(select(CompanyDomain).where(CompanyDomain.company_id == cid).order_by(CompanyDomain.domain))]


def add_brand(cid, brand):
    """New items need platform-admin approval before they affect detection."""
    try:
        with session() as s:
            if not s.scalar(select(CompanyBrand.id).where(CompanyBrand.company_id == cid, CompanyBrand.brand == brand)):
                s.add(CompanyBrand(company_id=cid, brand=brand, approved=0))
    except IntegrityError:
        pass


def add_domain(cid, domain):
    try:
        with session() as s:
            if not s.scalar(select(CompanyDomain.id).where(CompanyDomain.company_id == cid, CompanyDomain.domain == domain)):
                s.add(CompanyDomain(company_id=cid, domain=domain, approved=0))
    except IntegrityError:
        pass


def remove_brand(cid, item_id):
    with session() as s:
        s.execute(delete(CompanyBrand).where(CompanyBrand.id == item_id, CompanyBrand.company_id == cid))


def remove_domain(cid, item_id):
    with session() as s:
        s.execute(delete(CompanyDomain).where(CompanyDomain.id == item_id, CompanyDomain.company_id == cid))


def approve_pending_items(cid):
    with session() as s:
        a = s.execute(update(CompanyBrand).where(CompanyBrand.company_id == cid, CompanyBrand.approved == 0).values(approved=1)).rowcount
        b = s.execute(update(CompanyDomain).where(CompanyDomain.company_id == cid, CompanyDomain.approved == 0).values(approved=1)).rowcount
    return (a or 0) + (b or 0)


def brand_conflicts(cid):
    """Brands this company claims that another company has also claimed (the admin should check)."""
    with session() as s:
        mine = select(CompanyBrand.brand).where(CompanyBrand.company_id == cid)
        rows = s.execute(select(CompanyBrand.brand, Company.legal_name)
                         .select_from(CompanyBrand)
                         .join(Company, Company.id == CompanyBrand.company_id)
                         .where(CompanyBrand.company_id != cid, CompanyBrand.brand.in_(mine))).all()
        return [Rec(brand=b, legal_name=n) for b, n in rows]


def registry_snapshot():
    """What the engine monitors: approved companies, approved brands, approved own-domains."""
    out = []
    with session() as s:
        for co in s.scalars(select(Company).where(Company.status == "approved").order_by(Company.id)).all():
            bs = list(s.scalars(select(CompanyBrand.brand).where(CompanyBrand.company_id == co.id, CompanyBrand.approved == 1)))
            ds = list(s.scalars(select(CompanyDomain.domain).where(CompanyDomain.company_id == co.id, CompanyDomain.approved == 1)))
            if bs:
                out.append({"company_id": co.id, "brands": bs, "domains": ds, "auto_report": bool(co.auto_report)})
    return out


# ---------------------------------------------------------------- findings
def add_finding(company_id, domain, reason, sha256, serial, screenshot):
    """Stores a finding and returns its id, or None if this company already has one for the domain."""
    try:
        with session() as s:
            if s.scalar(select(Finding.id).where(Finding.company_id == company_id, Finding.domain == domain)):
                return None
            f = Finding(company_id=company_id, domain=_cut(domain, 253), reason=reason, sha256=sha256, serial=serial,
                        screenshot=_cut(screenshot, 255), detected_at=now(), updated_at=now())
            s.add(f)
            s.flush()
            return f.id
    except IntegrityError:
        return None


def finding_exists(company_id, domain):
    with session() as s:
        return s.scalar(select(Finding.id).where(Finding.company_id == company_id, Finding.domain == domain)) is not None


def list_findings(cid, status=None, limit=200, search=None):
    stmt = select(Finding).where(Finding.company_id == cid)
    if status:
        stmt = stmt.where(Finding.status == status)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(or_(Finding.domain.ilike(like), Finding.reason.ilike(like)))
    with session() as s:
        return [rec(x) for x in s.scalars(stmt.order_by(Finding.id.desc()).limit(limit))]


def get_finding(cid, fid):
    """Always scoped by company: tenants can never read each other's data."""
    with session() as s:
        return rec(s.scalars(select(Finding).where(Finding.id == fid, Finding.company_id == cid)).first())


def get_finding_any(fid):
    """A finding by id without company scoping (for background workers only)."""
    with session() as s:
        return rec(s.get(Finding, fid))


def finding_counts(cid):
    with session() as s:
        rows = s.execute(select(Finding.status, func.count()).where(Finding.company_id == cid).group_by(Finding.status)).all()
        return {st: n for st, n in rows}


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
    with session() as s:
        res = s.execute(update(Finding).where(Finding.id == fid, Finding.company_id == cid,
                                              Finding.status.in_(allowed_from)).values(status=new_status, updated_at=now()))
        return res.rowcount == 1


def fetch_approved_findings():
    with session() as s:
        return [rec(x) for x in s.scalars(select(Finding).where(Finding.status == "approved_for_report").order_by(Finding.id))]


def mark_reported(fid, ok):
    with session() as s:
        s.execute(update(Finding).where(Finding.id == fid).values(status="reported" if ok else "report_failed", updated_at=now()))



def claim_report(fid):
    """Atomically moves approved_for_report -> sending. Returns True only for the one worker that wins."""
    with session() as s:
        res = s.execute(update(Finding).where(Finding.id == fid, Finding.status == "approved_for_report")
                        .values(status="sending", updated_at=now()))
        return res.rowcount == 1


def requeue_stale_reports(minutes=15):
    """A worker that died mid-send leaves a finding in 'sending'; put it back so it is retried."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime(_ISO)
    with session() as s:
        res = s.execute(update(Finding).where(Finding.status == "sending", Finding.updated_at < cutoff)
                        .values(status="approved_for_report", updated_at=now()))
        return res.rowcount or 0


def backdate_finding(fid, days):
    """Moves a finding's detection time `days` days into the past (demo data only)."""
    when = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT10:00:00Z")
    with session() as s:
        s.execute(update(Finding).where(Finding.id == fid).values(detected_at=when))


def daily_counts(cid, days=14):
    """[(YYYY-MM-DD, detections)] for the last `days` days, oldest first, zeros included."""
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=days - 1)
    with session() as s:
        stamps = s.scalars(select(Finding.detected_at).where(Finding.company_id == cid, Finding.detected_at >= start.isoformat())).all()
    got = Counter(t[:10] for t in stamps)
    return [((start + timedelta(days=i)).isoformat(), got.get((start + timedelta(days=i)).isoformat(), 0)) for i in range(days)]


# ---------------------------------------------------------------- verification documents
def save_kra(cid, kra_pin, trademark_number):
    try:
        with session() as s:
            s.execute(update(Company).where(Company.id == cid).values(kra_pin=kra_pin, trademark_number=trademark_number or None))
            s.flush()
    except IntegrityError:
        raise ValueError("This KRA PIN is already registered to another company.")


def save_document(cid, doc_type, filename, stored_name, mime, size, sha256, serial):
    """Records the file with its hash and key serial; replaces an earlier file of the same type.
    Returns (new_id, [stored names of replaced files])."""
    try:
        with session() as s:
            old = list(s.scalars(select(CompanyDocument.stored_name).where(
                CompanyDocument.company_id == cid, CompanyDocument.doc_type == doc_type)))
            s.execute(delete(CompanyDocument).where(CompanyDocument.company_id == cid, CompanyDocument.doc_type == doc_type))
            d = CompanyDocument(company_id=cid, doc_type=doc_type, filename=filename, stored_name=stored_name,
                                mime=mime, size=size, sha256=sha256, serial=serial, uploaded_at=now())
            s.add(d)
            s.flush()
            return d.id, old
    except IntegrityError:
        raise ValueError("This exact file is already registered (by another company or for another document).")


def documents(cid):
    with session() as s:
        return [rec(x) for x in s.scalars(select(CompanyDocument).where(CompanyDocument.company_id == cid).order_by(CompanyDocument.id))]


def get_document(doc_id):
    with session() as s:
        return rec(s.get(CompanyDocument, doc_id))


def serial_owner(serial):
    """Company id that owns this key serial (verification document or protected asset), else None."""
    with session() as s:
        cid = s.scalar(select(CompanyDocument.company_id).where(CompanyDocument.serial == serial))
        if cid is None:
            cid = s.scalar(select(ProtectedAsset.company_id).where(ProtectedAsset.serial == serial))
        return cid


def serial_by_hash(sha256):
    """Serial of a REGISTERED trademark photo or protected asset with exactly this hash (None if unknown)."""
    with session() as s:
        ser = s.scalar(select(CompanyDocument.serial).where(CompanyDocument.sha256 == sha256, CompanyDocument.doc_type == "trademark_photo"))
        if ser is None:
            ser = s.scalar(select(ProtectedAsset.serial).where(ProtectedAsset.watermarked_sha256 == sha256))
        return ser


def try_auto_verify(cid):
    """Verifies a pending company once its KRA PIN and all required documents are on file."""
    with session() as s:
        co = s.get(Company, cid)
        if not co or co.status != "pending" or not co.kra_pin:
            return False
        have = set(s.scalars(select(CompanyDocument.doc_type).where(CompanyDocument.company_id == cid)))
        if not all(t in have for t in REQUIRED):
            return False
        co.status = "approved"
        co.verified_at = now()
    approve_pending_items(cid)
    return True


# ---------------------------------------------------------------- protected assets (steganography)
def add_asset(company_id, filename, stored_name, serial, original_sha256, watermarked_sha256, size):
    try:
        with session() as s:
            a = ProtectedAsset(company_id=company_id, filename=filename, stored_name=stored_name, serial=serial,
                               original_sha256=original_sha256, watermarked_sha256=watermarked_sha256, size=size,
                               created_at=now())
            s.add(a)
            s.flush()
            return a.id
    except IntegrityError:
        raise ValueError("This exact file is already registered.")


def list_assets(cid):
    with session() as s:
        return [rec(x) for x in s.scalars(select(ProtectedAsset).where(ProtectedAsset.company_id == cid).order_by(ProtectedAsset.id.desc()))]


def get_asset(cid, asset_id):
    with session() as s:
        return rec(s.scalars(select(ProtectedAsset).where(ProtectedAsset.id == asset_id, ProtectedAsset.company_id == cid)).first())


# ---------------------------------------------------------------- password reset codes
def create_reset(uid, code_hash, minutes=15):
    expires = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime(_ISO)
    with session() as s:
        s.execute(update(PasswordReset).where(PasswordReset.user_id == uid, PasswordReset.used == 0).values(used=1))
        s.add(PasswordReset(user_id=uid, code_hash=code_hash, expires_at=expires, created_at=now()))


def recent_reset_count(uid, minutes=60):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime(_ISO)
    with session() as s:
        return s.scalar(select(func.count()).select_from(PasswordReset).where(PasswordReset.user_id == uid, PasswordReset.created_at >= since)) or 0


def active_reset(uid):
    with session() as s:
        return rec(s.scalars(select(PasswordReset).where(
            PasswordReset.user_id == uid, PasswordReset.used == 0, PasswordReset.attempts < 5,
            PasswordReset.expires_at >= now()).order_by(PasswordReset.id.desc()).limit(1)).first())


def bump_reset_attempts(rid):
    with session() as s:
        s.execute(update(PasswordReset).where(PasswordReset.id == rid).values(attempts=PasswordReset.attempts + 1))


def use_reset(rid):
    with session() as s:
        s.execute(update(PasswordReset).where(PasswordReset.id == rid).values(used=1))
