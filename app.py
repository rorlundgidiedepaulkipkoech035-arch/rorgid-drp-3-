"""Company dashboard: registration, logins, findings review, company details, platform-admin approval."""
import hmac
import logging
import os
import re
import secrets
import time
from datetime import timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from src import assets, db, documents, mailer, security

logger = logging.getLogger("DRP-Dashboard")
EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[A-Za-z]{2,})$")
DUMMY_HASH = generate_password_hash("timing-equaliser-password")
ARTIFACT_DIR = os.path.abspath(os.getenv("ARTIFACT_DIR", "./artifacts"))
STATUS_FILTERS = ("pending_review", "confirmed", "dismissed", "approved_for_report", "reported", "report_failed")
STATUS_COLORS = {"pending_review": "#e39a1c", "confirmed": "#d0463b", "dismissed": "#9aa7bd",
                 "approved_for_report": "#8e44ad", "sending": "#8e44ad", "reported": "#16a36f", "report_failed": "#a3241c"}
COMPANY_STATUS = {"pending": "awaiting documents", "approved": "verified", "suspended": "suspended"}
_failures = {}  # (ip, email) -> [timestamps]; in-memory limiter, use Redis when running several workers


def _parse_list(text):
    return sorted({p.strip().lower() for p in re.split(r"[,\s;]+", text or "") if p.strip()})


def enqueue_report(finding_id):
    """Asks a Celery worker to send an approved report. If Redis or Celery is unavailable the finding simply
    stays 'approved for report' and the Celery beat sweep sends it later."""
    try:
        from src.workers.tasks import send_report_task
        send_report_task.delay(finding_id)
    except Exception as e:
        logger.warning("Could not queue report %s now (%r); the beat sweep will pick it up.", finding_id, e)


def _email_domain(email):
    if len(email or "") > 254:
        return None
    m = EMAIL_RE.match(email or "")
    return m.group(1).lower() if m else None


def create_app():
    app = Flask(__name__)
    secret = os.getenv("SECRET_KEY")
    if not secret:
        logger.warning("SECRET_KEY not set: using a random key (sessions reset on restart).")
        secret = secrets.token_hex(32)
    app.config.update(
        SECRET_KEY=secret, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
        SHOW_RESET_CODE=os.getenv("DRP_SHOW_RESET_CODE", "false").lower() == "true",  # demo only
        # Active session: the cookie is renewed on every request, so it only expires after this much inactivity.
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.getenv("SESSION_IDLE_MINUTES", "30"))),
        SESSION_REFRESH_EACH_REQUEST=True)
    db.init_db()
    app.jinja_env.globals["cstatus"] = lambda st: COMPANY_STATUS.get(st, st)
    app.jinja_env.globals["PASSWORD_HINT"] = security.PASSWORD_HINT

    def code_hash(uid, code):
        return hmac.new(app.config["SECRET_KEY"].encode(), f"{uid}:{code}".encode(), "sha256").hexdigest()

    # ------------------------------------------------------------ plumbing
    @app.before_request
    def load_user_and_check_csrf():
        g.user = None
        if session.get("uid"):
            g.user = db.get_user(session["uid"])
            if g.user is None:
                session.clear()
        if request.method == "POST":
            sent, real = request.form.get("csrf_token", ""), session.get("csrf", "")
            if not real or not hmac.compare_digest(sent.encode(), real.encode()):
                abort(400)

    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf_token": lambda: session["csrf"], "user": g.get("user")}

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'"
        if request.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "public, max-age=86400"
        else:
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def login_required(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if g.user is None:
                return redirect(url_for("login"))
            return f(*a, **kw)
        return wrapper

    def roles(*allowed):
        def deco(f):
            @wraps(f)
            def wrapper(*a, **kw):
                if g.user is None:
                    return redirect(url_for("login"))
                if g.user["role"] not in allowed:
                    abort(403)
                return f(*a, **kw)
            return wrapper
        return deco

    def my_company():
        if g.user["company_id"] is None:
            abort(403)
        return db.get_company(g.user["company_id"])

    # ------------------------------------------------------------ auth
    @app.get("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html", f={})
        f = {k: request.form.get(k, "").strip() for k in (
            "legal_name", "registration_number", "website", "official_email", "phone", "address", "country",
            "brands", "domains", "admin_email")}
        brands, domains = _parse_list(f["brands"]), _parse_list(f["domains"])
        admin_email = f["admin_email"].lower()
        pw, pw2 = request.form.get("password", ""), request.form.get("password2", "")
        errors = []
        if not 2 <= len(f["legal_name"]) <= 200:
            errors.append("Enter the company's full legal name.")
        if not 3 <= len(f["registration_number"]) <= 64:
            errors.append("Enter the official company registration number.")
        if not _email_domain(f["official_email"]):
            errors.append("Enter a valid official company email.")
        if not brands or not all(db.BRAND_RE.match(b) for b in brands):
            errors.append("Brands must be 4-63 characters (letters, digits, hyphens), e.g. 'yourbrand'.")
        if not domains or not all(db.DOMAIN_RE.match(d) for d in domains):
            errors.append("Enter at least one valid domain you own, e.g. 'yourbrand.com'.")
        ed = _email_domain(admin_email)
        if not ed:
            errors.append("Enter a valid admin email.")
        elif domains and not any(ed == d or ed.endswith("." + d) for d in domains):
            errors.append("The admin email must be on one of your company domains (proves you belong to the company).")
        if security.password_problem(pw):
            errors.append(security.password_problem(pw))
        if pw != pw2:
            errors.append("Passwords do not match.")
        if not errors:
            try:
                cid = db.create_company(f, brands, domains, admin_email, generate_password_hash(pw))
                db.audit(None, cid, "company_registered", f["legal_name"])
                flash("Registration received. Log in to upload your verification documents.")
                return redirect(url_for("login"))
            except ValueError as e:
                errors.append(str(e))
        for e in errors:
            flash(e, "error")
        return render_template("register.html", f=f), 400

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")
        email = request.form.get("email", "").strip().lower()
        key = (request.remote_addr, email)
        recent = [t for t in _failures.get(key, []) if time.time() - t < 900]
        if len(recent) >= 5:
            return render_template("login.html", error="Too many attempts. Try again in 15 minutes."), 429
        u = db.get_user_by_email(email)
        ok = check_password_hash(u["password_hash"] if u else DUMMY_HASH, request.form.get("password", ""))
        if not (u and ok):
            _failures[key] = recent + [time.time()]
            return render_template("login.html", error="Invalid email or password."), 401
        _failures.pop(key, None)
        session.clear()
        session.permanent = True
        session["uid"], session["csrf"] = u["id"], secrets.token_hex(16)
        db.audit(u["id"], u["company_id"], "login")
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/account/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            cur, new, new2 = (request.form.get(k, "") for k in ("current", "new", "new2"))
            if not check_password_hash(g.user["password_hash"], cur):
                flash("Your current password is incorrect.", "error")
            elif security.password_problem(new):
                flash(security.password_problem(new), "error")
            elif new != new2:
                flash("The new passwords do not match.", "error")
            else:
                db.update_password(g.user["id"], generate_password_hash(new))
                db.audit(g.user["id"], g.user["company_id"], "password_changed")
                session["csrf"] = secrets.token_hex(16)
                flash("Password updated.")
                return redirect(url_for("dashboard"))
            return render_template("account.html"), 400
        return render_template("account.html")

    # ------------------------------------------------------------ dashboard / findings
    @app.get("/dashboard")
    @login_required
    def dashboard():
        if g.user["role"] == "platform_admin":
            return redirect(url_for("admin"))
        company = my_company()
        if company["status"] == "pending" and g.user["role"] == "company_admin":
            return redirect(url_for("verification"))
        cid = company["id"]
        counts = db.finding_counts(cid)
        total = sum(counts.values())
        segs, offset = [], 0.0
        for st in STATUS_COLORS:
            n = counts.get(st, 0)
            if n:
                pct = n * 100 / total
                segs.append({"status": st, "n": n, "pct": round(pct, 2), "offset": round(offset, 2),
                             "color": STATUS_COLORS[st]})
                offset += pct
        daily = db.daily_counts(cid)
        mx = max([n for _, n in daily] + [1])
        bars = [{"label": d[5:], "n": n, "h": round(n * 100 / mx)} for d, n in daily]
        return render_template("dashboard.html", company=company, counts=counts, total=total, segs=segs, bars=bars,
                               recent=db.list_findings(cid, limit=6), docs=db.documents(cid),
                               colors=STATUS_COLORS)

    @app.get("/findings")
    @login_required
    def findings_list():
        company = my_company()
        status = request.args.get("status")
        if status not in STATUS_FILTERS:
            status = None
        q = request.args.get("q", "").strip()[:80] or None
        return render_template("findings.html", company=company, status=status, q=q or "", filters=STATUS_FILTERS,
                               counts=db.finding_counts(company["id"]),
                               findings=db.list_findings(company["id"], status, search=q))

    # ------------------------------------------------------------ verification documents
    @app.get("/verification")
    @roles("company_admin", "analyst")
    def verification():
        c = my_company()
        docs = {d["doc_type"]: d for d in db.documents(c["id"])}
        done = sum(1 for t in security.REQUIRED if t in docs) + (1 if c["kra_pin"] else 0)
        return render_template("verification.html", c=c, docs=docs, types=security.DOC_TYPES,
                               progress=round(done * 100 / (len(security.REQUIRED) + 1)))

    def _verified_message(company_id):
        if db.try_auto_verify(company_id):
            db.audit(g.user["id"], company_id, "company_verified")
            flash("All verification requirements received. Your company is now verified and monitoring has started.")

    @app.post("/verification/details")
    @roles("company_admin")
    def verification_details():
        c = my_company()
        if c["status"] != "pending":
            flash("Details are locked once your company is verified.", "error")
            return redirect(url_for("verification"))
        pin = security.normalize_kra(request.form.get("kra_pin"))
        tm = request.form.get("trademark_number", "").strip()[:40]
        if not security.kra_valid(pin):
            flash("Enter a valid company KRA PIN: the letter P, nine digits, then a letter (e.g. P051234567A).", "error")
        else:
            try:
                db.save_kra(c["id"], pin, tm)
                db.audit(g.user["id"], c["id"], "kra_pin_saved")
                flash("KRA PIN saved.")
                _verified_message(c["id"])
            except ValueError as e:
                flash(str(e), "error")
        return redirect(url_for("verification"))

    @app.post("/verification/upload/<doc_type>")
    @roles("company_admin")
    def verification_upload(doc_type):
        c = my_company()
        if doc_type not in security.DOC_TYPES:
            abort(404)
        if c["status"] != "pending":
            flash("Documents are locked once your company is verified.", "error")
            return redirect(url_for("verification"))
        f = request.files.get("file")
        try:
            res = documents.store_document(c["id"], doc_type, f.filename if f else "", f.read() if f else b"")
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("verification"))
        db.audit(g.user["id"], c["id"], "document_uploaded", f"{doc_type} {res['serial']}")
        flash(f"{security.DOC_TYPES[doc_type][0]} received. Key serial {res['serial']} recorded with its hash.")
        _verified_message(c["id"])
        return redirect(url_for("verification"))

    @app.get("/documents/<int:doc_id>")
    @login_required
    def document_file(doc_id):
        d = db.get_document(doc_id) or abort(404)
        if g.user["role"] != "platform_admin" and g.user["company_id"] != d["company_id"]:
            abort(404)
        return send_from_directory(documents.upload_dir(), d["stored_name"], mimetype=d["mime"],
                                   as_attachment=d["mime"] == "application/pdf", download_name=d["filename"])

    # ------------------------------------------------------------ protected assets (hidden serial numbers)
    @app.get("/assets")
    @login_required
    def assets_page():
        c = my_company()
        return render_template("assets.html", c=c, items=db.list_assets(c["id"]))

    @app.post("/assets/upload")
    @roles("company_admin")
    def assets_upload():
        c = my_company()
        if c["status"] != "approved":
            flash("Protecting assets is available once your company is verified.", "error")
            return redirect(url_for("assets_page"))
        f = request.files.get("file")
        try:
            res = assets.protect_asset(c["id"], f.filename if f else "", f.read() if f else b"")
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("assets_page"))
        db.audit(g.user["id"], c["id"], "asset_protected", res["serial"])
        flash(f"Protected. Serial {res['serial']} is hidden inside the image. Download it and use that version.")
        return redirect(url_for("assets_page"))

    @app.get("/assets/<int:asset_id>/download")
    @login_required
    def assets_download(asset_id):
        c = my_company()
        a = db.get_asset(c["id"], asset_id) or abort(404)
        base = os.path.splitext(a["filename"])[0] or "asset"
        return send_from_directory(documents.upload_dir(), a["stored_name"], mimetype="image/png",
                                   as_attachment=True, download_name=f"{base}-protected.png")

    @app.post("/assets/check")
    @login_required
    def assets_check():
        c = my_company()
        f = request.files.get("file")
        serial, whose = assets.check_image(c["id"], f.read() if f else b"")
        if whose == "yours":
            flash(f"Yes: this image carries your hidden serial {serial}.")
        elif whose == "other":
            flash("A hidden RORGID mark was found, but it does not belong to your company.", "error")
        else:
            flash("No hidden RORGID serial was found. (Marks do not survive JPEG re-saving, resizing or screenshots.)")
        return redirect(url_for("assets_page"))

    # ------------------------------------------------------------ forgot / reset password
    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "GET":
            return render_template("forgot.html")
        email = request.form.get("email", "").strip().lower()
        u = db.get_user_by_email(email)
        if u and db.recent_reset_count(u["id"]) < 3:
            code = f"{secrets.randbelow(1_000_000):06d}"
            db.create_reset(u["id"], code_hash(u["id"], code))
            mailer.send_mail(u["email"], "Your RORGID password reset code",
                             f"Your password reset code is {code}.\n\nIt expires in 15 minutes. "
                             "If you did not ask for this, ignore this email; your password has not changed.")
            db.audit(u["id"], u["company_id"], "password_reset_requested")
            if app.config["SHOW_RESET_CODE"]:
                flash(f"Demo mode: your code is {code} (normally it is only emailed).")
        flash("If that email has an account, a 6-digit code has been sent to it. It expires in 15 minutes.")
        session["reset_email"] = email
        return redirect(url_for("reset_password"))

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        if request.method == "GET":
            return render_template("reset.html", email=session.get("reset_email", ""))
        email = request.form.get("email", "").strip().lower()
        code, new, new2 = (request.form.get(k, "").strip() if k == "code" else request.form.get(k, "")
                           for k in ("code", "new", "new2"))
        u = db.get_user_by_email(email)
        r = db.active_reset(u["id"]) if u else None
        if not r:
            flash("That code is invalid or has expired. Request a new one.", "error")
            return render_template("reset.html", email=email), 400
        if not hmac.compare_digest(r["code_hash"], code_hash(u["id"], code)):
            db.bump_reset_attempts(r["id"])
            flash("That code is invalid or has expired. Request a new one.", "error")
            return render_template("reset.html", email=email), 400
        problem = security.password_problem(new) or (None if new == new2 else "The new passwords do not match.")
        if problem:                                   # code stays valid so they can fix the password
            flash(problem, "error")
            return render_template("reset.html", email=email, code=code), 400
        db.update_password(u["id"], generate_password_hash(new))
        db.use_reset(r["id"])
        db.audit(u["id"], u["company_id"], "password_reset_done")
        session.pop("reset_email", None)
        flash("Password updated. You can log in with it now.")
        return redirect(url_for("login"))

    @app.get("/findings/<int:fid>")
    @login_required
    def finding(fid):
        company = my_company()
        f = db.get_finding(company["id"], fid) or abort(404)
        return render_template("finding.html", f=f, company=company)

    @app.get("/findings/<int:fid>/screenshot")
    @login_required
    def screenshot(fid):
        f = db.get_finding(my_company()["id"], fid) or abort(404)
        name = os.path.basename(f["screenshot"] or "")
        if not name or not os.path.isfile(os.path.join(ARTIFACT_DIR, name)):
            abort(404)
        return send_from_directory(ARTIFACT_DIR, name, mimetype="image/png")

    ACTIONS = {"confirm": "confirmed", "dismiss": "dismissed", "reopen": "pending_review",
               "report": "approved_for_report"}

    @app.post("/findings/<int:fid>/<action>")
    @login_required
    def finding_action(fid, action):
        company = my_company()
        target = ACTIONS.get(action) or abort(404)
        if target == "approved_for_report":
            if g.user["role"] != "company_admin":
                abort(403)  # only a company admin can authorise a takedown report
            if company["status"] != "approved":
                abort(403)
        if db.get_finding(company["id"], fid) is None:
            abort(404)
        if db.set_finding_status(company["id"], fid, target):
            db.audit(g.user["id"], company["id"], f"finding_{action}", str(fid))
            if target == "approved_for_report":
                enqueue_report(fid)
            flash({"confirmed": "Marked as confirmed infringement.", "dismissed": "Dismissed as a false positive.",
                   "pending_review": "Reopened.", "approved_for_report":
                   "Approved. The report to KE-CIRT/CC will be sent shortly."}[target])
        else:
            flash("That action is not allowed for the finding's current status.", "error")
        return redirect(url_for("finding", fid=fid))

    # ------------------------------------------------------------ company settings
    @app.get("/company")
    @roles("company_admin")
    def company():
        c = my_company()
        return render_template("company.html", c=c, brands=db.brands(c["id"]), domains=db.domains(c["id"]),
                               users=db.company_users(c["id"]))

    @app.post("/company/details")
    @roles("company_admin")
    def company_details():
        c = my_company()
        d = {k: request.form.get(k, "").strip() for k in ("website", "official_email", "phone", "address", "country")}
        d["auto_report"] = request.form.get("auto_report") == "on"
        if not _email_domain(d["official_email"]):
            flash("Enter a valid official email.", "error")
        else:
            db.update_company_details(c["id"], d)
            db.audit(g.user["id"], c["id"], "company_details_updated")
            flash("Company details updated. (Legal name and registration number can only be changed by support.)")
        return redirect(url_for("company"))

    @app.post("/company/brands/add")
    @roles("company_admin")
    def brand_add():
        c = my_company()
        b = request.form.get("brand", "").strip().lower()
        if not db.BRAND_RE.match(b):
            flash("Invalid brand name.", "error")
        else:
            db.add_brand(c["id"], b)
            db.audit(g.user["id"], c["id"], "brand_added", b)
            flash("Brand submitted. It becomes active after verification.")
        return redirect(url_for("company"))

    @app.post("/company/domains/add")
    @roles("company_admin")
    def domain_add():
        c = my_company()
        d = request.form.get("domain", "").strip().lower()
        if not db.DOMAIN_RE.match(d):
            flash("Invalid domain.", "error")
        else:
            db.add_domain(c["id"], d)
            db.audit(g.user["id"], c["id"], "domain_added", d)
            flash("Domain submitted. It becomes active after verification.")
        return redirect(url_for("company"))

    @app.post("/company/brands/<int:item>/remove")
    @roles("company_admin")
    def brand_remove(item):
        c = my_company()
        db.remove_brand(c["id"], item)
        db.audit(g.user["id"], c["id"], "brand_removed", str(item))
        return redirect(url_for("company"))

    @app.post("/company/domains/<int:item>/remove")
    @roles("company_admin")
    def domain_remove(item):
        c = my_company()
        db.remove_domain(c["id"], item)
        db.audit(g.user["id"], c["id"], "domain_removed", str(item))
        return redirect(url_for("company"))

    @app.post("/company/users/add")
    @roles("company_admin")
    def user_add():
        c = my_company()
        email, pw = request.form.get("email", "").strip().lower(), request.form.get("password", "")
        role = request.form.get("role")
        if role not in ("analyst", "company_admin") or not _email_domain(email):
            flash("Provide a valid email and a role.", "error")
        elif security.password_problem(pw):
            flash(security.password_problem(pw), "error")
        else:
            try:
                db.create_user(c["id"], email, generate_password_hash(pw), role)
                db.audit(g.user["id"], c["id"], "user_added", email)
                flash("User added. Ask them to change the temporary password you set.")
            except ValueError as e:
                flash(str(e), "error")
        return redirect(url_for("company"))

    # ------------------------------------------------------------ platform admin
    @app.get("/admin")
    @roles("platform_admin")
    def admin():
        rows = [(c, db.brand_conflicts(c["id"]), db.company_users(c["id"]), db.documents(c["id"])) for c in db.list_companies()]
        return render_template("admin.html", rows=rows)

    @app.post("/admin/companies/<int:cid>/<action>")
    @roles("platform_admin")
    def admin_action(cid, action):
        if db.get_company(cid) is None:
            abort(404)
        if action == "approve":
            db.set_company_status(cid, "approved")
        elif action == "suspend":
            db.set_company_status(cid, "suspended")
        elif action == "approve-changes":
            db.approve_pending_items(cid)
        else:
            abort(404)
        db.audit(g.user["id"], cid, f"admin_{action}")
        flash(f"Company {cid}: {action} done.")
        return redirect(url_for("admin"))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")))
