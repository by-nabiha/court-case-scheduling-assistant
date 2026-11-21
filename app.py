"""
Presentation layer (Flask).

The routes contain NO business logic: every action is forwarded to
AccessControlProxy -> CourtSchedulingFacade.  This file only deals with HTTP,
sessions and web security:

  * CSRF token on every form (Flask-WTF)
  * HttpOnly + SameSite=Strict session cookie, Secure flag when HTTPS
  * 15-minute idle timeout, session cleared on login (no session fixation)
  * login rate limiting per client IP + account lockout (AuthService)
  * strict security headers (CSP, frame-ancestors, nosniff, no-store ...)
  * generic error pages (no stack traces), debug mode OFF
"""
import base64
import io
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import qrcode
from flask import (Flask, abort, flash, g, redirect, render_template, request, session,
                   url_for)
from flask_wtf.csrf import CSRFError, CSRFProtect

from court.access_proxy import AccessControlProxy
from court.auth import AuthenticationError, AuthService
from court.database import Database
from court.facade import CourtSchedulingFacade
from court.models import AccessDeniedError, CourtError, Role
from court.security import PASSWORD_RULES, FieldCipher

IDLE_TIMEOUT_MINUTES = 15
LOGIN_RATE_LIMIT = (10, 300)          # max 10 login POSTs per IP per 5 minutes


def _secret_key(instance):
    key = os.environ.get("COURT_SECRET_KEY")
    if key:
        return key
    path = Path(instance) / "secret.key"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path.read_text().strip()


def create_app(db_path=None, testing=False):
    app = Flask(__name__, instance_relative_config=False)
    instance = os.environ.get("COURT_INSTANCE", "instance")
    os.makedirs(instance, exist_ok=True)
    app.config.update(
        SECRET_KEY=_secret_key(instance),
        SESSION_COOKIE_NAME="court_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("COURT_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=IDLE_TIMEOUT_MINUTES),
        MAX_CONTENT_LENGTH=64 * 1024,
        WTF_CSRF_TIME_LIMIT=3600,
        TESTING=testing,
    )
    CSRFProtect(app)

    db = Database.get_instance(db_path or os.environ.get("COURT_DB", os.path.join(instance, "court.db")))
    facade = CourtSchedulingFacade(db, FieldCipher.from_environment(os.path.join(instance, "field.key")))
    auth = AuthService(facade)
    login_hits = defaultdict(deque)
    app.extensions["court_facade"] = facade

    # ------------------------------------------------------------ helpers
    def client_ip():
        return request.remote_addr or "unknown"

    def safe_back(default="dashboard"):
        """Redirect to the referring page only if it is on this site (no open redirect)."""
        ref = request.referrer
        if ref and urlparse(ref).netloc == request.host:
            return redirect(ref)
        return redirect(url_for(default))

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            uid = session.get("user_id")
            if not uid:
                if request.path == "/":
                    return redirect(url_for("landing"))
                return redirect(url_for("login"))
            last = session.get("last_seen", 0)
            if time.time() - last > IDLE_TIMEOUT_MINUTES * 60:
                user = facade.users.get(uid)
                auth.logout(user, "session timed out")
                session.clear()
                flash("Your session expired after 15 minutes of inactivity. Please log in again.", "warning")
                return redirect(url_for("login"))
            session["last_seen"] = time.time()
            g.svc = AccessControlProxy(facade, facade.users.get(uid) or abort(401))
            try:
                g.user = g.svc.user
            except AccessDeniedError as e:
                session.clear()
                flash(str(e), "error")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapper

    def action(success_message=None, back=None):
        """Run a state-changing operation; turn business errors into messages."""
        def deco(view):
            @wraps(view)
            def wrapper(*args, **kwargs):
                try:
                    result = view(*args, **kwargs)
                    if success_message:
                        flash(success_message, "success")
                    return result or (redirect(url_for(back)) if back else safe_back())
                except AccessDeniedError as e:
                    flash(str(e), "error")
                except CourtError as e:
                    flash(str(e), "error")
                return safe_back()
            return wrapper
        return deco

    @app.context_processor
    def inject():
        svc = getattr(g, "svc", None)
        ctx = {"Role": Role, "today": date.today().isoformat(), "user": getattr(g, "user", None),
               "can": (svc.can if svc else (lambda name: False))}
        if svc:
            try:
                ctx["judge_names"] = {j.judge_id: j.name for j in facade.judges_repo.all()}
                ctx["room_names"] = {r.courtroom_id: r.room_name for r in facade.courtrooms_repo.all()}
            except Exception:
                pass
        return ctx

    @app.template_filter("weekday")
    def weekday(iso):
        try:
            return date.fromisoformat(iso).strftime("%a")
        except ValueError:
            return ""

    @app.template_filter("status_label")
    def status_label(s):
        return (s or "").replace("_", " ").title()

    # ------------------------------------------------------ security headers
    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers.pop("Server", None)
        return resp

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        flash("Your form expired or was not sent from this site. Please try again.", "error")
        return redirect(url_for("login" if not session.get("user_id") else "dashboard"))

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(413)
    def too_large(e):
        return render_template("error.html", code=413, message="Request too large."), 413

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", code=500,
                               message="Something went wrong. The error has been logged."), 500

    @app.errorhandler(CourtError)
    def court_error(e):           # e.g. NotFoundError on a GET page
        flash(str(e), "error")
        return redirect(url_for("dashboard"))

    # ========================================================= authentication
    @app.route("/landing", methods=["GET", "POST"])
    def landing():
        if request.method == "POST":
            return login()
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return render_template("landing.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            hits, now = login_hits[client_ip()], time.time()
            while hits and now - hits[0] > LOGIN_RATE_LIMIT[1]:
                hits.popleft()
            if len(hits) >= LOGIN_RATE_LIMIT[0]:
                flash("Too many login attempts from this computer. Wait a few minutes.", "error")
                return render_template("login.html"), 429
            hits.append(now)
            try:
                user, needs_2fa = auth.authenticate(request.form.get("username"),
                                                    request.form.get("password"), f"ip={client_ip()}")
            except AuthenticationError as e:
                flash(str(e), "error")
                return render_template("login.html", username=request.form.get("username", "")[:50]), 401
            session.clear()                                   # prevent session fixation
            if needs_2fa:
                session["pending_2fa"] = user.user_id
                session["pending_since"] = time.time()
                return redirect(url_for("login_verify"))
            session.permanent = True
            session["user_id"], session["last_seen"] = user.user_id, time.time()
            flash(f"Welcome, {user.name}.", "success")
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/login/verify", methods=["GET", "POST"])
    def login_verify():
        uid = session.get("pending_2fa")
        if not uid or time.time() - session.get("pending_since", 0) > 300:
            session.clear()
            return redirect(url_for("login"))
        if request.method == "POST":
            try:
                user = auth.verify_second_factor(uid, request.form.get("code"), f"ip={client_ip()}")
            except AuthenticationError as e:
                flash(str(e), "error")
                if "locked" in str(e):
                    session.clear()
                    return redirect(url_for("login"))
                return render_template("verify.html"), 401
            session.clear()
            session.permanent = True
            session["user_id"], session["last_seen"] = user.user_id, time.time()
            flash(f"Welcome, {user.name}.", "success")
            return redirect(url_for("dashboard"))
        return render_template("verify.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        uid = session.get("user_id")
        if uid:
            auth.logout(facade.users.get(uid))
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    # ============================================================== dashboard
    @app.route("/")
    @login_required
    def dashboard():
        return render_template("dashboard.html", stats=g.svc.dashboard(),
                               notes=g.svc.notifications()[:8])

    @app.route("/notifications")
    @login_required
    def notifications():
        return render_template("notifications.html", notes=g.svc.notifications())

    # ====================================================== MODULE A: cases
    @app.route("/cases")
    @login_required
    def cases():
        status = request.args.get("status") or None
        q = (request.args.get("q") or "").strip().lower()[:50]
        items = g.svc.list_cases(status)
        if q:
            items = [c for c in items if q in c.case_id.lower() or q in c.case_title.lower()
                     or q in c.parties.lower()]
        return render_template("cases.html", cases=items, status=status, q=q)

    @app.route("/cases/new", methods=["GET", "POST"])
    @login_required
    def case_new():
        if request.method == "POST":
            try:
                case = g.svc.register_case(request.form.to_dict())
                flash(f"Case {case.case_id} registered as {case.type_label}"
                      + (" and marked URGENT by court rule." if case.urgent_by_rule else "."), "success")
                return redirect(url_for("case_detail", case_id=case.case_id))
            except CourtError as e:
                flash(str(e), "error")
                return render_template("case_form.html", form=request.form,
                                       types=g.svc.case_types(), judges=g.svc.judges(),
                                       lawyers=g.svc.lawyers())
        if not g.svc.can("register_case"):
            flash("Access denied: your role cannot register cases.", "error")
            return redirect(url_for("cases"))
        return render_template("case_form.html", form={}, types=g.svc.case_types(),
                               judges=g.svc.judges(), lawyers=g.svc.lawyers())

    @app.route("/cases/<case_id>")
    @login_required
    def case_detail(case_id):
        try:
            case = g.svc.get_case(case_id)
        except CourtError as e:
            flash(str(e), "error")
            return redirect(url_for("cases"))
        hearings = [h for h in g.svc.list_hearings() if h.case_id == case_id]
        return render_template("case_detail.html", case=case, hearings=hearings,
                               history=g.svc.case_history(case_id),
                               judges=g.svc.judges(), vtypes=g.svc.vulnerability_types(),
                               waiting=case.waiting_days())

    @app.route("/cases/<case_id>/update", methods=["POST"])
    @login_required
    @action("Case information updated.")
    def case_update(case_id):
        data = {k: request.form[k] for k in ("case_title", "parties", "judge_id") if k in request.form}
        g.svc.update_case(case_id, data, request.form.get("reason"))

    @app.route("/cases/<case_id>/validate", methods=["POST"])
    @login_required
    def case_validate(case_id):
        try:
            problems = g.svc.validate_case(case_id)
            if problems:
                flash("Validation failed - case moved to UPDATE REQUIRED: " + "; ".join(problems), "warning")
            else:
                flash("Case validated. It will enter the prioritised backlog.", "success")
        except CourtError as e:
            flash(str(e), "error")
        return redirect(url_for("case_detail", case_id=case_id))

    @app.route("/cases/<case_id>/correction", methods=["POST"])
    @login_required
    @action("Correction requested.")
    def case_correction(case_id):
        g.svc.request_correction(case_id, request.form.get("reason"))

    @app.route("/cases/<case_id>/urgency", methods=["POST"])
    @login_required
    @action("Urgency updated.")
    def case_urgency(case_id):
        g.svc.mark_urgent(case_id, request.form.get("is_urgent") == "1", request.form.get("reason"))

    @app.route("/cases/<case_id>/vulnerability", methods=["POST"])
    @login_required
    @action("Vulnerability information recorded.")
    def case_vulnerability(case_id):
        g.svc.record_vulnerability(case_id, request.form.get("vulnerable") == "1",
                                   request.form.get("vulnerability_type", ""), request.form.get("reason", ""))

    # =============================================== MODULE B: priority engine
    @app.route("/priority")
    @login_required
    def priority():
        return render_template("priority.html", settings=g.svc.priority_settings(),
                               ranked=g.svc.prioritized_backlog())

    @app.route("/priority/strategy", methods=["POST"])
    @login_required
    @action("Priority rule changed. The backlog has been re-ranked.", back="priority")
    def priority_strategy():
        weights = None
        if request.form.get("strategy") == "WEIGHTED":
            weights = {k: request.form.get(f"w_{k}") for k in
                       ("urgency", "vulnerability", "waiting_per_year", "waiting_cap", "case_type")}
        g.svc.set_priority_strategy(request.form.get("strategy"), weights, request.form.get("reason"))

    @app.route("/priority/recalculate", methods=["POST"])
    @login_required
    @action("Priorities recalculated and saved.", back="priority")
    def priority_recalculate():
        g.svc.recalculate_priorities()

    # ========================================== MODULE C: availability/schedule
    @app.route("/availability")
    @login_required
    def availability():
        return render_template("availability.html", slots=g.svc.availability(),
                               judges=g.svc.judges(), rooms=g.svc.courtrooms())

    @app.route("/availability/add", methods=["POST"])
    @login_required
    @action("Availability added.")
    def availability_add():
        f = request.form
        rtype, _, rid = (f.get("resource") or "").partition(":")
        g.svc.add_availability(rtype, rid, f.get("date"), f.get("start"), f.get("end"))

    @app.route("/availability/<int:aid>/delete", methods=["POST"])
    @login_required
    @action("Availability removed. Run a conflict scan to check existing hearings.")
    def availability_delete(aid):
        g.svc.remove_availability(aid)

    @app.route("/courtrooms/<int:rid>/status", methods=["POST"])
    @login_required
    @action("Courtroom status updated.")
    def courtroom_status(rid):
        g.svc.set_courtroom_status(rid, request.form.get("status"), request.form.get("reason", ""))

    @app.route("/schedule")
    @login_required
    def schedule():
        status = request.args.get("status") or None
        hearings = g.svc.list_hearings(status)
        titles = {c.case_id: c for c in g.svc.list_cases()}
        open_conf = {c.schedule_id for c in (g.svc.list_conflicts() if g.svc.can("list_conflicts") else [])
                     if c.resolution_status == "OPEN"}
        return render_template("schedule.html", hearings=hearings, cases=titles, status=status,
                               open_conf=open_conf,
                               start=(date.today() + timedelta(days=1)).isoformat())

    @app.route("/schedule/generate", methods=["POST"])
    @login_required
    def schedule_generate():
        try:
            rec = g.svc.generate_schedule(request.form.get("start"), request.form.get("days"))
            msg = f"{len(rec.proposed)} hearings recommended and sent for judicial approval."
            if rec.unscheduled:
                msg += " Not placed: " + ", ".join(c for c, _ in rec.unscheduled)
            flash(msg, "success" if rec.proposed else "warning")
        except CourtError as e:
            flash(str(e), "error")
        return redirect(url_for("schedule"))

    @app.route("/hearings/<int:sid>/approve", methods=["POST"])
    @login_required
    @action("Hearing approved and added to the official schedule.")
    def hearing_approve(sid):
        g.svc.approve_hearing(sid)

    @app.route("/hearings/<int:sid>/changes", methods=["POST"])
    @login_required
    @action("Changes requested. The administrator has been notified.")
    def hearing_changes(sid):
        g.svc.request_changes(sid, request.form.get("reason"))

    @app.route("/hearings/<int:sid>/override", methods=["GET", "POST"])
    @login_required
    def hearing_override(sid):
        h = facade.hearings.get(sid)
        if not g.svc.can("override_hearing"):
            flash("Access denied: your role cannot change hearings.", "error")
            return redirect(url_for("schedule"))
        form = request.form if request.method == "POST" else {
            "date": h.hearing_date, "start": h.hearing_time, "courtroom_id": str(h.courtroom_id)}
        conflicts = None
        if request.method == "POST":
            try:
                if request.form.get("do") == "check":
                    conflicts = g.svc.check_slot(sid, form.get("date"), form.get("start"),
                                                 form.get("courtroom_id"))
                else:
                    g.svc.override_hearing(sid, form.get("date"), form.get("start"),
                                           form.get("courtroom_id"), form.get("reason"))
                    flash("Hearing rescheduled. It now needs approval again.", "success")
                    return redirect(url_for("schedule"))
            except CourtError as e:
                flash(str(e), "error")
        return render_template("override.html", h=h, form=form, conflicts=conflicts,
                               rooms=g.svc.courtrooms(),
                               slots=[a for a in g.svc.availability()
                                      if a.resource_type == "JUDGE" and a.resource_id == h.judge_id])

    @app.route("/hearings/<int:sid>/complete", methods=["POST"])
    @login_required
    @action("Hearing marked completed. Case disposed.")
    def hearing_complete(sid):
        g.svc.complete_hearing(sid)

    @app.route("/hearings/<int:sid>/cancel", methods=["POST"])
    @login_required
    @action("Hearing cancelled. Case returned to the backlog.")
    def hearing_cancel(sid):
        g.svc.cancel_hearing(sid, request.form.get("reason"))

    @app.route("/conflicts")
    @login_required
    def conflicts():
        try:
            items = g.svc.list_conflicts()
        except AccessDeniedError as e:
            flash(str(e), "error")
            return redirect(url_for("dashboard"))
        return render_template("conflicts.html", conflicts=items)

    @app.route("/conflicts/scan", methods=["POST"])
    @login_required
    def conflicts_scan():
        try:
            found = g.svc.scan_conflicts()
            flash(f"Scan complete: {len(found)} conflict(s) found." if found
                  else "Scan complete: no conflicts in the current schedule.",
                  "warning" if found else "success")
        except CourtError as e:
            flash(str(e), "error")
        return redirect(url_for("conflicts"))

    @app.route("/conflicts/<int:cid>/resolve", methods=["POST"])
    @login_required
    @action("Conflict marked as resolved.")
    def conflict_resolve(cid):
        g.svc.resolve_conflict(cid, request.form.get("note"))

    # ================================================== audit & administration
    @app.route("/audit")
    @login_required
    def audit():
        try:
            rows = g.svc.audit_log()
        except AccessDeniedError as e:
            flash(str(e), "error")
            return redirect(url_for("dashboard"))
        return render_template("audit.html", rows=rows)

    @app.route("/audit/verify", methods=["POST"])
    @login_required
    def audit_verify():
        try:
            ok, bad, count = g.svc.verify_audit()
            if ok:
                flash(f"Audit log integrity verified: all {count} entries are intact.", "success")
            else:
                flash(f"TAMPERING DETECTED: the audit chain is broken at entry #{bad}.", "error")
        except CourtError as e:
            flash(str(e), "error")
        return redirect(url_for("audit"))

    @app.route("/users")
    @login_required
    def users():
        try:
            items = g.svc.list_users()
        except AccessDeniedError as e:
            flash(str(e), "error")
            return redirect(url_for("dashboard"))
        return render_template("users.html", users=items, roles=Role.LABELS, rules=PASSWORD_RULES,
                               now=datetime.now().isoformat(timespec="seconds"))

    @app.route("/users/create", methods=["POST"])
    @login_required
    @action("User account created.")
    def user_create():
        f = request.form
        g.svc.create_user(f.get("username"), f.get("name"), f.get("email"), f.get("role"), f.get("password", ""))

    @app.route("/users/<int:uid>/<op>", methods=["POST"])
    @login_required
    @action("User account updated.")
    def user_op(uid, op):
        if op == "activate":
            g.svc.set_user_active(uid, True)
        elif op == "deactivate":
            g.svc.set_user_active(uid, False)
        elif op == "unlock":
            g.svc.unlock_user(uid)
        elif op == "reset-password":
            g.svc.reset_password(uid, request.form.get("password", ""))
        elif op == "reset-2fa":
            g.svc.reset_two_factor(uid)
        else:
            abort(404)

    @app.route("/account", methods=["GET", "POST"])
    @login_required
    def account():
        qr = secret = None
        if request.method == "POST":
            op = request.form.get("op")
            try:
                if op == "password":
                    g.svc.change_own_password(request.form.get("current", ""), request.form.get("new", ""))
                    flash("Password changed.", "success")
                elif op == "2fa-begin":
                    secret, uri = g.svc.begin_two_factor_setup()
                    buf = io.BytesIO()
                    qrcode.make(uri, box_size=5, border=2).save(buf, format="PNG")
                    qr = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
                elif op == "2fa-confirm":
                    g.svc.confirm_two_factor_setup(request.form.get("code"))
                    flash("Two-factor authentication is now ON for your account.", "success")
            except CourtError as e:
                flash(str(e), "error")
        return render_template("account.html", qr=qr, secret=secret, rules=PASSWORD_RULES,
                               me=facade.users.get(g.user.user_id))

    return app


if __name__ == "__main__":
    application = create_app()
    facade = application.extensions["court_facade"]
    if not facade.users.all():                      # first start (e.g. on Replit): load demo data
        import seed
        instance = os.environ.get("COURT_INSTANCE", "instance")
        seed.seed(Database.get_instance(), FieldCipher.from_environment(os.path.join(instance, "field.key")))
        print(f"Demo data loaded. Password for all demo users: {seed.DEMO_PASSWORD}")
    # On Replit (or any container) listen on all interfaces; locally only on this computer.
    host = os.environ.get("HOST") or ("0.0.0.0" if os.environ.get("REPL_ID") else "127.0.0.1")
    application.run(host=host, port=int(os.environ.get("PORT", 5000)), debug=False)
