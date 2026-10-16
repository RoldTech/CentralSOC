"""Login, MFA challenge/enrollment, and logout."""

from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

from regexsoc import config
from regexsoc.db.auth_service import (
    AccountDisabled, AccountLocked, InvalidCredentials, MFARequired, authenticate,
    begin_mfa_enrollment, confirm_mfa_enrollment, verify_mfa_login,
)
from regexsoc.security.audit import AuditAction
from regexsoc.security.rbac import ROLES
from regexsoc.db.service import record_audit
from regexsoc.web.csrf_middleware import current_token

bp = Blueprint("auth", __name__, url_prefix="")


def _client_ip() -> str | None:
    return request.remote_addr


def _safe_next(target: str | None) -> str:
    """Only ever redirect to a same-site relative path (open-redirect protection)."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard.overview")


@bp.get("/login")
def login_form():
    if session.get("user_id"):
        return redirect(url_for("dashboard.overview"))
    return render_template("auth/login.html", csrf_token=current_token(session, config.secret_key()),
                           next=request.args.get("next"))


@bp.post("/login")
def login_submit():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    try:
        result = authenticate(g.db, username, password, ip_address=_client_ip(),
                              policy=config.lockout_policy())
    except MFARequired as exc:
        session["mfa_pending_user_id"] = exc.user_id
        return redirect(url_for("auth.mfa_form", next=request.args.get("next")))
    except AccountLocked as exc:
        flash(exc.reason)
        return redirect(url_for("auth.login_form"))
    except (InvalidCredentials, AccountDisabled) as exc:
        flash(exc.reason if isinstance(exc, AccountDisabled) else "Invalid username or password.")
        return redirect(url_for("auth.login_form"))
    next_target = request.form.get("next_redirect")
    session.clear()  # drop any pre-auth session data (defense in depth)
    session["user_id"] = result.user.id
    session.permanent = True
    return redirect(_safe_next(next_target))


@bp.get("/login/mfa")
def mfa_form():
    if "mfa_pending_user_id" not in session:
        return redirect(url_for("auth.login_form"))
    return render_template("auth/mfa.html", csrf_token=current_token(session, config.secret_key()),
                           next=request.args.get("next"))


@bp.post("/login/mfa")
def mfa_submit():
    user_id = session.get("mfa_pending_user_id")
    if user_id is None:
        return redirect(url_for("auth.login_form"))
    try:
        result = verify_mfa_login(g.db, user_id, request.form.get("code") or "", ip_address=_client_ip())
    except InvalidCredentials as exc:
        flash(exc.reason)
        return redirect(url_for("auth.mfa_form"))
    next_target = request.form.get("next_redirect")
    session.clear()
    session["user_id"] = result.user.id
    session.permanent = True
    return redirect(_safe_next(next_target))


@bp.post("/logout")
def logout():
    user = getattr(g, "current_user", None)
    if user is not None:
        record_audit(g.db, AuditAction.LOGOUT, user.username, "SUCCESS", ip_address=_client_ip())
    session.clear()
    return redirect(url_for("auth.login_form"))


@bp.get("/mfa/setup")
def mfa_setup_form():
    user = getattr(g, "current_user", None)
    if user is None:
        return redirect(url_for("auth.login_form"))
    if user.username.casefold() == "demo_viewer":
        return "Security settings are locked for this demo account.", 403

    secret, _uri = begin_mfa_enrollment(g.db, user.id)
    return render_template(
        "auth/mfa_setup.html",
        secret=secret,
        csrf_token=current_token(session, config.secret_key()),
    )


@bp.post("/mfa/setup")
def mfa_setup_submit():
    user = getattr(g, "current_user", None)
    if user is None:
        return redirect(url_for("auth.login_form"))
    if user.username.casefold() == "demo_viewer":
        return "Security settings are locked for this demo account.", 403

    try:
        confirm_mfa_enrollment(
            g.db,
            user.id,
            request.form.get("code") or "",
            ip_address=_client_ip(),
        )
    except InvalidCredentials as exc:
        flash(exc.reason)
        return redirect(url_for("auth.mfa_setup_form"))
    flash("Two-factor authentication is now enabled.")
    return redirect(url_for("dashboard.overview"))
