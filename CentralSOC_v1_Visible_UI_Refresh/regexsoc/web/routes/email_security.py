"""Email Security analyzer page.

Stateless by design: nothing here is persisted to the database. There is no EmailAnalysis table
yet (that depends on IOC/alert integration — a later phase, not yet built); this page parses and
scores whatever is submitted and shows the result in the same response. Refreshing loses it. This
limitation is shown in the UI itself, not just here, so it is never mistaken for a history feature.

Security notes:
- The email's HTML body is 100% attacker-controlled. It is shown as escaped source text only
  (standard Jinja auto-escaping, never |safe) — never rendered as live HTML, since there is no
  sandboxed-iframe infrastructure to do that safely yet.
- Uploads go through the same save_stream_to_temp() used by the log analyzer (generic, content
  agnostic), so the same size-limit-while-copying protection applies.
- Every analysis is audited (who ran it, when), even though the email content itself isn't stored.
"""

from __future__ import annotations

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for

from regexsoc import config
from regexsoc.db import models
from regexsoc.email_security.cases import save_case, update_case, list_cases, link_case_incident, linked_incidents
from regexsoc.db.service import record_audit
from regexsoc.email_security.auth import evaluate_dkim, evaluate_dmarc, evaluate_spf
from regexsoc.email_security.indicators import collect_indicators
from regexsoc.email_security.parser import DEFAULT_MAX_BYTES, EmailParseError, parse_email
from regexsoc.email_security.verdict import compute_verdict
from regexsoc.email_security.forensics import analyze_message_metadata
from regexsoc.security.audit import AuditAction
from regexsoc.security.files import sanitize_filename
from regexsoc.web.csrf_middleware import current_token
from regexsoc.web.decorators import permission_required
from regexsoc.security.rbac import has_permission
from regexsoc.web.upload import UploadRejected, save_stream_to_temp

bp = Blueprint("email_security", __name__, url_prefix="")


def _ctx(**extra) -> dict:
    from regexsoc.security.rbac import has_permission

    role = g.current_user.role
    return {
        "active": "email_security",
        "can_view_rules": has_permission(role, "view_rules"),
        "can_manage_rules": has_permission(role, "manage_rules"),
        "can_update_alert_status": has_permission(role, "update_alert_status"),
        "can_upload_logs": has_permission(role, "upload_logs"),
        "csrf_token": current_token(session, current_app.config["SECRET_KEY"]),
        "new_alert_count": 0,
        "can_view_incidents": has_permission(role, "view_incidents"),
        "can_manage_incidents": has_permission(role, "manage_incidents"),
        **extra,
    }


def _read_submission() -> tuple[bytes | None, str | None]:
    """Return (raw_bytes, error_message). A file upload takes priority over pasted text."""
    upload = request.files.get("file")
    if upload and upload.filename:
        safe_name = sanitize_filename(upload.filename)
        ext = "." + safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
        if ext not in config.ALLOWED_EMAIL_EXTENSIONS:
            return None, (f"unsupported file extension {ext or '(none)'!r}; allowed: "
                         f"{', '.join(config.ALLOWED_EMAIL_EXTENSIONS)}")
        try:
            tmp_path = save_stream_to_temp(upload.stream, config.max_upload_bytes())
        except UploadRejected as exc:
            return None, str(exc)
        try:
            return tmp_path.read_bytes(), None
        finally:
            tmp_path.unlink(missing_ok=True)

    pasted = request.form.get("raw_email", "")
    if pasted.strip():
        return pasted.encode("utf-8", errors="surrogateescape"), None
    return None, "Paste raw email text, or choose a .eml file, then submit."


@bp.route("/email-security", methods=["GET", "POST"])
@permission_required("upload_logs")
def analyze():
    if request.method == "GET":
        return render_template("dashboard/email_security.html", **_ctx(result=None))

    raw, error = _read_submission()
    if error:
        flash(error)
        return render_template("dashboard/email_security.html", **_ctx(result=None)), 400

    try:
        parsed = parse_email(raw, max_bytes=min(DEFAULT_MAX_BYTES, config.max_upload_bytes()))
    except EmailParseError as exc:
        flash(str(exc))
        return render_template("dashboard/email_security.html", **_ctx(result=None)), 400

    spf = evaluate_spf(parsed.headers)
    dkim = evaluate_dkim(parsed.headers)
    dmarc = evaluate_dmarc(parsed.headers)
    indicators = collect_indicators(parsed.headers, parsed.plain_text_body, parsed.html_body, dmarc)
    verdict = compute_verdict(indicators, header_from_present=bool(parsed.headers.from_))
    metadata_findings = analyze_message_metadata(parsed)

    case = save_case(g.db, raw, parsed, verdict, analyst=g.current_user.username, client_ip=request.remote_addr)

    record_audit(g.db, AuditAction.EMAIL_ANALYZED, g.current_user.username, "SUCCESS",
                ip_address=request.remote_addr,
                detail={"subject": parsed.headers.subject, "classification": verdict.classification,
                        "score": verdict.score, "size_bytes": parsed.size_bytes})

    result = {"parsed": parsed, "spf": spf, "dkim": dkim, "dmarc": dmarc, "indicators": indicators,
             "verdict": verdict, "metadata_findings": metadata_findings, "case": case}
    return render_template("dashboard/email_security.html", **_ctx(result=result))


@bp.get("/email-security/cases")
@permission_required("upload_logs")
def cases_index():
    return render_template("dashboard/email_cases.html", **_ctx(cases=list_cases(g.db)))


@bp.route("/email-security/cases/<int:case_id>", methods=["GET", "POST"])
@permission_required("upload_logs")
def case_detail(case_id):
    case = g.db.get(models.EmailCase, case_id)
    if case is None:
        return "Email investigation not found", 404
    if request.method == "POST":
        try:
            update_case(g.db, case, status=request.form.get("status", ""),
                        note=request.form.get("note", ""), analyst=g.current_user.username)
        except ValueError as exc:
            flash(str(exc))
            return render_template("dashboard/email_case_detail.html", **_ctx(case=case, linked_incidents=_case_incidents(case.id))), 400
        flash("Investigation updated")
        return redirect(url_for("email_security.case_detail", case_id=case.id))
    return render_template("dashboard/email_case_detail.html", **_ctx(case=case, linked_incidents=_case_incidents(case.id)))


def _case_incidents(case_id):
    return linked_incidents(g.db, case_id) if has_permission(g.current_user.role, 'view_incidents') else []


@bp.post('/email-security/cases/<int:case_id>/link-incident')
@permission_required('manage_incidents')
def link_to_incident(case_id):
    try:
        incident_id = int(request.form.get('incident_id', ''))
        if incident_id < 1:
            raise ValueError('Provide a valid incident ID')
        link_case_incident(g.db, case_id, incident_id, analyst=g.current_user.username)
        flash('Email case linked to incident')
    except (ValueError, TypeError) as exc:
        g.db.rollback()
        flash(str(exc))
    return redirect(url_for('email_security.case_detail', case_id=case_id))
