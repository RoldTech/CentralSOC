"""Email parsing: raw bytes/text -> ParsedEmail.

Uses only the Python standard library (``email`` package with the modern ``EmailMessage`` policy),
so this module has no new dependency and is fully testable offline. Parsing never executes anything
in the message: no JavaScript, no attachment content, no URLs are fetched. Headers and bodies are
treated as untrusted data throughout — see docs/email-security.md for what later phases add on top.
"""

from __future__ import annotations

import email
from email import policy
from email.errors import MessageDefect
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime

from regexsoc.email_security.models import EmailAddress, MessagePart, ParsedEmail, ParsedHeaders
from regexsoc.security.files import sanitize_filename

DEFAULT_MAX_BYTES = 25 * 1024 * 1024  # 25 MB; matches typical mail-gateway attachment limits

_SINGLE_HEADERS = ("Return-Path", "Subject", "Message-ID", "MIME-Version", "Content-Type",
                  "X-Originating-IP", "X-Mailer", "User-Agent")
_MULTI_HEADERS = ("Received", "Authentication-Results", "Received-SPF", "DKIM-Signature",
                 "ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results")


class EmailParseError(ValueError):
    """Raised for conditions that make parsing unsafe to attempt (currently: oversized input)."""


def _addresses(msg: EmailMessage, header_name: str) -> list[EmailAddress]:
    raw_values = [str(v) for v in msg.get_all(header_name, [])]
    if not raw_values:
        return []
    out = []
    for display_name, address in getaddresses(raw_values):
        raw = f'"{display_name}" <{address}>' if display_name else address
        out.append(EmailAddress(display_name=display_name or None, address=address or None, raw=raw))
    return out


def _single(msg: EmailMessage, name: str) -> str | None:
    value = msg.get(name)
    return str(value) if value is not None else None


def _multi(msg: EmailMessage, name: str) -> list[str]:
    return [str(v) for v in msg.get_all(name, [])]


def _parse_date(msg: EmailMessage) -> tuple[object | None, str | None]:
    raw = msg.get("Date")
    if raw is None:
        return None, None
    try:
        return parsedate_to_datetime(str(raw)), str(raw)
    except (TypeError, ValueError):
        return None, str(raw)  # malformed Date is itself a signal; keep the raw text, drop the parse


def _extract_body(msg: EmailMessage) -> tuple[str | None, str | None]:
    """Best-effort plain-text and HTML bodies. Decoding failures never raise; they just yield None
    for that part rather than aborting the whole parse."""
    plain = html = None
    try:
        part = msg.get_body(preferencelist=("plain",))
        if part is not None:
            plain = part.get_content()
    except (LookupError, UnicodeDecodeError, ValueError):
        pass
    try:
        part = msg.get_body(preferencelist=("html",))
        if part is not None:
            html = part.get_content()
    except (LookupError, UnicodeDecodeError, ValueError):
        pass
    return plain, html


def _walk_parts(msg: EmailMessage) -> list[MessagePart]:
    """Structural metadata for every MIME part: content type, filename, size. Content is only read
    to measure its size — never interpreted, decompressed, or executed."""
    parts: list[MessagePart] = []
    attachment_names = {id(a) for a in msg.iter_attachments()} if msg.is_multipart() or msg.get_content_disposition() else set()

    def index_for(depth_path: list[int]) -> str:
        return ".".join(str(i) for i in depth_path)

    def walk(node: EmailMessage, path: list[int]) -> None:
        if node.is_multipart():
            for i, child in enumerate(node.iter_parts(), start=1):
                walk(child, path + [i])
            return
        filename = node.get_filename()
        try:
            payload = node.get_payload(decode=True)
            size = len(payload) if payload is not None else 0
        except (LookupError, ValueError):
            size = 0
        parts.append(MessagePart(
            part_index=index_for(path) or "1", content_type=node.get_content_type(),
            filename=filename, sanitized_filename=sanitize_filename(filename) if filename else None,
            size_bytes=size, is_attachment=id(node) in attachment_names or filename is not None,
        ))

    walk(msg, [])
    return parts


def _collect_defects(msg: EmailMessage) -> list[str]:
    defects: list[str] = []
    for part in msg.walk():
        for defect in part.defects:
            defects.append(f"{type(defect).__name__}: {defect}" if isinstance(defect, MessageDefect) else str(defect))
    return defects


def parse_email(raw: bytes | str, max_bytes: int = DEFAULT_MAX_BYTES) -> ParsedEmail:
    """Parse a raw RFC 5322 message (as produced by a mail server or a .eml file) into a ParsedEmail.

    Accepts bytes or str. Raises EmailParseError only for an oversized message; malformed but
    within-size content is parsed leniently (RFC 5322 parsing always tolerates malformed input) and
    any structural problems are reported via ``ParsedEmail.defects`` rather than raising.
    """
    raw_bytes = raw.encode("utf-8", errors="surrogateescape") if isinstance(raw, str) else raw
    if len(raw_bytes) > max_bytes:
        raise EmailParseError(f"email is {len(raw_bytes)} bytes; limit is {max_bytes}")

    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    raw_headers: dict[str, list[str]] = {}
    for key, value in msg.items():
        raw_headers.setdefault(key.lower(), []).append(str(value))

    date, date_raw = _parse_date(msg)
    headers = ParsedHeaders(
        from_=_addresses(msg, "From"), to=_addresses(msg, "To"), cc=_addresses(msg, "Cc"),
        reply_to=_addresses(msg, "Reply-To"), return_path=_single(msg, "Return-Path"),
        subject=_single(msg, "Subject"), date=date, date_raw=date_raw,
        message_id=_single(msg, "Message-ID"), received=_multi(msg, "Received"),
        authentication_results=_multi(msg, "Authentication-Results"),
        received_spf=_multi(msg, "Received-SPF"), dkim_signature=_multi(msg, "DKIM-Signature"),
        arc_seal=_multi(msg, "ARC-Seal"), arc_message_signature=_multi(msg, "ARC-Message-Signature"),
        arc_authentication_results=_multi(msg, "ARC-Authentication-Results"),
        mime_version=_single(msg, "MIME-Version"), content_type=_single(msg, "Content-Type"),
        x_originating_ip=_single(msg, "X-Originating-IP"), x_mailer=_single(msg, "X-Mailer"),
        user_agent=_single(msg, "User-Agent"),
    )
    plain_body, html_body = _extract_body(msg)

    return ParsedEmail(
        raw_headers=raw_headers, headers=headers, plain_text_body=plain_body, html_body=html_body,
        parts=_walk_parts(msg), size_bytes=len(raw_bytes), defects=_collect_defects(msg),
    )


def parse_email_file(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> ParsedEmail:
    """Parse a .eml file from disk. Reads only up to ``max_bytes`` + 1 to detect oversized files
    without loading an arbitrarily large file fully into memory first."""
    with open(path, "rb") as handle:
        raw = handle.read(max_bytes + 1)
    return parse_email(raw, max_bytes)
