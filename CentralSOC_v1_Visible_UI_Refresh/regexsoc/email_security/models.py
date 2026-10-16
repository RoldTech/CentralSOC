"""Data model for a parsed email. Pure dataclasses: no database, no Flask, fully unit-testable."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class EmailAddress:
    """One address from an address-type header (From, To, Cc, Reply-To...).

    ``display_name`` and ``address`` are exactly what the header claimed — never verified against
    anything. A missing/unparseable address still yields a record (``address=None``) so the raw
    text isn't silently dropped.
    """

    display_name: str | None
    address: str | None
    raw: str

    def to_dict(self) -> dict:
        return {"display_name": self.display_name, "address": self.address, "raw": self.raw}


@dataclass
class MessagePart:
    """One node in the MIME tree: a body part or an attachment."""

    part_index: str  # dotted path within the tree, e.g. "1.2"
    content_type: str
    filename: str | None
    sanitized_filename: str | None
    size_bytes: int
    is_attachment: bool

    def to_dict(self) -> dict:
        return {"part_index": self.part_index, "content_type": self.content_type,
               "filename": self.filename, "sanitized_filename": self.sanitized_filename,
               "size_bytes": self.size_bytes, "is_attachment": self.is_attachment}


@dataclass
class ParsedHeaders:
    """Normalized, structured view of the headers named in the Phase 1 spec.

    Every field here is exactly what the message claims — parsing does not evaluate, verify, or
    trust any of it. Fields that can legitimately repeat (Received, Authentication-Results, ARC-*,
    DKIM-Signature) are lists, oldest-hop-last is NOT assumed; order is preserved as it appeared.
    """

    from_: list[EmailAddress] = field(default_factory=list)
    to: list[EmailAddress] = field(default_factory=list)
    cc: list[EmailAddress] = field(default_factory=list)
    reply_to: list[EmailAddress] = field(default_factory=list)
    return_path: str | None = None
    subject: str | None = None
    date: datetime | None = None
    date_raw: str | None = None  # kept even when unparseable, since a malformed Date is itself a signal
    message_id: str | None = None
    received: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    dkim_signature: list[str] = field(default_factory=list)
    arc_seal: list[str] = field(default_factory=list)
    arc_message_signature: list[str] = field(default_factory=list)
    arc_authentication_results: list[str] = field(default_factory=list)
    mime_version: str | None = None
    content_type: str | None = None
    x_originating_ip: str | None = None
    x_mailer: str | None = None
    user_agent: str | None = None

    def to_dict(self) -> dict:
        return {
            "from": [a.to_dict() for a in self.from_], "to": [a.to_dict() for a in self.to],
            "cc": [a.to_dict() for a in self.cc], "reply_to": [a.to_dict() for a in self.reply_to],
            "return_path": self.return_path, "subject": self.subject,
            "date": self.date.isoformat() if self.date else None, "date_raw": self.date_raw,
            "message_id": self.message_id, "received": self.received,
            "authentication_results": self.authentication_results, "received_spf": self.received_spf,
            "dkim_signature": self.dkim_signature, "arc_seal": self.arc_seal,
            "arc_message_signature": self.arc_message_signature,
            "arc_authentication_results": self.arc_authentication_results,
            "mime_version": self.mime_version, "content_type": self.content_type,
            "x_originating_ip": self.x_originating_ip, "x_mailer": self.x_mailer,
            "user_agent": self.user_agent,
        }


@dataclass
class ParsedEmail:
    """The full result of parsing one email message."""

    raw_headers: dict[str, list[str]]  # lowercase header name -> every raw value, in order
    headers: ParsedHeaders
    plain_text_body: str | None
    html_body: str | None
    parts: list[MessagePart]
    size_bytes: int
    defects: list[str]  # malformed-structure warnings surfaced by the parser, never hidden

    @property
    def attachments(self) -> list[MessagePart]:
        return [p for p in self.parts if p.is_attachment]

    def to_dict(self) -> dict:
        return {
            "headers": self.headers.to_dict(), "size_bytes": self.size_bytes,
            "has_plain_text_body": self.plain_text_body is not None,
            "has_html_body": self.html_body is not None,
            "parts": [p.to_dict() for p in self.parts], "defects": self.defects,
        }
