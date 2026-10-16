"""Best-effort parser for unstructured security logs."""

from __future__ import annotations

import re

from regexsoc.models import Event, EventType
from regexsoc.utils.net import normalize_ip
from regexsoc.utils.patterns import IPV4
from regexsoc.utils.timeutil import parse_iso

ISO_TS = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
SRC_IP = re.compile(rf"(?i)\b(?:src|src_ip|source_ip|srcip|client|from)[=: ]+({IPV4})")
DST_IP = re.compile(rf"(?i)\b(?:dst|dst_ip|dest_ip|dstip|dest|to)[=: ]+({IPV4})")
ANY_IPV4 = re.compile(f"({IPV4})")
USER = re.compile(r"(?i)\b(?:user(?:name)?|account|acct)[=: ]+([\w.\-@]+)")
SPORT = re.compile(r"(?i)\b(?:sport|spt|src_port)[=: ]+(\d{1,5})\b")
DPORT = re.compile(r"(?i)\b(?:dport|dpt|dst_port|dest_port)[=: ]+(\d{1,5})\b")
PROTO = re.compile(r"(?i)\b(?:proto(?:col)?)[=: ]+(\w+)")
FAIL_WORDS = re.compile(
    r"(?i)\b(?:login|logon|authentication|auth)\b.{0,20}\b(?:fail\w*|denied|invalid)\b|\bfailed (?:login|logon)\b"
)
OK_WORDS = re.compile(
    r"(?i)\b(?:login|logon|authentication|auth)\b.{0,20}\b(?:success\w*|ok)\b|\blogged in\b"
)


def _first(rx: re.Pattern[str], text: str) -> str | None:
    m = rx.search(text)
    return m.group(1) if m else None


def _port(value: str | None) -> int | None:
    return int(value) if value and int(value) <= 65535 else None


def parse(line: str, line_number: int = 0) -> Event:
    """Always returns an Event so that unknown formats still get detection and IOC extraction."""
    ts = ISO_TS.search(line)
    src = _first(SRC_IP, line) or _first(ANY_IPV4, line)
    event = Event(
        timestamp=parse_iso(ts.group(0)) if ts else None,
        source_ip=normalize_ip(src),
        destination_ip=normalize_ip(_first(DST_IP, line)),
        source_port=_port(_first(SPORT, line)),
        destination_port=_port(_first(DPORT, line)),
        protocol=(_first(PROTO, line) or "").upper() or None,
        username=_first(USER, line),
        raw_log=line,
        source_format="generic",
        event_type=EventType.GENERIC,
        line_number=line_number,
    )
    if FAIL_WORDS.search(line):
        event.event_type, event.auth_status = EventType.FAILED_LOGIN, "FAILURE"
    elif OK_WORDS.search(line):
        event.event_type, event.auth_status = EventType.LOGIN_SUCCESS, "SUCCESS"
    return event
