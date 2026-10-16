"""Windows-style security events rendered as ``<timestamp> ... EventID=NNNN key=value`` lines."""

from __future__ import annotations

import re

from regexsoc.models import Event, EventType
from regexsoc.utils.net import normalize_ip
from regexsoc.utils.timeutil import parse_iso

LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+.*?\bEventID=(?P<eid>\d+)"
)
KEY_VALUE = re.compile(r'(\w+)=("[^"]*"|\S+)')
EVENT_MAP = {
    "4624": (EventType.LOGIN_SUCCESS, "SUCCESS"),
    "4625": (EventType.FAILED_LOGIN, "FAILURE"),
    "4634": (EventType.LOGOFF, None),
    "4647": (EventType.LOGOFF, None),
    "4672": (EventType.PRIVILEGE_ASSIGNED, None),
    "4720": (EventType.ACCOUNT_CREATED, None),
    "4740": (EventType.ACCOUNT_LOCKOUT, "FAILURE"),
}


def parse(line: str, line_number: int = 0) -> Event | None:
    """Parse a Windows-style event line; return None if no EventID is present."""
    m = LINE.match(line)
    if not m:
        return None
    fields = {k: v.strip('"') for k, v in KEY_VALUE.findall(line)}
    event_type, status = EVENT_MAP.get(m["eid"], (EventType.GENERIC, None))
    username = fields.get("TargetUserName") or fields.get("UserName")
    port = fields.get("IpPort", "")
    return Event(
        timestamp=parse_iso(m["ts"]),
        source_ip=normalize_ip(fields.get("IpAddress")),
        source_port=int(port) if port.isdigit() else None,
        username=username if username not in (None, "-") else None,
        protocol="RDP" if fields.get("LogonType") == "10" else "WINDOWS",
        host=fields.get("Computer"),
        auth_status=status,
        event_type=event_type,
        raw_log=line,
        source_format="windows",
        line_number=line_number,
    )
