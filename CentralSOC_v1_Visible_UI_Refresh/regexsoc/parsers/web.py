"""Apache / Nginx access-log parser (Common and Combined Log Format)."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl

from regexsoc.models import Event, EventType
from regexsoc.utils.net import normalize_ip
from regexsoc.utils.timeutil import parse_apache

ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
REQUEST = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)(?:\s+(?P<proto>HTTP/[\d.]+))?$")


def parse(line: str, line_number: int = 0) -> Event | None:
    """Parse an access-log line; return None if it does not match."""
    m = ACCESS_LINE.match(line)
    if not m:
        return None
    event = Event(
        timestamp=parse_apache(m["ts"]),
        source_ip=normalize_ip(m["ip"]),
        username=None if m["user"] == "-" else m["user"],
        http_status=int(m["status"]),
        user_agent=m["ua"] if m["ua"] not in (None, "-") else None,
        protocol="HTTP",
        event_type=EventType.HTTP_REQUEST,
        raw_log=line,
        source_format="web_access",
        line_number=line_number,
    )
    req = REQUEST.match(m["req"])
    if req:
        event.http_method = req["method"]
        path, _, query = req["target"].partition("?")
        event.http_path = path
        event.http_query = query or None
        event.request_params = dict(parse_qsl(query, keep_blank_values=True, max_num_fields=100))
    else:
        # Malformed request lines (binary garbage, TLS handshakes on port 80) are themselves signals.
        event.http_path = m["req"][:500]
    return event
