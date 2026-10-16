"""Linux syslog parser: sshd, sudo/PAM and kernel firewall (iptables/UFW) messages."""

from __future__ import annotations

import re

from regexsoc.models import Event, EventType
from regexsoc.utils.net import normalize_ip
from regexsoc.utils.timeutil import parse_syslog

SYSLOG_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
SSH_FAILED = re.compile(
    r"Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_INVALID_USER = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
PAM_FAILURE = re.compile(r"authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?")
SUDO_CMD = re.compile(r"^\s*(?P<user>\S+)\s*:\s.*?COMMAND=(?P<cmd>.*)$")
FW_FIELD = {
    "src": re.compile(r"\bSRC=(\S+)"),
    "dst": re.compile(r"\bDST=(\S+)"),
    "proto": re.compile(r"\bPROTO=(\w+)"),
    "spt": re.compile(r"\bSPT=(\d+)"),
    "dpt": re.compile(r"\bDPT=(\d+)"),
    "action": re.compile(r"\b(DROP|REJECT|BLOCK|ACCEPT|ALLOW)\b"),
}


def parse(line: str, year: int, line_number: int = 0) -> Event | None:
    """Parse a syslog-formatted line; return None if it does not look like syslog."""
    m = SYSLOG_LINE.match(line)
    if not m:
        return None
    proc, msg = m["proc"].lower(), m["msg"]
    event = Event(
        timestamp=parse_syslog(m["ts"], year),
        host=m["host"],
        raw_log=line,
        source_format="syslog",
        event_type=EventType.SYSLOG,
        line_number=line_number,
    )
    if "SRC=" in msg and "DST=" in msg:
        return _firewall(event, msg)
    if proc.startswith("sshd"):
        event.protocol, event.destination_port = "SSH", 22  # sshd logs omit the listen port
        return _sshd(event, msg)
    if proc == "sudo":
        sm = SUDO_CMD.match(msg)
        if sm:
            event.event_type, event.username = EventType.SUDO_COMMAND, sm["user"]
        return event
    pm = PAM_FAILURE.search(msg)
    if pm:
        event.event_type = EventType.AUTH_FAILURE
        event.auth_status = "FAILURE"
        event.source_ip = normalize_ip(pm["ip"])
        event.username = pm["user"]
    return event


def _sshd(event: Event, msg: str) -> Event:
    if m := SSH_FAILED.search(msg):
        event.event_type, event.auth_status = EventType.FAILED_LOGIN, "FAILURE"
    elif m := SSH_ACCEPTED.search(msg):
        event.event_type, event.auth_status = EventType.LOGIN_SUCCESS, "SUCCESS"
    elif m := SSH_INVALID_USER.search(msg):
        # Not counted as a failed login: sshd also emits "Failed password for invalid user".
        event.event_type = EventType.INVALID_USER
    elif m := PAM_FAILURE.search(msg):
        event.event_type, event.auth_status = EventType.AUTH_FAILURE, "FAILURE"
    else:
        return event
    event.username = m["user"] or None
    event.source_ip = normalize_ip(m["ip"])
    port = m.groupdict().get("port")
    event.source_port = int(port) if port else None
    return event


def _firewall(event: Event, msg: str) -> Event:
    found: dict[str, str | None] = {}
    for key, rx in FW_FIELD.items():
        match = rx.search(msg)
        found[key] = match.group(1) if match else None
    event.source_ip = normalize_ip(found["src"])
    event.destination_ip = normalize_ip(found["dst"])
    event.protocol = found["proto"]
    event.source_port = int(found["spt"]) if found["spt"] else None
    event.destination_port = int(found["dpt"]) if found["dpt"] else None
    blocked = found["action"] in {"DROP", "REJECT", "BLOCK"}
    event.event_type = EventType.CONNECTION_BLOCKED if blocked else EventType.CONNECTION
    return event
