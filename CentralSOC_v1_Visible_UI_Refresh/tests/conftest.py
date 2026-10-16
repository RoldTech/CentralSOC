"""Shared helpers for building synthetic log lines."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

BASE = datetime(2024, 3, 10, 10, 0, 0)


def ssh_fail(offset_s: int, ip: str = "203.0.113.5", user: str = "root", port: int = 40000) -> str:
    t = (BASE + timedelta(seconds=offset_s)).strftime("%b %d %H:%M:%S")
    return f"{t} web01 sshd[1234]: Failed password for {user} from {ip} port {port} ssh2"


def ssh_ok(offset_s: int, ip: str = "203.0.113.5", user: str = "root") -> str:
    t = (BASE + timedelta(seconds=offset_s)).strftime("%b %d %H:%M:%S")
    return f"{t} web01 sshd[1234]: Accepted password for {user} from {ip} port 41000 ssh2"


def web(offset_s: int, target: str, status: int = 200, ip: str = "203.0.113.9", ua: str = "Mozilla/5.0") -> str:
    t = (BASE + timedelta(seconds=offset_s)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{t}] "GET {target} HTTP/1.1" {status} 512 "-" "{ua}"'
