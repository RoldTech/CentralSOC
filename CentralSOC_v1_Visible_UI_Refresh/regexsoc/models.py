"""Normalized data model shared by every parser, detector and interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from urllib.parse import unquote_plus


class Severity(str, Enum):
    """Ordered severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return ("LOW", "MEDIUM", "HIGH", "CRITICAL").index(self.value)

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().upper())
        except ValueError as exc:
            raise ValueError(f"Unknown severity: {value!r}") from exc


class EventType:
    """Normalized event-type names."""

    FAILED_LOGIN = "FAILED_LOGIN"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    INVALID_USER = "INVALID_USER"
    AUTH_FAILURE = "AUTH_FAILURE"
    LOGOFF = "LOGOFF"
    ACCOUNT_LOCKOUT = "ACCOUNT_LOCKOUT"
    ACCOUNT_CREATED = "ACCOUNT_CREATED"
    PRIVILEGE_ASSIGNED = "PRIVILEGE_ASSIGNED"
    SUDO_COMMAND = "SUDO_COMMAND"
    HTTP_REQUEST = "HTTP_REQUEST"
    CONNECTION = "CONNECTION"
    CONNECTION_BLOCKED = "CONNECTION_BLOCKED"
    SYSLOG = "SYSLOG"
    GENERIC = "GENERIC"


@dataclass
class Event:
    """A single log record in RegexSOC's normalized format."""

    id: int = 0
    timestamp: datetime | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    auth_status: str | None = None  # "SUCCESS" | "FAILURE" | None
    http_method: str | None = None
    http_path: str | None = None
    http_query: str | None = None
    http_status: int | None = None
    user_agent: str | None = None
    host: str | None = None
    request_params: dict[str, str] = field(default_factory=dict)
    event_type: str = EventType.GENERIC
    severity: str = Severity.LOW.value
    raw_log: str = ""
    source_format: str = "generic"
    line_number: int = 0

    @property
    def is_web(self) -> bool:
        return self.http_path is not None

    @property
    def request_target(self) -> str:
        """Path + query, URL-decoded twice so that (double-)encoded payloads are visible."""
        if self.http_path is None:
            return ""
        target = self.http_path + (f"?{self.http_query}" if self.http_query else "")
        return unquote_plus(unquote_plus(target))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "username": self.username,
            "auth_status": self.auth_status,
            "http_method": self.http_method,
            "http_path": self.http_path,
            "http_status": self.http_status,
            "user_agent": self.user_agent,
            "host": self.host,
            "request_params": self.request_params,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_format": self.source_format,
            "raw_log": self.raw_log,
        }
