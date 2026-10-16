"""Indicator-of-Compromise extraction driven by the IOC rules (RULE-014 ... RULE-023)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from regexsoc.models import Event
from regexsoc.rules.definitions import Rule
from regexsoc.utils.net import is_private, normalize_ip


@dataclass
class IOC:
    """An extracted indicator with its provenance."""

    ioc_type: str
    value: str
    event_id: int
    timestamp: datetime | None
    context: str
    rule_id: str

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type, "value": self.value, "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "context": self.context, "rule_id": self.rule_id,
        }


def _valid_ipv4(v: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(v))
    except ValueError:
        return None


def _valid_ipv6(v: str) -> str | None:
    # A bare "10:15:00" time string is rejected by ipaddress, which is why we validate here.
    if v.count(":") < 2:
        return None
    try:
        return str(ipaddress.IPv6Address(v))
    except ValueError:
        return None


def _clean_url(v: str) -> str | None:
    v = v.rstrip(".,;:)]}'\"")
    return v if urlsplit(v).netloc else None


def _clean_domain(v: str) -> str | None:
    return v.lower() if len(v) <= 253 else None


_VALIDATORS = {"ipv4": _valid_ipv4, "ipv6": _valid_ipv6, "url": _clean_url, "domain": _clean_domain}


def extract_iocs(event: Event, rules: list[Rule]) -> list[IOC]:
    """Extract all IOCs from an event's raw line using the enabled IOC rules (deduplicated)."""
    found: dict[tuple[str, str], IOC] = {}
    for rule in rules:
        if not rule.enabled or rule.target != "ioc":
            continue
        validator = _VALIDATORS.get(rule.params.get("validator") or "")
        for rx in rule.regexes:
            for match in rx.finditer(event.raw_log):
                value = match.group(0)
                if validator:
                    value = validator(value)
                    if value is None:
                        continue
                elif rule.params["ioc_type"] in {"MD5", "SHA1", "SHA256", "CVE"}:
                    value = value.lower() if rule.params["ioc_type"] != "CVE" else value.upper()
                key = (rule.params["ioc_type"], value)
                if key in found:
                    continue
                context = event.raw_log[:200]
                if rule.params["ioc_type"] in {"IPV4", "IPV6"} and (
                    normalize_ip(value) and is_private(value)
                ):
                    context = f"[private/reserved] {context}"
                found[key] = IOC(rule.params["ioc_type"], value, event.id, event.timestamp, context, rule.id)
    return list(found.values())
