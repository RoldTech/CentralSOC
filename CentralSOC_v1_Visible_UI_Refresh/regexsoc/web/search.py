"""Global search: classify a free-text query so it can be matched against the right column(s).

Pure logic, no Flask or database dependency, so it is directly unit-testable.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_ALERT_ID = re.compile(r"^ALERT-[0-9A-F]{10}$", re.IGNORECASE)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_DOMAIN_OR_URL = re.compile(r"^(?:https?://\S+|(?:[a-z0-9-]+\.)+[a-z]{2,})$", re.IGNORECASE)


@dataclass(frozen=True)
class SearchQuery:
    kind: str  # "ip" | "alert_id" | "hash" | "cve" | "domain_or_url" | "text"
    value: str


def classify(raw_query: str) -> SearchQuery:
    """Decide what kind of thing the query looks like, so the search page can query the matching
    column(s) directly instead of a slow free-text scan across everything."""
    q = raw_query.strip()
    if _ALERT_ID.match(q):
        return SearchQuery("alert_id", q.upper())
    if _CVE.match(q):
        return SearchQuery("cve", q.upper())
    try:
        ipaddress.ip_address(q)
        return SearchQuery("ip", q)
    except ValueError:
        pass
    if _HEX.match(q) and len(q) in _HASH_LENGTHS:
        return SearchQuery("hash", q.lower())
    if _DOMAIN_OR_URL.match(q):
        return SearchQuery("domain_or_url", q)
    return SearchQuery("text", q)
