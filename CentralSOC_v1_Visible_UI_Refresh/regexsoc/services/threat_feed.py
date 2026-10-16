"""Optional, offline, analyst-controlled IOC feed loader.

Untrusted feed data never causes outgoing connections or response actions. Expired
indicators are ignored; provenance is retained for analyst inspection.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path


@dataclass(frozen=True)
class FeedIndicator:
    kind: str
    value: str
    source: str
    expires_at: datetime


def load_feed(path: str | Path, *, now: datetime | None = None, max_bytes: int = 1024 * 1024) -> tuple[FeedIndicator, ...]:
    path = Path(path)
    if path.stat().st_size > max_bytes:
        raise ValueError('feed exceeds size limit')
    def unique_object(pairs):
        data = {}
        for key, value in pairs:
            if key in data:
                raise ValueError('duplicate feed key')
            data[key] = value
        return data
    with path.open('r', encoding='utf-8') as stream:
        items = json.load(stream, object_pairs_hook=unique_object)
    if not isinstance(items, list) or len(items) > 5000:
        raise ValueError('feed must be a list of at most 5000 indicators')
    now = now or datetime.now(timezone.utc)
    result = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {'type', 'value', 'source', 'expires_at'}:
            raise ValueError('indicator requires type, value, source and expires_at')
        kind, value, source = item['type'], item['value'], item['source']
        if kind not in {'ipv4', 'ipv6', 'domain'} or not isinstance(value, str) or not isinstance(source, str):
            raise ValueError('unsupported indicator')
        if not 1 <= len(source) <= 120 or not 1 <= len(value) <= 253:
            raise ValueError('invalid indicator length')
        if kind in {'ipv4', 'ipv6'}:
            address = ipaddress.ip_address(value)
            if address.version != int(kind[-1]):
                raise ValueError('IP version does not match indicator type')
            value = str(address)
        else:
            import re
            value = value.lower().rstrip('.')
            if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)+', value) or any(
                label.startswith('-') or label.endswith('-') or len(label) > 63 for label in value.split('.')
            ):
                raise ValueError('invalid domain')
        if not isinstance(item['expires_at'], str):
            raise ValueError('invalid expiration')
        try:
            expiry = datetime.fromisoformat(item['expires_at'].replace('Z', '+00:00'))
        except ValueError as exc:
            raise ValueError('invalid expiration') from exc
        if expiry.tzinfo is None:
            raise ValueError('expiration must include timezone')
        if expiry > now:
            result.append(FeedIndicator(kind, value, source, expiry))
    return tuple(result)
