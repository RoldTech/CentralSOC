"""Integrity verification: SHA-256 file hashing and a tamper-evident event hash chain.

IMPORTANT: hashing provides *integrity verification*, not confidentiality. Anyone who can read the
data can still read it. A plain hash chain is tamper-EVIDENT, not tamper-PROOF: an attacker with full
write access to the database could recompute every hash. Setting REGEXSOC_INTEGRITY_KEY makes the
chain an HMAC chain, so forging it also requires the key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

# Fields covered by the chain. Severity is excluded on purpose: it may legitimately change on re-analysis.
CHAIN_FIELDS = (
    "timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol",
    "username", "auth_status", "http_method", "http_path", "http_status", "user_agent", "host",
    "event_type", "source_format", "raw_log",
)


def to_naive_utc(value: datetime | None) -> datetime | None:
    """Normalize to naive UTC (how timestamps are stored) so hashes survive a database round-trip."""
    if value is not None and value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """Stream a file through SHA-256 (constant memory, never executes or imports it)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_event(seq: int, obj: Any) -> str:
    """Deterministic JSON for an event (works for Event dataclasses and ORM rows alike)."""
    values: list[Any] = []
    for name in CHAIN_FIELDS:
        value = getattr(obj, name, None)
        if name == "timestamp":
            value = to_naive_utc(value).isoformat() if value is not None else None
        values.append(value)
    return json.dumps({"seq": seq, "f": values}, ensure_ascii=True, separators=(",", ":"))


def event_hash(prev_hash: str, seq: int, obj: Any, key: bytes | None = None) -> str:
    """hash = H(prev_hash | canonical_event). Uses HMAC-SHA256 when a key is supplied."""
    message = f"{prev_hash}|{canonical_event(seq, obj)}".encode("utf-8")
    if key:
        return hmac.new(key, message, hashlib.sha256).hexdigest()
    return hashlib.sha256(message).hexdigest()


def build_chain(genesis: str, events: Iterable[Any], key: bytes | None = None) -> list[tuple[int, str, str]]:
    """Return (seq, prev_hash, hash) for each event, seq starting at 1. ``genesis`` is the file's SHA-256."""
    prev, out = genesis, []
    for seq, event in enumerate(events, start=1):
        current = event_hash(prev, seq, event, key)
        out.append((seq, prev, current))
        prev = current
    return out


@dataclass
class ChainResult:
    ok: bool
    checked: int
    broken_at: int | None
    reason: str


def verify_chain(genesis: str, rows: Iterable[Any], expected_count: int | None = None,
                 key: bytes | None = None) -> ChainResult:
    """Verify rows (ordered by seq; each with seq, prev_hash, hash and the CHAIN_FIELDS)."""
    prev, checked, expected_seq = genesis, 0, 1
    for row in rows:
        if row.seq != expected_seq:
            return ChainResult(False, checked, expected_seq,
                               f"event {expected_seq} missing or reordered (found seq {row.seq})")
        if not hmac.compare_digest(row.prev_hash, prev):
            return ChainResult(False, checked, row.seq, f"event {row.seq}: link to previous event is broken")
        if not hmac.compare_digest(event_hash(prev, row.seq, row, key), row.hash):
            return ChainResult(False, checked, row.seq, f"event {row.seq}: content was modified")
        prev, checked, expected_seq = row.hash, checked + 1, expected_seq + 1
    if expected_count is not None and checked != expected_count:
        return ChainResult(False, checked, checked + 1,
                           f"expected {expected_count} events but found {checked} (events removed)")
    return ChainResult(True, checked, None, f"chain intact ({checked} events)")


@dataclass
class IntegrityReport:
    """Result of verifying one stored log file and its events."""

    log_file_id: int
    original_hash: str
    current_hash: str | None
    file_status: str  # OK | TAMPERED | MISSING
    chain: ChainResult

    @property
    def ok(self) -> bool:
        return self.file_status == "OK" and self.chain.ok

    @property
    def status(self) -> str:
        return "OK" if self.ok else "FAILED"

    def to_dict(self) -> dict:
        return {"log_file_id": self.log_file_id, "original_hash": self.original_hash,
                "current_hash": self.current_hash, "file_status": self.file_status,
                "chain_ok": self.chain.ok, "chain_reason": self.chain.reason, "status": self.status}
