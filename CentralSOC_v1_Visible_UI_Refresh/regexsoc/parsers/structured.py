"""Bounded, strict CSV/JSON/JSONL security-event parsing.

Unknown keys are retained only in the raw evidence, not promoted to trusted fields.
Malformed structured input fails the batch explicitly instead of silently disappearing.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from regexsoc.config import MAX_LINE_LENGTH
from regexsoc.models import Event, EventType
from regexsoc.utils.net import normalize_ip
from regexsoc.utils.timeutil import parse_iso

MAX_RECORDS = 100_000
MAX_COLUMNS = 128


class StructuredParseError(ValueError):
    pass


def _value(row: dict, *names):
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            if not isinstance(value, (str, int, float, bool)):
                raise StructuredParseError(f"field {name!r} must be a scalar")
            return str(value)
    return None


def _port(value, line):
    if value is None:
        return None
    try:
        number = int(value)
        if 0 <= number <= 65535:
            return number
    except ValueError:
        pass
    raise StructuredParseError(f"record {line}: invalid network port")


def _event(row: dict, number: int, fmt: str) -> Event:
    if not isinstance(row, dict) or not row:
        raise StructuredParseError(f"record {number}: expected a nonempty object")
    if len(row) > MAX_COLUMNS or any(not isinstance(k, str) or not k for k in row):
        raise StructuredParseError(f"record {number}: invalid or excessive fields")
    timestamp = _value(row, "timestamp", "@timestamp", "event_time", "time")
    parsed = parse_iso(timestamp) if timestamp else None
    if timestamp and parsed is None:
        raise StructuredParseError(f"record {number}: invalid ISO-8601 timestamp")
    source = _value(row, "source_ip", "src_ip", "src")
    dest = _value(row, "destination_ip", "dest_ip", "dst_ip", "dst")
    source_ip, dest_ip = normalize_ip(source), normalize_ip(dest)
    if source and not source_ip:
        raise StructuredParseError(f"record {number}: invalid source IP")
    if dest and not dest_ip:
        raise StructuredParseError(f"record {number}: invalid destination IP")
    status = _value(row, "auth_status", "outcome")
    if status:
        status = status.upper()
        if status in ("FAILED", "FAIL", "DENIED"):
            status = "FAILURE"
        if status in ("SUCCEEDED", "SUCCESSFUL", "OK", "PASS"):
            status = "SUCCESS"
        if status not in ("SUCCESS", "FAILURE"):
            raise StructuredParseError(f"record {number}: unsupported auth_status")
    kind = (_value(row, "event_type", "event_category") or "").upper()
    allowed = {v for k, v in vars(EventType).items() if k.isupper() and isinstance(v, str)}
    if kind and kind not in allowed:
        raise StructuredParseError(f"record {number}: unsupported event_type")
    if not kind:
        kind = EventType.FAILED_LOGIN if status == "FAILURE" else EventType.LOGIN_SUCCESS if status == "SUCCESS" else EventType.GENERIC
    http_status = _value(row, "http_status")
    if http_status:
        try:
            http_code = int(http_status)
            if http_code < 100 or http_code > 599:
                raise ValueError()
        except ValueError:
            raise StructuredParseError(f"record {number}: invalid HTTP status") from None
    else:
        http_code = None
    raw = json.dumps(row, ensure_ascii=True, separators=(",", ":"))
    if len(raw) > MAX_LINE_LENGTH:
        raise StructuredParseError(f"record {number}: exceeds {MAX_LINE_LENGTH} characters")
    return Event(id=number, line_number=number, timestamp=parsed, source_ip=source_ip,
                 destination_ip=dest_ip, source_port=_port(_value(row, "source_port", "src_port"), number),
                 destination_port=_port(_value(row, "destination_port", "dst_port"), number),
                 protocol=_value(row, "protocol"), username=_value(row, "username", "user"),
                 auth_status=status, event_type=kind, host=_value(row, "host", "hostname"),
                 http_method=_value(row, "http_method"), http_path=_value(row, "http_path"),
                 http_status=http_code, raw_log=raw, source_format=fmt)


def _pairs_no_duplicate(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise StructuredParseError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def parse_structured(path: str | Path, extension: str) -> list[Event]:
    """Parse one file; abort clearly on any malformed record or invalid UTF-8."""
    try:
        with Path(path).open("r", encoding="utf-8-sig", errors="strict", newline="") as handle:
            if extension == ".csv":
                reader = csv.DictReader(handle, restkey="__extra_fields__")
                if not reader.fieldnames or len(reader.fieldnames) > MAX_COLUMNS or len(set(reader.fieldnames)) != len(reader.fieldnames):
                    raise StructuredParseError("CSV requires unique, nonempty column headings")
                if any(not name or name == "__extra_fields__" for name in reader.fieldnames):
                    raise StructuredParseError("CSV has invalid column headings")
                rows = []
                for idx, row in enumerate(reader, 1):
                    if idx > MAX_RECORDS:
                        raise StructuredParseError("maximum record count exceeded")
                    if None in row or "__extra_fields__" in row:
                        raise StructuredParseError(f"record {idx}: CSV column count mismatch")
                    rows.append(_event(row, idx, "csv"))
                return rows
            if extension not in (".json", ".jsonl"):
                raise StructuredParseError("unsupported structured format")
            if extension == ".json":
                data = json.load(handle, object_pairs_hook=_pairs_no_duplicate)
                if isinstance(data, dict):
                    data = data.get("events", [data])
                if not isinstance(data, list):
                    raise StructuredParseError("JSON must contain an array of events or an events array")
                if len(data) > MAX_RECORDS:
                    raise StructuredParseError("maximum record count exceeded")
                return [_event(row, idx, "json") for idx, row in enumerate(data, 1)]
            rows = []
            for idx, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                if len(rows) >= MAX_RECORDS:
                    raise StructuredParseError("maximum record count exceeded")
                rows.append(_event(json.loads(line, object_pairs_hook=_pairs_no_duplicate), idx, "jsonl"))
            return rows
    except (UnicodeError, json.JSONDecodeError, csv.Error) as exc:
        raise StructuredParseError(f"malformed {extension} input: {exc}") from exc
