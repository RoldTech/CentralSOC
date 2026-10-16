"""CSV / JSON export with CSV-injection protection."""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: Any) -> Any:
    """Neutralise spreadsheet formulas: prefix risky strings with an apostrophe (OWASP guidance)."""
    if isinstance(value, str) and value.lstrip().startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _flatten(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return " | ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return value


def to_csv(rows: Iterable[dict], fields: list[str] | None = None) -> str:
    """Render dict rows as CSV. Every string cell is sanitised against formula injection."""
    rows = list(rows)
    fields = fields or (list(rows[0].keys()) if rows else [])
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    csv.writer(buf, lineterminator="\n").writerow([sanitize_cell(field) for field in fields])
    for row in rows:
        writer.writerow({k: sanitize_cell(_flatten(row.get(k))) for k in fields})
    return buf.getvalue()


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)
