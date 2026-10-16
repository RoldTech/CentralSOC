"""Persisted enable/disable state for rules (a JSON file for now; the database arrives in Phase 2)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from regexsoc.config import rule_state_path
from regexsoc.rules.definitions import Rule, default_rules


class UnknownRuleError(KeyError):
    """Raised when a rule ID does not exist."""


def _read(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read rule state file {path}: {exc}") from exc
    return data if isinstance(data, dict) else {}


def load_rules(path: Path | None = None) -> list[Rule]:
    """Return the rule catalogue with persisted overrides applied."""
    overrides = _read(path or rule_state_path())
    rules = default_rules()
    for rule in rules:
        state = overrides.get(rule.id, {})
        if isinstance(state.get("enabled"), bool):
            rule.enabled = state["enabled"]
    return rules


def set_enabled(rule_id: str, enabled: bool, path: Path | None = None) -> Rule:
    """Enable or disable a rule and persist the change atomically."""
    path = path or rule_state_path()
    rules = {r.id: r for r in default_rules()}
    rule_id = rule_id.upper()
    if rule_id not in rules:
        raise UnknownRuleError(rule_id)
    overrides = _read(path)
    overrides.setdefault(rule_id, {})["enabled"] = enabled
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(overrides, handle, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    rule = rules[rule_id]
    rule.enabled = enabled
    return rule
