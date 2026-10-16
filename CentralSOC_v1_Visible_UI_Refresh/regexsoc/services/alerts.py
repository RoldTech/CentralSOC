"""Alert model and construction from detections."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from regexsoc.detectors.base import Detection

STATUSES = ("New", "Investigating", "Resolved", "False Positive")


@dataclass
class Alert:
    """An analyst-facing alert."""

    alert_id: str
    timestamp: datetime | None
    rule_id: str
    rule_name: str
    source_ip: str | None
    username: str | None
    event_type: str | None
    severity: str
    risk_score: int
    evidence: list[str]
    recommended_response: str
    reason: str
    status: str = "New"
    event_ids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "rule_id": self.rule_id, "rule_name": self.rule_name, "source_ip": self.source_ip,
            "username": self.username, "event_type": self.event_type, "severity": self.severity,
            "risk_score": self.risk_score, "reason": self.reason, "evidence": self.evidence,
            "recommended_response": self.recommended_response, "status": self.status,
            "event_ids": self.event_ids,
        }


def make_alert_id(d: Detection) -> str:
    """Deterministic ID so re-analysing the same log yields the same alert IDs."""
    seed = f"{d.rule_id}|{d.source_ip}|{d.username}|{d.timestamp}|{d.event_ids[:1]}"
    return "ALERT-" + hashlib.sha256(seed.encode()).hexdigest()[:10].upper()


def build_alerts(detections: list[Detection], threshold: int) -> list[Alert]:
    """Turn detections at or above the alert threshold into alerts, highest score first."""
    # Different detection paths may report the exact same event/rule firing.
    # Collapse only matching deterministic alert IDs; do not suppress distinct
    # timestamps, identities or rules. Keep all distinct linked event IDs.
    by_id: dict[str, Alert] = {}
    for d in detections:
        if d.risk_score < threshold:
            continue
        alert_id = make_alert_id(d)
        existing = by_id.get(alert_id)
        if existing is None:
            by_id[alert_id] = Alert(
                alert_id, d.timestamp, d.rule_id, d.rule_name, d.source_ip,
                d.username, d.event_type, d.severity, d.risk_score,
                list(d.evidence[:20]), d.recommended_response, d.reason,
                event_ids=list(dict.fromkeys(d.event_ids)),
            )
            continue
        existing.event_ids = list(dict.fromkeys(existing.event_ids + d.event_ids))
        existing.evidence = list(dict.fromkeys(existing.evidence + d.evidence))[:20]
        if d.risk_score > existing.risk_score:
            existing.risk_score = d.risk_score
            existing.severity = d.severity
            existing.reason = d.reason
            existing.recommended_response = d.recommended_response
    return sorted(by_id.values(), key=lambda a: (-a.risk_score, a.timestamp.isoformat() if a.timestamp else ""))
