"""Detection result model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from regexsoc.rules.definitions import Rule


@dataclass
class Detection:
    """A rule firing on one event (event rules) or on a group of events (correlation rules)."""

    rule_id: str
    rule_name: str
    category: str
    severity: str
    risk_score: int
    recommended_response: str
    reason: str
    source_ip: str | None = None
    username: str | None = None
    event_type: str | None = None
    timestamp: datetime | None = None
    event_ids: list[int] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @classmethod
    def from_rule(cls, rule: Rule, reason: str, **kwargs) -> "Detection":
        return cls(
            rule_id=rule.id, rule_name=rule.name, category=rule.category, severity=rule.severity,
            risk_score=rule.risk_score, recommended_response=rule.recommended_response,
            reason=reason, **kwargs,
        )

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "rule_name": self.rule_name, "category": self.category,
            "severity": self.severity, "risk_score": self.risk_score, "reason": self.reason,
            "source_ip": self.source_ip, "username": self.username, "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_ids": self.event_ids, "evidence": self.evidence, "details": self.details,
            "recommended_response": self.recommended_response,
        }
