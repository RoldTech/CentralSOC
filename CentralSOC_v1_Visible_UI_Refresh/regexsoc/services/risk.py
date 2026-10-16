"""Transparent, configurable risk scoring.

The score is a triage aid built from itemised, human-readable contributions. It is NOT a
probability of compromise.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from regexsoc.detectors.base import Detection

DEFAULT_BANDS = ((80, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (0, "LOW"))


@dataclass
class ScoringConfig:
    """Scoring knobs. ``points`` overrides a rule's default risk score by rule ID."""

    points: dict[str, int] = field(default_factory=dict)
    bands: tuple[tuple[int, str], ...] = DEFAULT_BANDS
    repeat_threshold: int = 3
    repeat_bonus: int = 10
    alert_threshold: int = 30

    def points_for(self, rule_id: str, default: int) -> int:
        return max(0, min(100, int(self.points.get(rule_id, default))))

    def severity_for(self, score: int) -> str:
        for floor, name in self.bands:
            if score >= floor:
                return name
        return "LOW"

    @classmethod
    def from_file(cls, path: str | Path) -> "ScoringConfig":
        """Load overrides from JSON: {"points": {...}, "alert_threshold": 30, "repeat_bonus": 10}."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        allowed = {"points", "repeat_threshold", "repeat_bonus", "alert_threshold"}
        unknown = set(data) - allowed
        if unknown:
            raise ValueError(f"Unknown scoring keys: {sorted(unknown)}")
        return cls(**data)


@dataclass
class ScoreReason:
    points: int
    text: str

    def __str__(self) -> str:
        return f"+{self.points} {self.text}"


@dataclass
class RiskProfile:
    """Aggregate risk for one entity (source IP) with the reasons behind the number."""

    entity: str
    score: int
    severity: str
    reasons: list[ScoreReason]

    def to_dict(self) -> dict:
        return {"entity": self.entity, "score": self.score, "severity": self.severity,
                "reasons": [str(r) for r in self.reasons]}


def apply_scoring(detection: Detection, config: ScoringConfig) -> Detection:
    """Apply configured points and severity bands to a detection (in place)."""
    detection.risk_score = config.points_for(detection.rule_id, detection.risk_score)
    detection.severity = config.severity_for(detection.risk_score)
    return detection


def profile_entities(detections: list[Detection], config: ScoringConfig) -> dict[str, RiskProfile]:
    """Aggregate detections per source IP: each distinct rule counts once, plus a repeat bonus."""
    by_ip: dict[str, dict[str, list[Detection]]] = defaultdict(lambda: defaultdict(list))
    for d in detections:
        if d.source_ip and d.risk_score > 0:
            by_ip[d.source_ip][d.rule_id].append(d)
    profiles: dict[str, RiskProfile] = {}
    for ip, rules in by_ip.items():
        reasons: list[ScoreReason] = []
        for hits in rules.values():
            reasons.append(ScoreReason(max(h.risk_score for h in hits), hits[0].rule_name))
            if len(hits) >= config.repeat_threshold:
                reasons.append(ScoreReason(config.repeat_bonus, f"Repeated: {hits[0].rule_name} x{len(hits)}"))
        reasons.sort(key=lambda r: -r.points)
        score = min(100, sum(r.points for r in reasons))
        profiles[ip] = RiskProfile(ip, score, config.severity_for(score), reasons)
    return profiles
