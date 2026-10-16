"""Phishing risk scoring and verdict classification.

Transparent and explainable: every point traces back to a specific indicator (see indicators.py).
Within one category, repeated similar signals contribute with diminishing weight (1x, 0.5x, 0.25x,
...) rather than stacking linearly — four urgency-language phrases in one email are not four times
the evidence of one, they are the same underlying technique observed repeatedly. Different
categories (authentication, sender, domain, content, BEC correlation) are independent evidence and
combine at full weight.

Per the spec: "Do not automatically label an email malicious based only on one weak indicator."
A single LOW or MEDIUM indicator alone stays BENIGN; MALICIOUS is reserved for cases with either a
correlated BEC signal or several independent categories of strong evidence — not one loud category.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from regexsoc.email_security.indicators import PhishingIndicator
from regexsoc.models import Severity

POINTS = {Severity.LOW.value: 8, Severity.MEDIUM.value: 16, Severity.HIGH.value: 28, Severity.CRITICAL.value: 45}
_DIMINISHING_WEIGHTS = (1.0, 0.5, 0.25, 0.125)  # 5th+ indicator in one category adds a flat 0.1

# (floor, classification) — highest floor the score meets or exceeds wins.
BANDS = ((80, "MALICIOUS"), (50, "PHISHING"), (20, "SUSPICIOUS"), (0, "BENIGN"))

CATEGORIES = ("AUTHENTICATION", "SENDER", "DOMAIN", "CONTENT", "BEC", "URL", "ATTACHMENT")


class Classification(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


def _classify(score: int) -> str:
    for floor, label in BANDS:
        if score >= floor:
            return label
    return Classification.BENIGN.value


def _category_score(indicators: list[PhishingIndicator]) -> int:
    """Diminishing-returns sum for one category's indicators: highest-severity first, each
    subsequent one contributing a shrinking fraction of its points."""
    points = sorted((POINTS.get(i.severity, 0) for i in indicators), reverse=True)
    total = 0.0
    for idx, p in enumerate(points):
        weight = _DIMINISHING_WEIGHTS[idx] if idx < len(_DIMINISHING_WEIGHTS) else 0.1
        total += p * weight
    return round(total)


def _confidence(indicators: list[PhishingIndicator]) -> str:
    """HIGH when evidence spans several independent categories or includes a CRITICAL
    (correlated) signal; MEDIUM for two categories; LOW for a single category or no indicators —
    matching the spec's "Show: Classification, Confidence, Reasons, Evidence" requirement."""
    if not indicators:
        return "HIGH"  # confidently benign: nothing at all was found
    categories = {i.category for i in indicators}
    if any(i.severity == Severity.CRITICAL.value for i in indicators) or len(categories) >= 3:
        return "HIGH"
    if len(categories) == 2:
        return "MEDIUM"
    return "LOW"


@dataclass
class PhishingRiskScore:
    score: int
    classification: str
    confidence: str
    category_scores: dict[str, int]
    indicators: list[PhishingIndicator]
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": self.score, "classification": self.classification, "confidence": self.confidence,
               "category_scores": self.category_scores, "reasons": self.reasons,
               "indicators": [i.to_dict() for i in self.indicators]}


def compute_verdict(indicators: list[PhishingIndicator], header_from_present: bool = True) -> PhishingRiskScore:
    """Score a list of indicators into a final, explainable verdict."""
    if not header_from_present:
        return PhishingRiskScore(0, Classification.UNKNOWN.value, "LOW", {}, indicators,
                                 ["No From header was present to evaluate."])

    by_category: dict[str, list[PhishingIndicator]] = {}
    for ind in indicators:
        by_category.setdefault(ind.category, []).append(ind)
    category_scores = {cat: _category_score(inds) for cat, inds in by_category.items()}
    total = min(100, sum(category_scores.values()))

    reasons = [f"{i.description} ({i.evidence})" if i.evidence else i.description
              for i in sorted(indicators, key=lambda i: -POINTS.get(i.severity, 0))]

    return PhishingRiskScore(total, _classify(total), _confidence(indicators), category_scores,
                             indicators, reasons)
