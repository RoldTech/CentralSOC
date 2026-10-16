"""Social-engineering content indicators: phrase-based, not single-keyword, detection.

Per the spec this follows: "Do not rely exclusively on keyword matching. Treat these as supporting
indicators." Every pattern here requires a specific multi-word phrase or a word combined with
pressure/action language — not a bare word like "account" or "password" that would fire on any
ordinary transactional email. Each match returns the actual matched text as evidence, never just a
boolean, so an analyst can see exactly what triggered it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_BODY_CHARS = 200_000  # bound the amount of text regexes run over, independent of any ReDoS
                          # concern in the patterns themselves (see the sandbox timing check below)


@dataclass
class ContentMatch:
    category: str
    pattern_id: str
    evidence: str


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Each entry requires a specific phrase or word+pressure-context combination, never a bare noun.
_URGENCY = {
    "account_suspension": _rx(r"\b(?:account|access)\s+(?:will\s+be|has\s+been)\s+(?:suspended|"
                              r"locked|closed|terminated|disabled)\b"),
    "act_immediately": _rx(r"\b(?:act|respond|verify|confirm)\s+(?:now|immediately|urgently|"
                           r"within\s+\d+\s*(?:hours?|minutes?|days?))\b"),
    "urgent_action_required": _rx(r"\burgent(?:ly)?\s+action\s+(?:is\s+)?required\b"),
    "final_notice": _rx(r"\bfinal\s+(?:notice|warning|reminder)\b"),
    "failure_to_respond": _rx(r"\bfailure\s+to\s+(?:respond|act|verify|comply)\b"),
    "limited_time": _rx(r"\b(?:limited\s+time|expires?\s+(?:today|soon|shortly)|about\s+to\s+expire)\b"),
}

_CREDENTIAL_HARVESTING = {
    "verify_account": _rx(r"\bverify\s+your\s+(?:account|identity|details|information)\b"),
    "confirm_credentials": _rx(r"\bconfirm\s+your\s+(?:password|credentials|login|identity)\b"),
    "update_payment_info": _rx(r"\bupdate\s+your\s+(?:payment|billing)\s+(?:information|details|method)\b"),
    "click_to_verify": _rx(r"\bclick\s+(?:here\s+)?to\s+(?:verify|confirm|update|restore)\b"),
    "unusual_activity": _rx(r"\bunusual\s+(?:sign-?in|login|activity)\s+(?:detected|on\s+your\s+account)\b"),
}

_FINANCIAL_PRESSURE = {
    "wire_transfer": _rx(r"\bwire\s+transfer\b"),
    "gift_card_request": _rx(r"\b(?:purchase|buy|send)\s+(?:some\s+)?gift\s+cards?\b"),
    "bank_account_change": _rx(r"\b(?:change|update)\s+(?:of\s+)?(?:bank|banking)\s+(?:account|details)\b"),
    "routing_number": _rx(r"\brouting\s+number\b"),
    "urgent_payment": _rx(r"\burgent\s+payment\b"),
    "invoice_overdue": _rx(r"\b(?:invoice|payment)\b(?:\s+\w+){0,3}\s+(?:overdue|outstanding|past\s+due)\b"),
}

_MFA_PRESSURE = {
    "reset_password": _rx(r"\breset\s+your\s+password\b"),
    "verification_code": _rx(r"\b(?:verification|security)\s+code\b"),
    "mfa_reset": _rx(r"\b(?:two-?factor|multi-?factor|mfa)\s+(?:authentication\s+)?(?:reset|disabled|required)\b"),
}

_ALL_CATEGORIES = {
    "URGENCY": _URGENCY, "CREDENTIAL_HARVESTING": _CREDENTIAL_HARVESTING,
    "FINANCIAL_PRESSURE": _FINANCIAL_PRESSURE, "MFA_PRESSURE": _MFA_PRESSURE,
}


def find_content_indicators(text: str | None) -> list[ContentMatch]:
    """Scan plain-text (or HTML-stripped) body text for social-engineering phrase patterns.
    Returns one ContentMatch per distinct pattern that fires, with the exact matched text."""
    if not text:
        return []
    text = text[:MAX_BODY_CHARS]
    matches = []
    for category, patterns in _ALL_CATEGORIES.items():
        for pattern_id, rx in patterns.items():
            m = rx.search(text)
            if m:
                matches.append(ContentMatch(category, pattern_id, m.group(0)))
    return matches


_EXECUTIVE_TITLES = _rx(r"\b(?:CEO|CFO|COO|President|Chief\s+Executive|Chief\s+Financial|"
                        r"Managing\s+Director|Founder)\b")


def display_name_claims_executive_title(display_name: str | None) -> str | None:
    """Does a From display name claim an executive title (e.g. "John Smith, CEO")? A supporting
    signal for BEC/executive-impersonation, only meaningful combined with other indicators (an
    external sender, a domain mismatch, financial-pressure content)."""
    if not display_name:
        return None
    m = _EXECUTIVE_TITLES.search(display_name)
    return m.group(0) if m else None
