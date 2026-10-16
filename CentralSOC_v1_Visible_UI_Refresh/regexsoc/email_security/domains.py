"""Domain analysis: typosquatting, homoglyphs, punycode, lookalike domains.

Pure string/heuristic analysis — no DNS, no external reputation lookups (see auth.py's
DMARCPolicyProvider for why that boundary exists). This is a best-effort heuristic against a small
built-in brand list, not a comprehensive brand-protection product: it will have both false
positives and false negatives. See docs/email-security.md for known limitations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from regexsoc.email_security.auth import organizational_domain

# A small, illustrative set of commonly-impersonated brands, not an exhaustive list. An analyst
# can pass their own via the `brands` parameter of check_lookalike_domain.
DEFAULT_BRANDS = (
    "paypal", "microsoft", "apple", "google", "amazon", "netflix", "bankofamerica", "wellsfargo",
    "chase", "dhl", "fedex", "ups", "irs", "docusign", "adobe", "dropbox", "linkedin", "facebook",
    "instagram", "coinbase", "binance", "outlook", "office365", "americanexpress", "citibank",
)

# Common free/consumer email providers — used only to flag a mismatch between a corporate-sounding
# display name and a personal-email sending address, never to flag the providers themselves.
FREE_EMAIL_PROVIDERS = frozenset({
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com", "mail.com",
    "protonmail.com", "gmx.com", "yandex.com", "zoho.com",
})

_MULTI_CHAR_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_SINGLE_CHAR_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a"})


def normalize_homoglyphs(label: str) -> str:
    """Fold common look-alike character substitutions to their canonical form, so
    "micr0s0ft" and "microsoft" compare equal. Order matters: multi-character substitutions are
    applied before single-character ones (e.g. "rn" -> "m" before any digit folding)."""
    text = label.lower()
    for pattern, replacement in _MULTI_CHAR_HOMOGLYPHS:
        text = text.replace(pattern, replacement)
    return text.translate(_SINGLE_CHAR_HOMOGLYPHS)


def levenshtein(a: str, b: str) -> int:
    """Standard edit distance (insertions/deletions/substitutions), O(len(a) * len(b)). Both
    inputs here are always short (domain labels, brand names), so this is never a performance
    concern — unlike a regex, there is no backtracking risk at all."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
        previous = current
    return previous[-1]


def is_punycode(domain: str) -> bool:
    """True if any label of the domain is raw punycode (an encoded internationalized domain
    name) — these can hide homoglyph attacks using non-Latin lookalike characters."""
    return any(label.lower().startswith("xn--") for label in domain.split("."))


def domain_shape_flags(domain: str) -> list[str]:
    """Weak, structural signals: excessive length, high digit density, excessive hyphens. Each is
    common enough in legitimate domains that these are only ever LOW-severity supporting signals,
    never used alone to call something malicious."""
    flags = []
    primary_label = domain.split(".")[0]
    if len(domain) > 40:
        flags.append("unusually long domain")
    if primary_label and sum(c.isdigit() for c in primary_label) / len(primary_label) > 0.3:
        flags.append("high digit density in domain label")
    if primary_label.count("-") >= 3:
        flags.append("multiple hyphens in domain label")
    return flags


@dataclass
class LookalikeMatch:
    brand: str
    matched_label: str
    distance: int
    reason: str  # "exact_substring" | "edit_distance" | "homoglyph"


def check_lookalike_domain(domain: str, brands: tuple[str, ...] = DEFAULT_BRANDS) -> LookalikeMatch | None:
    """Check whether ``domain`` looks like it is impersonating one of ``brands``.

    Never flags the brand's own legitimate domain (exact match to "<brand>.<tld>" is skipped).
    Checked against the whole primary label AND each hyphen-separated segment of it (so
    "micros0ft-security.com" is caught via its "micros0ft" segment, not just the full label) —
    three checks per candidate, in order of confidence: (1) a brand name as a substring, (2) small
    edit distance (typosquatting), (3) the homoglyph-normalized form matching a brand (e.g.
    "micr0s0ft" -> "microsoft").
    """
    org_domain = organizational_domain(domain)
    primary_label = org_domain.split(".")[0]
    if not primary_label:
        return None
    candidates = [primary_label] + [seg for seg in primary_label.split("-") if seg]

    for brand in brands:
        if primary_label == brand:
            continue  # the brand's own legitimate domain

        for candidate in candidates:
            if candidate == brand:
                continue  # a hyphen segment that IS the brand name is not itself suspicious

            # Substring and edit-distance checks are only meaningful for brands longer than 3
            # characters: a short abbreviation like "ups" or "irs" is a substring of many
            # unrelated words ("upstairs", "first") purely by chance. The homoglyph check below
            # is exempt from this guard since it requires the WHOLE segment to match after
            # normalization, which does not have the same false-positive risk.
            if len(brand) > 3:
                if brand in candidate:
                    return LookalikeMatch(brand, primary_label, 0, "exact_substring")
                distance = levenshtein(candidate, brand)
                if 0 < distance <= 2:
                    return LookalikeMatch(brand, primary_label, distance, "edit_distance")

            normalized = normalize_homoglyphs(candidate)
            if normalized == brand and candidate != brand:
                return LookalikeMatch(brand, primary_label, 0, "homoglyph")

    return None


def check_suspicious_subdomain(domain: str, brands: tuple[str, ...] = DEFAULT_BRANDS) -> str | None:
    """Flag a brand name appearing as a non-organizational subdomain of an unrelated domain, e.g.
    "paypal.com.attacker-verify.net" — the organizational domain is attacker-verify.net, but a
    brand name shows up earlier in the hostname to look convincing at a glance."""
    org_domain = organizational_domain(domain)
    if domain == org_domain:
        return None  # no subdomain at all
    prefix_labels = domain[: -len(org_domain)].rstrip(".").split(".")
    for label in prefix_labels:
        for brand in brands:
            if brand in label.lower():
                return brand
    return None
