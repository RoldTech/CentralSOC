"""The phishing indicator engine: combines header analysis, SPF/DKIM/DMARC (Phase 2), domain
analysis and content analysis into a list of tagged, explainable PhishingIndicator objects.

Every indicator carries its own category and severity so services/verdict.py can score them
transparently — no indicator here decides the final verdict by itself (see verdict.py and the
spec's explicit warning against calling an email "malicious" from one weak signal).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from regexsoc.email_security.auth import AuthResult, DMARCEvaluation
from regexsoc.email_security.domains import (
    FREE_EMAIL_PROVIDERS, check_lookalike_domain, check_suspicious_subdomain, domain_shape_flags,
    is_punycode,
)
from regexsoc.email_security.models import ParsedHeaders
from regexsoc.email_security.textmatch import display_name_claims_executive_title, find_content_indicators
from regexsoc.models import Severity


@dataclass
class PhishingIndicator:
    indicator_id: str
    category: str  # "AUTHENTICATION" | "SENDER" | "DOMAIN" | "CONTENT" | "BEC"
    severity: str  # a Severity value
    description: str
    evidence: str

    def to_dict(self) -> dict:
        return {"indicator_id": self.indicator_id, "category": self.category,
               "severity": self.severity, "description": self.description, "evidence": self.evidence}


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].strip(">").strip() or None


def _sender_indicators(headers: ParsedHeaders, internal_domains: frozenset[str]) -> list[PhishingIndicator]:
    out: list[PhishingIndicator] = []
    from_addr = headers.from_[0] if headers.from_ else None
    from_domain = _domain_of(from_addr.address) if from_addr else None

    # Display-name spoofing: the display name itself contains a different email address than the
    # actual From address — a classic way to make a preview pane show a trusted-looking address.
    if from_addr and from_addr.display_name and "@" in from_addr.display_name:
        claimed = from_addr.display_name.split("@")[-1].strip().rstrip(">.")
        if claimed and from_domain and claimed.lower() != from_domain.lower():
            out.append(PhishingIndicator(
                "DISPLAY_NAME_SPOOFING", "SENDER", Severity.HIGH.value,
                "The display name contains a different address/domain than the actual sender.",
                f'display name "{from_addr.display_name}" vs actual address {from_addr.address}'))

    # Reply-To / Return-Path mismatches: replies or bounces would go somewhere other than From.
    for label, addrs in (("Reply-To", headers.reply_to),
                        ("Return-Path", [headers.return_path] if headers.return_path else [])):
        for addr in addrs:
            addr_value = addr.address if hasattr(addr, "address") else addr
            other_domain = _domain_of(addr_value)
            if from_domain and other_domain and other_domain.lower() != from_domain.lower():
                out.append(PhishingIndicator(
                    f"{label.upper().replace('-', '_')}_MISMATCH", "SENDER", Severity.MEDIUM.value,
                    f"{label} domain differs from the From domain.",
                    f"From domain {from_domain}, {label} domain {other_domain}"))
                break  # one report per header type is enough

    # A corporate-sounding display name sent from a free/consumer email provider.
    if from_addr and from_addr.display_name and from_domain in FREE_EMAIL_PROVIDERS:
        title = display_name_claims_executive_title(from_addr.display_name)
        looks_corporate = title is not None or any(
            w in from_addr.display_name.lower() for w in ("support", "security", "billing", "team", "service"))
        if looks_corporate:
            out.append(PhishingIndicator(
                "FREE_EMAIL_BRAND_IMPERSONATION", "SENDER", Severity.MEDIUM.value,
                "A corporate-sounding sender name is using a free consumer email provider.",
                f'"{from_addr.display_name}" <{from_addr.address}>'))

    # External sender whose display name claims an executive title (weak alone; BEC correlation
    # in _bec_indicators below escalates this when combined with financial-pressure content).
    if from_addr and internal_domains and from_domain and from_domain not in internal_domains:
        title = display_name_claims_executive_title(from_addr.display_name)
        if title:
            out.append(PhishingIndicator(
                "EXTERNAL_EXECUTIVE_IMPERSONATION", "SENDER", Severity.LOW.value,
                "An external sender's display name claims an executive title.",
                f'"{from_addr.display_name}" from external domain {from_domain}'))

    return out


def _domain_indicators(headers: ParsedHeaders) -> list[PhishingIndicator]:
    out: list[PhishingIndicator] = []
    from_addr = headers.from_[0] if headers.from_ else None
    domain = _domain_of(from_addr.address) if from_addr else None
    if not domain:
        return out

    if is_punycode(domain):
        out.append(PhishingIndicator(
            "PUNYCODE_DOMAIN", "DOMAIN", Severity.MEDIUM.value,
            "The sender domain uses raw punycode, which can hide look-alike characters.",
            domain))

    lookalike = check_lookalike_domain(domain)
    if lookalike:
        out.append(PhishingIndicator(
            "LOOKALIKE_DOMAIN", "DOMAIN", Severity.HIGH.value,
            f"The sender domain resembles the brand \"{lookalike.brand}\" ({lookalike.reason}).",
            domain))

    subdomain_brand = check_suspicious_subdomain(domain)
    if subdomain_brand:
        out.append(PhishingIndicator(
            "SUSPICIOUS_SUBDOMAIN", "DOMAIN", Severity.HIGH.value,
            f"A brand name (\"{subdomain_brand}\") appears in the hostname ahead of the real "
            "organizational domain.", domain))

    for flag in domain_shape_flags(domain):
        out.append(PhishingIndicator("DOMAIN_SHAPE_" + flag.split()[0].upper(), "DOMAIN",
                                     Severity.LOW.value, flag.capitalize() + ".", domain))
    return out


def _content_indicators(plain_body: str | None, html_body: str | None) -> list[PhishingIndicator]:
    out: list[PhishingIndicator] = []
    severity_by_category = {"URGENCY": Severity.MEDIUM.value, "CREDENTIAL_HARVESTING": Severity.MEDIUM.value,
                            "FINANCIAL_PRESSURE": Severity.MEDIUM.value, "MFA_PRESSURE": Severity.LOW.value}
    for text in (plain_body, html_body):
        for match in find_content_indicators(text):
            out.append(PhishingIndicator(
                match.pattern_id.upper(), "CONTENT", severity_by_category.get(match.category, Severity.LOW.value),
                f"{match.category.replace('_', ' ').title()} language detected.", match.evidence))
    # De-duplicate by indicator_id alone (not exact evidence text): the same phrase pattern firing
    # in both the plain-text and HTML alternative of one message is the same underlying signal,
    # not two independent ones — counting it twice would inflate the score for no real reason.
    seen: set[str] = set()
    deduped = []
    for ind in out:
        if ind.indicator_id not in seen:
            seen.add(ind.indicator_id)
            deduped.append(ind)
    return deduped


def _bec_indicators(indicators: list[PhishingIndicator]) -> list[PhishingIndicator]:
    """Correlation, not keyword matching: only fires when several independent signals line up —
    per the spec, "Generate an alert when multiple indicators correlate." """
    by_id = {i.indicator_id for i in indicators}
    financial = {"WIRE_TRANSFER", "GIFT_CARD_REQUEST", "BANK_ACCOUNT_CHANGE", "ROUTING_NUMBER",
                "URGENT_PAYMENT", "INVOICE_OVERDUE"} & by_id
    sender_risk = {"DISPLAY_NAME_SPOOFING", "REPLY_TO_MISMATCH", "RETURN_PATH_MISMATCH",
                  "LOOKALIKE_DOMAIN", "EXTERNAL_EXECUTIVE_IMPERSONATION",
                  "FREE_EMAIL_BRAND_IMPERSONATION"} & by_id
    if financial and sender_risk:
        return [PhishingIndicator(
            "BEC_CORRELATION", "BEC", Severity.CRITICAL.value,
            "Financial-pressure content combined with sender-authenticity problems — a strong "
            "Business Email Compromise pattern, not just one weak signal.",
            f"financial: {', '.join(sorted(financial))}; sender: {', '.join(sorted(sender_risk))}")]
    return []


def _authentication_indicators(dmarc: DMARCEvaluation) -> list[PhishingIndicator]:
    if dmarc.result == AuthResult.FAIL:
        return [PhishingIndicator("DMARC_FAILURE", "AUTHENTICATION", Severity.HIGH.value,
                                  "The message fails DMARC (neither SPF nor DKIM both authenticated and aligned).",
                                  dmarc.reason)]
    if dmarc.result == AuthResult.NONE:
        return [PhishingIndicator("NO_AUTHENTICATION_INFO", "AUTHENTICATION", Severity.LOW.value,
                                  "No SPF or DKIM authentication information was present to evaluate.", "")]
    return []


def collect_indicators(headers: ParsedHeaders, plain_body: str | None, html_body: str | None,
                       dmarc: DMARCEvaluation, internal_domains: frozenset[str] = frozenset()
                       ) -> list[PhishingIndicator]:
    """Run every check and return the combined, de-duplicated list of indicators."""
    indicators: list[PhishingIndicator] = []
    indicators += _authentication_indicators(dmarc)
    indicators += _sender_indicators(headers, internal_domains)
    indicators += _domain_indicators(headers)
    indicators += _content_indicators(plain_body, html_body)
    indicators += _bec_indicators(indicators)
    return indicators
