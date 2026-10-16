"""SPF / DKIM / DMARC evaluation.

Evaluates the authentication information a message already carries (Authentication-Results,
Received-SPF, DKIM-Signature headers) — this is "reported by the receiving mail server," not
independent cryptographic verification. RegexSOC does not perform DNS-based SPF lookups or
cryptographic DKIM verification: doing the former safely needs careful resolver hardening against
SSRF/DNS-exfiltration risk (attacker-controlled domains), and the latter needs a dedicated crypto
library. Both are documented here as deliberately out of scope for this phase, not silently skipped.

DMARC alignment logic follows RFC 7489 section 3.1: DMARC passes when at least one of SPF or DKIM
BOTH authenticates AND aligns with the RFC5322.From domain — this is an OR across mechanisms, never
an AND, and alignment is evaluated independently from the domain's DMARC policy (a "reject" policy
does not, by itself, mean this message failed DMARC).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from regexsoc.email_security.models import ParsedHeaders

# --------------------------------------------------------------------------- shared enums
class AuthResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    TEMPERROR = "TEMPERROR"
    PERMERROR = "PERMERROR"
    UNKNOWN = "UNKNOWN"


class AlignmentMode(str, Enum):
    STRICT = "STRICT"
    RELAXED = "RELAXED"


class Alignment(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"  # not enough information to compare (a domain is missing)


_SPF_RESULTS = {r.value.lower() for r in AuthResult}
_AUTH_RESULTS_TOKEN = re.compile(r"\b(spf|dkim|dmarc)=([a-zA-Z]+)")
_IDENTITY_TOKEN = re.compile(r"\b(smtp\.mailfrom|header\.from|header\.d|header\.i|header\.s)=([^\s;()]+)")
_RECEIVED_SPF_RESULT = re.compile(r"^\s*([a-zA-Z]+)")
_RECEIVED_SPF_ENVELOPE = re.compile(r"envelope-from=([^\s;]+)")
_RECEIVED_SPF_DOMAIN_OF = re.compile(r"domain of ([^\s@]+)@?([^\s;]*)")


# --------------------------------------------------------------------------- domain helpers
# A pragmatic, small set of common two-label public suffixes, NOT the full IANA Public Suffix
# List. Good enough for the common real-world cases (.co.uk, .com.au, ...); wrong for anything
# outside this list. For authoritative results, integrate the `tldextract` package or PSL data.
_KNOWN_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in",
    "co.id", "co.il", "co.th", "com.au", "net.au", "org.au", "com.br", "com.mx", "com.sg",
    "com.tw", "com.hk", "com.ph", "com.cn", "com.tr", "com.ar",
})


def organizational_domain(domain: str) -> str:
    """A pragmatic approximation of the "organizational domain" (RFC 7489 section 3.2): the
    registrable domain used for relaxed alignment. Known limitation: only recognizes the common
    two-label public suffixes above; anything else falls back to a naive last-two-labels rule,
    which is wrong for less common multi-part suffixes not in that list."""
    labels = domain.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _KNOWN_TWO_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def check_alignment(domain_a: str | None, domain_b: str | None, mode: AlignmentMode) -> Alignment:
    """Compare two domains for DMARC alignment purposes."""
    if not domain_a or not domain_b:
        return Alignment.UNKNOWN
    a, b = domain_a.lower().strip("."), domain_b.lower().strip(".")
    if mode == AlignmentMode.STRICT:
        return Alignment.PASS if a == b else Alignment.FAIL
    return Alignment.PASS if organizational_domain(a) == organizational_domain(b) else Alignment.FAIL


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].strip(">").strip() or None


def _to_auth_result(text: str | None) -> AuthResult:
    if not text:
        return AuthResult.NONE
    try:
        return AuthResult(text.strip().upper())
    except ValueError:
        return AuthResult.UNKNOWN


def _header_from_domain(headers: ParsedHeaders) -> str | None:
    if not headers.from_:
        return None
    return _domain_of(headers.from_[0].address)


# --------------------------------------------------------------------------- Authentication-Results parsing
@dataclass
class AuthResultsEntry:
    """One method's result parsed out of an Authentication-Results header, e.g. one ``spf=pass``."""

    method: str  # "spf" | "dkim" | "dmarc"
    result: AuthResult
    identities: dict[str, str] = field(default_factory=dict)  # e.g. {"smtp.mailfrom": "...", "header.d": "..."}


def parse_authentication_results(raw: str) -> list[AuthResultsEntry]:
    """Extract every spf=/dkim=/dmarc= result and its nearby identity tags from one raw
    Authentication-Results header value. Tolerant of malformed input: unmatched text is ignored
    rather than raising. A header can report several methods (and DKIM can appear more than once
    for multiple signatures), so this always returns a list."""
    entries: list[AuthResultsEntry] = []
    tokens = list(_AUTH_RESULTS_TOKEN.finditer(raw))
    for i, match in enumerate(tokens):
        method, result = match.group(1).lower(), match.group(2)
        segment_end = tokens[i + 1].start() if i + 1 < len(tokens) else len(raw)
        segment = raw[match.end():segment_end]
        identities = {tag: value.strip('"') for tag, value in _IDENTITY_TOKEN.findall(segment)}
        entries.append(AuthResultsEntry(method=method, result=_to_auth_result(result), identities=identities))
    return entries


def parse_received_spf(raw: str) -> dict:
    """Extract the result and envelope-from domain from a raw Received-SPF header value."""
    result_match = _RECEIVED_SPF_RESULT.match(raw)
    result = result_match.group(1) if result_match else None
    envelope = None
    if m := _RECEIVED_SPF_ENVELOPE.search(raw):
        envelope = m.group(1)
    elif m := _RECEIVED_SPF_DOMAIN_OF.search(raw):
        envelope = f"{m.group(1)}@{m.group(2)}" if m.group(2) else m.group(1)
    return {"result": result, "envelope_from": envelope}


def parse_dkim_signature(raw: str) -> dict[str, str]:
    """Parse a raw DKIM-Signature header value into its tag=value pairs (RFC 6376 section 3.5).
    Values are taken up to the next unescaped ';' — good enough for the tags we use (d, s, a, c,
    h, bh, b, i); does not attempt full RFC 6376 folding-whitespace normalization."""
    tags: dict[str, str] = {}
    for segment in raw.split(";"):
        if "=" not in segment:
            continue
        tag, _, value = segment.strip().partition("=")
        tag = tag.strip()
        if tag:
            tags[tag] = value.strip()
    return tags


# --------------------------------------------------------------------------- SPF
@dataclass
class SPFEvaluation:
    result: AuthResult
    source: str  # "authentication-results" | "received-spf" | "not reported"
    envelope_from_domain: str | None
    header_from_domain: str | None
    alignment: Alignment
    alignment_mode: AlignmentMode
    raw: str | None

    def to_dict(self) -> dict:
        return {"result": self.result.value, "source": self.source,
               "envelope_from_domain": self.envelope_from_domain,
               "header_from_domain": self.header_from_domain, "alignment": self.alignment.value,
               "alignment_mode": self.alignment_mode.value, "raw": self.raw}


def evaluate_spf(headers: ParsedHeaders, alignment_mode: AlignmentMode = AlignmentMode.RELAXED) -> SPFEvaluation:
    header_from = _header_from_domain(headers)

    for raw in headers.authentication_results:
        for entry in parse_authentication_results(raw):
            if entry.method == "spf":
                envelope_domain = _domain_of(entry.identities.get("smtp.mailfrom"))
                alignment = check_alignment(envelope_domain, header_from, alignment_mode)
                return SPFEvaluation(entry.result, "authentication-results", envelope_domain,
                                     header_from, alignment, alignment_mode, raw)

    for raw in headers.received_spf:
        parsed = parse_received_spf(raw)
        result = _to_auth_result(parsed["result"])
        envelope_domain = _domain_of(parsed["envelope_from"])
        alignment = check_alignment(envelope_domain, header_from, alignment_mode)
        return SPFEvaluation(result, "received-spf", envelope_domain, header_from, alignment,
                             alignment_mode, raw)

    return SPFEvaluation(AuthResult.NONE, "not reported", None, header_from, Alignment.UNKNOWN,
                         alignment_mode, None)


# --------------------------------------------------------------------------- DKIM
@dataclass
class DKIMSignatureEvaluation:
    signing_domain: str | None
    selector: str | None
    result: AuthResult
    verified_by: str  # "authentication-results" | "signature present, not independently verified"
    alignment: Alignment
    alignment_mode: AlignmentMode
    raw: str


@dataclass
class DKIMEvaluation:
    signatures: list[DKIMSignatureEvaluation]

    @property
    def result(self) -> AuthResult:
        """NONE if there is no signature at all (including a bare "dkim=none" report with nothing
        actually signed); otherwise PASS only if at least one signature is both authenticated and
        aligned (RFC 7489: DKIM can pass DMARC via any one signature); FAIL if something was
        actually attempted (a signature existed, or a non-NONE result was reported) but none
        both authenticated and aligned."""
        if not self.signatures or all(s.result == AuthResult.NONE for s in self.signatures):
            return AuthResult.NONE
        if self.any_aligned_pass:
            return AuthResult.PASS
        return AuthResult.FAIL

    @property
    def any_aligned_pass(self) -> bool:
        return any(s.result == AuthResult.PASS and s.alignment == Alignment.PASS for s in self.signatures)

    def to_dict(self) -> dict:
        return {"result": self.result.value, "signatures": [
            {"signing_domain": s.signing_domain, "selector": s.selector, "result": s.result.value,
             "verified_by": s.verified_by, "alignment": s.alignment.value,
             "alignment_mode": s.alignment_mode.value} for s in self.signatures
        ]}


def evaluate_dkim(headers: ParsedHeaders, alignment_mode: AlignmentMode = AlignmentMode.RELAXED) -> DKIMEvaluation:
    header_from = _header_from_domain(headers)

    # Every dkim= result Authentication-Results reported, keyed by signing domain (header.d),
    # so a per-signature match can look up whether that specific signature was authenticated.
    reported: dict[str | None, AuthResult] = {}
    for raw in headers.authentication_results:
        for entry in parse_authentication_results(raw):
            if entry.method == "dkim":
                reported[entry.identities.get("header.d")] = entry.result

    signatures = []
    for raw in headers.dkim_signature:
        tags = parse_dkim_signature(raw)
        signing_domain = tags.get("d")
        if signing_domain in reported:
            result, verified_by = reported[signing_domain], "authentication-results"
        elif not reported:
            result, verified_by = AuthResult.UNKNOWN, "signature present, not independently verified"
        else:
            result, verified_by = AuthResult.UNKNOWN, "signature present, not independently verified"
        alignment = check_alignment(signing_domain, header_from, alignment_mode)
        signatures.append(DKIMSignatureEvaluation(signing_domain, tags.get("s"), result, verified_by,
                                                   alignment, alignment_mode, raw))

    # A dkim= result with no matching DKIM-Signature header still counts (the signature header
    # may have been stripped in transit); represent it with whatever domain it reported.
    for domain, result in reported.items():
        if not any(s.signing_domain == domain for s in signatures):
            alignment = check_alignment(domain, header_from, alignment_mode)
            signatures.append(DKIMSignatureEvaluation(domain, None, result, "authentication-results",
                                                       alignment, alignment_mode, raw=""))

    return DKIMEvaluation(signatures)


# --------------------------------------------------------------------------- DMARC policy (parsing only — no DNS)
@dataclass
class DMARCPolicy:
    domain: str
    p: str | None
    sp: str | None
    pct: int
    adkim: AlignmentMode
    aspf: AlignmentMode
    rua: list[str]
    ruf: list[str]
    raw: str

    def to_dict(self) -> dict:
        return {"domain": self.domain, "p": self.p, "sp": self.sp, "pct": self.pct,
               "adkim": self.adkim.value, "aspf": self.aspf.value, "rua": self.rua, "ruf": self.ruf}


def parse_dmarc_record(domain: str, raw: str) -> DMARCPolicy:
    """Parse a raw DMARC TXT record string (e.g. ``v=DMARC1; p=reject; adkim=r; aspf=s``).
    Pure parsing — this does not fetch the record; see DMARCPolicyProvider for that boundary."""
    tags = parse_dkim_signature(raw)  # same tag=value; grammar as DKIM-Signature, reused as-is
    pct_raw = tags.get("pct", "100")
    try:
        pct = max(0, min(100, int(pct_raw)))
    except ValueError:
        pct = 100
    mode = lambda t: AlignmentMode.STRICT if tags.get(t, "r").lower() == "s" else AlignmentMode.RELAXED
    return DMARCPolicy(
        domain=domain, p=tags.get("p"), sp=tags.get("sp"), pct=pct, adkim=mode("adkim"), aspf=mode("aspf"),
        rua=[a.strip() for a in tags.get("rua", "").split(",") if a.strip()],
        ruf=[a.strip() for a in tags.get("ruf", "").split(",") if a.strip()], raw=raw,
    )


class DMARCPolicyProvider:
    """Abstraction boundary for fetching a domain's DMARC policy (normally a DNS TXT lookup at
    ``_dmarc.<organizational-domain>``). RegexSOC does not perform that DNS lookup itself — doing
    so safely against attacker-controlled domains needs resolver hardening (timeouts, rate limits,
    blocking internal/link-local targets) that is out of scope for this phase. The default
    implementation always reports "unavailable", so DMARC evaluation works correctly without any
    network access; a real resolver-backed provider can be substituted later without changing any
    evaluation logic, or an analyst can supply a known record via StaticDMARCPolicyProvider.
    """

    def get_policy(self, domain: str) -> DMARCPolicy | None:
        raise NotImplementedError


class NullDMARCPolicyProvider(DMARCPolicyProvider):
    def get_policy(self, domain: str) -> DMARCPolicy | None:
        return None


class StaticDMARCPolicyProvider(DMARCPolicyProvider):
    """For tests, or for an analyst who already knows/has fetched a domain's DMARC record."""

    def __init__(self, records: dict[str, str]) -> None:
        self._records = records

    def get_policy(self, domain: str) -> DMARCPolicy | None:
        raw = self._records.get(domain)
        return parse_dmarc_record(domain, raw) if raw else None


# --------------------------------------------------------------------------- DMARC evaluation
@dataclass
class DMARCEvaluation:
    result: AuthResult  # PASS | FAIL | NONE
    reason: str
    header_from_domain: str | None
    spf: SPFEvaluation
    dkim: DKIMEvaluation
    policy: DMARCPolicy | None
    reported_result: AuthResult | None  # what Authentication-Results itself said, if present — for comparison only

    def to_dict(self) -> dict:
        return {"result": self.result.value, "reason": self.reason,
               "header_from_domain": self.header_from_domain, "spf": self.spf.to_dict(),
               "dkim": self.dkim.to_dict(), "policy": self.policy.to_dict() if self.policy else None,
               "reported_result": self.reported_result.value if self.reported_result else None}


def _reported_dmarc(headers: ParsedHeaders) -> AuthResult | None:
    for raw in headers.authentication_results:
        for entry in parse_authentication_results(raw):
            if entry.method == "dmarc":
                return entry.result
    return None


def evaluate_dmarc(headers: ParsedHeaders, policy_provider: DMARCPolicyProvider | None = None) -> DMARCEvaluation:
    """Independently compute the DMARC verdict from SPF/DKIM authentication + alignment (RFC 7489
    section 3.1), rather than trusting a self-reported ``dmarc=`` result. That reported value (if
    present) is still surfaced separately, for comparison, via ``reported_result``.
    """
    header_from = _header_from_domain(headers)
    policy_provider = policy_provider or NullDMARCPolicyProvider()
    policy = policy_provider.get_policy(organizational_domain(header_from)) if header_from else None

    aspf_mode = policy.aspf if policy else AlignmentMode.RELAXED
    adkim_mode = policy.adkim if policy else AlignmentMode.RELAXED
    spf = evaluate_spf(headers, aspf_mode)
    dkim = evaluate_dkim(headers, adkim_mode)
    reported = _reported_dmarc(headers)

    spf_ok = spf.result == AuthResult.PASS and spf.alignment == Alignment.PASS
    dkim_ok = dkim.any_aligned_pass

    if not header_from:
        return DMARCEvaluation(AuthResult.UNKNOWN, "no RFC5322.From header to evaluate alignment against",
                               None, spf, dkim, policy, reported)
    if spf.result == AuthResult.NONE and dkim.result == AuthResult.NONE:
        return DMARCEvaluation(AuthResult.NONE, "neither SPF nor DKIM authentication information was present",
                               header_from, spf, dkim, policy, reported)
    if spf_ok or dkim_ok:
        via = []
        if spf_ok:
            via.append(f"SPF authenticated and aligned ({spf.alignment_mode.value.lower()}) with {header_from}")
        if dkim_ok:
            via.append(f"DKIM authenticated and aligned ({adkim_mode.value.lower()}) with {header_from}")
        return DMARCEvaluation(AuthResult.PASS, "; ".join(via), header_from, spf, dkim, policy, reported)

    reasons = []
    if spf.result != AuthResult.PASS:
        reasons.append(f"SPF did not authenticate (result: {spf.result.value})")
    elif spf.alignment != Alignment.PASS:
        reasons.append(f"SPF authenticated but is not aligned with {header_from}")
    if dkim.result == AuthResult.NONE:
        reasons.append("no DKIM signature was present")
    elif not dkim.any_aligned_pass:
        reasons.append(f"no DKIM signature both authenticated and aligned with {header_from}")
    return DMARCEvaluation(AuthResult.FAIL, "; ".join(reasons), header_from, spf, dkim, policy, reported)
