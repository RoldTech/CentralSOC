"""SPF / DKIM / DMARC evaluation tests (Phase 2).

Every DMARC test here exists because the spec this module follows explicitly warns against a
specific wrong implementation (e.g. "do not require both SPF and DKIM to pass" — tested directly
by test_dmarc_passes_via_spf_only_when_dkim_fails and its mirror).
"""

import pytest

from regexsoc.email_security.auth import (
    Alignment, AlignmentMode, AuthResult, DMARCPolicyProvider, StaticDMARCPolicyProvider,
    check_alignment, evaluate_dkim, evaluate_dmarc, evaluate_spf, organizational_domain,
    parse_authentication_results, parse_dkim_signature, parse_dmarc_record, parse_received_spf,
)
from regexsoc.email_security.parser import parse_email


def msg(from_="alice@example.com", extra_headers=b"", body=b"body"):
    return parse_email(f"From: {from_}\r\n".encode() + extra_headers + b"\r\n" + body).headers


# --------------------------------------------------------------------------- organizational_domain / alignment
@pytest.mark.parametrize("domain,expected", [
    ("example.com", "example.com"),
    ("mail.example.com", "example.com"),
    ("a.b.mail.example.com", "example.com"),
    ("example.co.uk", "example.co.uk"),
    ("mail.example.co.uk", "example.co.uk"),
    ("co.uk", "co.uk"),
])
def test_organizational_domain(domain, expected):
    assert organizational_domain(domain) == expected


def test_relaxed_alignment_matches_subdomains_of_same_org_domain():
    assert check_alignment("mail.example.com", "example.com", AlignmentMode.RELAXED) == Alignment.PASS


def test_relaxed_alignment_does_not_match_different_org_domains_even_same_tld():
    assert check_alignment("mail.evil-example.com", "example.com", AlignmentMode.RELAXED) == Alignment.FAIL


def test_strict_alignment_requires_exact_match():
    assert check_alignment("mail.example.com", "example.com", AlignmentMode.STRICT) == Alignment.FAIL
    assert check_alignment("example.com", "example.com", AlignmentMode.STRICT) == Alignment.PASS


def test_alignment_unknown_when_a_domain_is_missing():
    assert check_alignment(None, "example.com", AlignmentMode.RELAXED) == Alignment.UNKNOWN
    assert check_alignment("example.com", None, AlignmentMode.RELAXED) == Alignment.UNKNOWN


def test_co_uk_style_relaxed_alignment_does_not_falsely_align_unrelated_domains():
    # Both reduce to "co.uk" under a naive last-two-labels rule; the known-suffix list prevents
    # this from being treated as an aligned match.
    assert check_alignment("mail.legit-bank.co.uk", "evil-attacker.co.uk", AlignmentMode.RELAXED) == Alignment.FAIL


# --------------------------------------------------------------------------- Authentication-Results parsing
def test_parse_authentication_results_extracts_all_methods():
    raw = ("mx.google.com; spf=pass smtp.mailfrom=news@example.com; "
          "dkim=pass header.d=example.com header.s=sel1; dmarc=pass header.from=example.com")
    entries = parse_authentication_results(raw)
    methods = {e.method: e.result for e in entries}
    assert methods == {"spf": AuthResult.PASS, "dkim": AuthResult.PASS, "dmarc": AuthResult.PASS}
    spf_entry = next(e for e in entries if e.method == "spf")
    assert spf_entry.identities["smtp.mailfrom"] == "news@example.com"
    dkim_entry = next(e for e in entries if e.method == "dkim")
    assert dkim_entry.identities["header.d"] == "example.com"


def test_parse_authentication_results_handles_multiple_dkim_results():
    raw = "mx.a.com; dkim=pass header.d=example.com; dkim=fail header.d=other.com"
    entries = [e for e in parse_authentication_results(raw) if e.method == "dkim"]
    assert len(entries) == 2
    assert entries[0].identities["header.d"] == "example.com" and entries[0].result == AuthResult.PASS
    assert entries[1].identities["header.d"] == "other.com" and entries[1].result == AuthResult.FAIL


@pytest.mark.parametrize("garbage", ["", "not an auth results header at all", "\x00\xff;;;==="],
                         ids=["empty", "not_auth_results", "control_chars"])
def test_parse_authentication_results_never_raises_on_garbage(garbage):
    parse_authentication_results(garbage)  # must not raise


def test_parse_authentication_results_never_raises_on_very_long_input():
    """Separate, non-parametrized test: parametrizing directly with a 40,000-character value made
    pytest embed the whole string into its own PYTEST_CURRENT_TEST environment variable (used for
    crash reporting), which exceeds Windows' ~32KB environment-variable limit and crashes pytest
    itself during test setup/teardown — a real bug, but in how this test was written, not in
    RegexSOC's parsing code. Caught by an actual pytest run on Windows; not something my sandbox's
    stand-in test runner could have caught, since it doesn't replicate pytest's own internals."""
    parse_authentication_results("spf=" * 10000)  # must not raise, and must complete quickly (no ReDoS)


def test_parse_received_spf_extracts_result_and_envelope():
    raw = ("pass (example.org: domain of news@example.com designates 203.0.113.10 as permitted sender) "
          "client-ip=203.0.113.10; envelope-from=news@example.com; helo=mail.example.com;")
    parsed = parse_received_spf(raw)
    assert parsed["result"] == "pass" and parsed["envelope_from"] == "news@example.com"


def test_parse_received_spf_falls_back_to_domain_of_pattern_when_no_envelope_from_tag():
    raw = "fail (example.org: domain of attacker@evil.net does not designate 198.51.100.1 as permitted sender)"
    parsed = parse_received_spf(raw)
    assert parsed["result"] == "fail" and parsed["envelope_from"] == "attacker@evil.net"


def test_parse_dkim_signature_tags():
    raw = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector1; h=from:to:subject; bh=abc=; b=def="
    tags = parse_dkim_signature(raw)
    assert tags["d"] == "example.com" and tags["s"] == "selector1" and tags["a"] == "rsa-sha256"


# --------------------------------------------------------------------------- SPF
def test_spf_pass_and_aligned_from_authentication_results():
    h = msg(extra_headers=b"Authentication-Results: mx.a.com; spf=pass smtp.mailfrom=alice@example.com\r\n")
    r = evaluate_spf(h)
    assert r.result == AuthResult.PASS and r.alignment == Alignment.PASS and r.source == "authentication-results"


def test_spf_pass_but_not_aligned_envelope_domain_differs():
    h = msg(extra_headers=b"Authentication-Results: mx.a.com; spf=pass smtp.mailfrom=news@othersender.com\r\n")
    r = evaluate_spf(h)
    assert r.result == AuthResult.PASS and r.alignment == Alignment.FAIL


def test_spf_falls_back_to_received_spf_when_no_authentication_results():
    h = msg(extra_headers=b"Received-SPF: pass (x) envelope-from=alice@example.com;\r\n")
    r = evaluate_spf(h)
    assert r.result == AuthResult.PASS and r.source == "received-spf" and r.alignment == Alignment.PASS


def test_spf_not_reported_at_all():
    r = evaluate_spf(msg())
    assert r.result == AuthResult.NONE and r.source == "not reported" and r.alignment == Alignment.UNKNOWN


@pytest.mark.parametrize("result_word,expected", [
    ("pass", AuthResult.PASS), ("fail", AuthResult.FAIL), ("softfail", AuthResult.SOFTFAIL),
    ("neutral", AuthResult.NEUTRAL), ("temperror", AuthResult.TEMPERROR),
    ("permerror", AuthResult.PERMERROR), ("bogus_word", AuthResult.UNKNOWN),
])
def test_spf_result_words(result_word, expected):
    h = msg(extra_headers=f"Authentication-Results: mx.a.com; spf={result_word} smtp.mailfrom=a@example.com\r\n".encode())
    assert evaluate_spf(h).result == expected


# --------------------------------------------------------------------------- DKIM
def test_dkim_pass_and_aligned():
    h = msg(extra_headers=(
        b"Authentication-Results: mx.a.com; dkim=pass header.d=example.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; b=abc\r\n"))
    r = evaluate_dkim(h)
    assert r.result == AuthResult.PASS and r.any_aligned_pass
    assert r.signatures[0].alignment == Alignment.PASS


def test_dkim_signature_present_but_not_independently_verified_when_auth_results_silent():
    h = msg(extra_headers=b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; b=abc\r\n")
    r = evaluate_dkim(h)
    assert r.signatures[0].verified_by == "signature present, not independently verified"
    assert r.signatures[0].result != AuthResult.PASS  # never claim PASS on signature presence alone


def test_dkim_none_when_no_signature_and_no_report():
    r = evaluate_dkim(msg())
    assert r.result == AuthResult.NONE and r.signatures == []


def test_dkim_reported_none_with_no_signature_header_is_none_not_fail():
    """Regression test: a bare 'dkim=none' report (no actual signature) must yield NONE, not FAIL —
    caught during manual testing before this suite existed."""
    h = msg(extra_headers=b"Authentication-Results: mx.a.com; spf=fail smtp.mailfrom=x@evil.com; dkim=none\r\n")
    r = evaluate_dkim(h)
    assert r.result == AuthResult.NONE


def test_dkim_authenticated_but_wrong_domain_does_not_count_as_aligned_pass():
    h = msg(extra_headers=(
        b"Authentication-Results: mx.a.com; dkim=pass header.d=totally-different.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=totally-different.com; s=sel1; b=abc\r\n"))
    r = evaluate_dkim(h)
    assert not r.any_aligned_pass and r.result == AuthResult.FAIL


def test_multiple_dkim_signatures_any_one_aligned_pass_is_enough():
    h = msg(extra_headers=(
        b"Authentication-Results: mx.a.com; dkim=fail header.d=other.com; dkim=pass header.d=example.com\r\n"
        b"DKIM-Signature: v=1; d=other.com; s=s1; b=x\r\n"
        b"DKIM-Signature: v=1; d=example.com; s=s2; b=y\r\n"))
    r = evaluate_dkim(h)
    assert r.result == AuthResult.PASS and len(r.signatures) == 2


# --------------------------------------------------------------------------- DMARC: the critical OR logic
def test_dmarc_passes_via_dkim_only_when_spf_fails():
    h = msg(extra_headers=(
        b"Authentication-Results: mx.a.com; spf=fail smtp.mailfrom=x@attacker.net; dkim=pass header.d=example.com\r\n"
        b"DKIM-Signature: v=1; d=example.com; s=s1; b=x\r\n"))
    d = evaluate_dmarc(h)
    assert d.result == AuthResult.PASS and "DKIM" in d.reason


def test_dmarc_passes_via_spf_only_when_dkim_fails():
    h = msg(extra_headers=(
        b"Authentication-Results: mx.a.com; spf=pass smtp.mailfrom=alice@example.com; dkim=fail header.d=example.com\r\n"
        b"DKIM-Signature: v=1; d=example.com; s=s1; b=x\r\n"))
    d = evaluate_dmarc(h)
    assert d.result == AuthResult.PASS and "SPF" in d.reason


def test_dmarc_never_requires_both_spf_and_dkim():
    """Direct regression test for the spec's explicit warning against AND logic."""
    only_spf = msg(extra_headers=b"Authentication-Results: mx.a.com; spf=pass smtp.mailfrom=alice@example.com\r\n")
    only_dkim = msg(extra_headers=(
        b"Authentication-Results: mx.a.com; dkim=pass header.d=example.com\r\n"
        b"DKIM-Signature: v=1; d=example.com; s=s1; b=x\r\n"))
    assert evaluate_dmarc(only_spf).result == AuthResult.PASS
    assert evaluate_dmarc(only_dkim).result == AuthResult.PASS


def test_dmarc_fails_when_both_fail():
    h = msg(extra_headers=b"Authentication-Results: mx.a.com; spf=fail smtp.mailfrom=x@evil.com; dkim=fail header.d=evil.com\r\n")
    assert evaluate_dmarc(h).result == AuthResult.FAIL


def test_dmarc_fails_when_authenticated_but_unaligned():
    """Both mechanisms technically 'pass' authentication but for the wrong domain — must still fail."""
    h = msg(extra_headers=(
        b"Authentication-Results: mx.a.com; spf=pass smtp.mailfrom=x@other.net; dkim=pass header.d=other.net\r\n"
        b"DKIM-Signature: v=1; d=other.net; s=s1; b=x\r\n"))
    d = evaluate_dmarc(h)
    assert d.result == AuthResult.FAIL


def test_dmarc_none_when_no_authentication_info_present_at_all():
    d = evaluate_dmarc(msg())
    assert d.result == AuthResult.NONE


def test_dmarc_unknown_when_no_header_from_domain():
    h = parse_email(b"Subject: no from header\r\n\r\nbody").headers
    d = evaluate_dmarc(h)
    assert d.result == AuthResult.UNKNOWN


# --------------------------------------------------------------------------- policy vs. authentication result
def test_dmarc_policy_reject_does_not_override_an_actual_pass():
    """Direct regression test: policy=reject must not itself make DMARC=FAIL when the message
    genuinely authenticates and aligns."""
    h = msg(extra_headers=b"Authentication-Results: mx.a.com; spf=pass smtp.mailfrom=alice@example.com\r\n")
    provider = StaticDMARCPolicyProvider({"example.com": "v=DMARC1; p=reject"})
    d = evaluate_dmarc(h, provider)
    assert d.result == AuthResult.PASS and d.policy.p == "reject"


def test_dmarc_policy_and_result_are_reported_as_distinct_fields():
    h = msg(extra_headers=b"Authentication-Results: mx.a.com; spf=fail smtp.mailfrom=x@evil.com\r\n")
    provider = StaticDMARCPolicyProvider({"example.com": "v=DMARC1; p=quarantine"})
    d = evaluate_dmarc(h, provider)
    assert d.result == AuthResult.FAIL and d.policy.p == "quarantine"  # independent facts


def test_reported_dmarc_result_surfaced_separately_from_computed_result():
    """The message's own self-reported dmarc= (possibly from a different, less strict evaluator)
    must never silently replace our own computed verdict."""
    h = msg(extra_headers=(
        b"Authentication-Results: mx.a.com; spf=fail smtp.mailfrom=x@evil.com; dmarc=pass header.from=example.com\r\n"))
    d = evaluate_dmarc(h)
    assert d.result == AuthResult.FAIL  # our computation, not blindly trusting the reported value
    assert d.reported_result == AuthResult.PASS  # but the reported value is still surfaced


# --------------------------------------------------------------------------- DMARC record parsing
def test_parse_dmarc_record_all_tags():
    r = parse_dmarc_record("example.com", "v=DMARC1; p=quarantine; sp=reject; pct=50; "
                                          "rua=mailto:a@b.com,mailto:c@d.com; adkim=s; aspf=r")
    assert (r.p, r.sp, r.pct, r.adkim, r.aspf) == ("quarantine", "reject", 50, AlignmentMode.STRICT, AlignmentMode.RELAXED)
    assert r.rua == ["mailto:a@b.com", "mailto:c@d.com"]


def test_parse_dmarc_record_defaults_when_optional_tags_missing():
    r = parse_dmarc_record("example.com", "v=DMARC1; p=none")
    assert r.pct == 100 and r.adkim == AlignmentMode.RELAXED and r.aspf == AlignmentMode.RELAXED and r.rua == []


def test_parse_dmarc_record_invalid_pct_falls_back_to_100():
    r = parse_dmarc_record("example.com", "v=DMARC1; p=none; pct=not-a-number")
    assert r.pct == 100


def test_static_policy_provider_returns_none_for_unknown_domain():
    provider = StaticDMARCPolicyProvider({"example.com": "v=DMARC1; p=reject"})
    assert provider.get_policy("unknown.com") is None


def test_null_policy_provider_always_returns_none():
    from regexsoc.email_security.auth import NullDMARCPolicyProvider
    assert NullDMARCPolicyProvider().get_policy("example.com") is None


def test_dmarc_policy_provider_base_class_is_abstract():
    with pytest.raises(NotImplementedError):
        DMARCPolicyProvider().get_policy("example.com")


# --------------------------------------------------------------------------- full-sample integration
def test_benign_sample_is_dmarc_pass():
    from pathlib import Path
    from regexsoc.email_security.parser import parse_email_file
    f = Path(__file__).resolve().parent.parent / "sample_emails" / "benign_newsletter.eml"
    h = parse_email_file(str(f)).headers
    d = evaluate_dmarc(h)
    assert d.result == AuthResult.PASS


def test_phishing_sample_is_dmarc_fail():
    from pathlib import Path
    from regexsoc.email_security.parser import parse_email_file
    f = Path(__file__).resolve().parent.parent / "sample_emails" / "phishing_password_reset.eml"
    h = parse_email_file(str(f)).headers
    d = evaluate_dmarc(h)
    assert d.result == AuthResult.FAIL


# --------------------------------------------------------------------------- serialization
def test_dmarc_evaluation_to_dict_is_json_serializable():
    import json
    h = msg(extra_headers=b"Authentication-Results: mx.a.com; spf=pass smtp.mailfrom=alice@example.com\r\n")
    json.dumps(evaluate_dmarc(h).to_dict())  # must not raise
