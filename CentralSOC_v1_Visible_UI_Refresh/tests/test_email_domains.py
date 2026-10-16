"""Domain analysis tests (Phase 3): Levenshtein, homoglyphs, punycode, lookalike detection."""

import pytest

from regexsoc.email_security.domains import (
    check_lookalike_domain, check_suspicious_subdomain, domain_shape_flags, is_punycode,
    levenshtein, normalize_homoglyphs,
)


@pytest.mark.parametrize("a,b,expected", [
    ("microsoft", "microsoft", 0), ("", "abc", 3), ("abc", "", 3),
    ("microsoft", "micros0ft", 1), ("kitten", "sitting", 3), ("paypal", "paypa1", 1),
])
def test_levenshtein(a, b, expected):
    assert levenshtein(a, b) == expected


@pytest.mark.parametrize("text,expected", [
    ("micr0s0ft", "microsoft"), ("paypa1", "paypal"), ("arnazon", "amazon"), ("vvells", "wells"),
    ("microsoft", "microsoft"),
])
def test_normalize_homoglyphs(text, expected):
    assert normalize_homoglyphs(text) == expected


@pytest.mark.parametrize("domain,expected", [
    ("xn--pypal-4ve.com", True), ("microsoft.com", False), ("xn--80ak6aa92e.com", True),
])
def test_is_punycode(domain, expected):
    assert is_punycode(domain) == expected


@pytest.mark.parametrize("domain,should_flag", [
    ("micros0ft-security.com", True), ("microsoft.com", False), ("paypa1.com", True),
    ("paypal-secure-verify.net", True), ("example.com", False), ("g00gle-account-verify.info", True),
    ("mycompany.com", False), ("wellsfarg0.com", True), ("mail.paypal.com", False),
    ("paypal.com", False), ("microsoft-security-update.com", True), ("totally-unrelated-thing.com", False),
])
def test_check_lookalike_domain(domain, should_flag):
    assert (check_lookalike_domain(domain) is not None) == should_flag


def test_lookalike_match_reports_brand_and_reason():
    match = check_lookalike_domain("paypa1.com")
    assert match.brand == "paypal" and match.reason == "edit_distance" and match.distance == 1


def test_lookalike_never_flags_short_brand_via_fuzzy_edit_distance():
    # "ups" (3 chars) is excluded from fuzzy matching to avoid noisy false positives on short words
    assert check_lookalike_domain("upstairs.com") is None


def test_suspicious_subdomain_detects_brand_ahead_of_real_domain():
    assert check_suspicious_subdomain("paypal.com.attacker-verify.net") == "paypal"


def test_suspicious_subdomain_none_for_brands_own_real_subdomain():
    assert check_suspicious_subdomain("mail.paypal.com") is None


def test_suspicious_subdomain_none_for_plain_domain_with_no_subdomain():
    assert check_suspicious_subdomain("example.com") is None


def test_domain_shape_flags_long_domain():
    assert any("long" in f for f in domain_shape_flags("a" * 50 + ".com"))


def test_domain_shape_flags_high_digit_density():
    assert any("digit" in f for f in domain_shape_flags("12345678.com"))


def test_domain_shape_flags_normal_domain_has_none():
    assert domain_shape_flags("example.com") == []


def test_domain_shape_flags_many_hyphens():
    assert any("hyphen" in f for f in domain_shape_flags("a-b-c-d.com"))
