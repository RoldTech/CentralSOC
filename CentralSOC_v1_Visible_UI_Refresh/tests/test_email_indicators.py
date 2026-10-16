"""Indicator engine + verdict tests (Phase 3)."""

from regexsoc.email_security.auth import evaluate_dmarc
from regexsoc.email_security.indicators import PhishingIndicator, collect_indicators
from regexsoc.email_security.parser import parse_email
from regexsoc.email_security.verdict import POINTS, compute_verdict
from regexsoc.models import Severity


def analyze(raw: bytes, internal_domains=frozenset()):
    p = parse_email(raw)
    dmarc = evaluate_dmarc(p.headers)
    inds = collect_indicators(p.headers, p.plain_text_body, p.html_body, dmarc, internal_domains)
    return inds, compute_verdict(inds, header_from_present=bool(p.headers.from_))


def ids(inds):
    return {i.indicator_id for i in inds}


# --------------------------------------------------------------------------- sender indicators
def test_display_name_spoofing_detected():
    inds, _ = analyze(b'From: "security@paypal.com" <attacker@evil-domain.net>\r\n\r\nhello')
    assert "DISPLAY_NAME_SPOOFING" in ids(inds)


def test_display_name_with_matching_domain_is_not_spoofing():
    inds, _ = analyze(b'From: "billing@example.com" <billing@example.com>\r\n\r\nhello')
    assert "DISPLAY_NAME_SPOOFING" not in ids(inds)


def test_reply_to_mismatch_detected():
    inds, _ = analyze(b"From: a@example.com\r\nReply-To: b@other-domain.net\r\n\r\nhi")
    assert "REPLY_TO_MISMATCH" in ids(inds)


def test_matching_reply_to_is_not_flagged():
    inds, _ = analyze(b"From: a@example.com\r\nReply-To: support@example.com\r\n\r\nhi")
    assert "REPLY_TO_MISMATCH" not in ids(inds)


def test_return_path_mismatch_detected():
    inds, _ = analyze(b"From: a@example.com\r\nReturn-Path: <bounce@evil.net>\r\n\r\nhi")
    assert "RETURN_PATH_MISMATCH" in ids(inds)


def test_free_email_with_corporate_sounding_name():
    inds, _ = analyze(b'From: "Account Security Team" <helper123@gmail.com>\r\n\r\nhi')
    assert "FREE_EMAIL_BRAND_IMPERSONATION" in ids(inds)


def test_ordinary_person_on_free_email_is_not_flagged():
    inds, _ = analyze(b'From: "Alice Johnson" <alice@gmail.com>\r\n\r\nhi there')
    assert "FREE_EMAIL_BRAND_IMPERSONATION" not in ids(inds)


def test_external_executive_impersonation_needs_internal_domains_configured():
    raw = b'From: "Sarah, CEO" <s@other.com>\r\n\r\nhi'
    assert "EXTERNAL_EXECUTIVE_IMPERSONATION" not in ids(analyze(raw)[0])  # feature off by default
    assert "EXTERNAL_EXECUTIVE_IMPERSONATION" in ids(analyze(raw, frozenset({"example.org"}))[0])


# --------------------------------------------------------------------------- domain indicators
def test_lookalike_domain_indicator():
    inds, _ = analyze(b"From: support@micros0ft-security.com\r\n\r\nhi")
    assert "LOOKALIKE_DOMAIN" in ids(inds)


def test_punycode_domain_indicator():
    inds, _ = analyze(b"From: a@xn--pypal-4ve.com\r\n\r\nhi")
    assert "PUNYCODE_DOMAIN" in ids(inds)


def test_suspicious_subdomain_indicator():
    inds, _ = analyze(b"From: a@paypal.com.attacker-verify.net\r\n\r\nhi")
    assert "SUSPICIOUS_SUBDOMAIN" in ids(inds)


def test_legitimate_domain_has_no_domain_indicators():
    inds, _ = analyze(b"From: a@example.com\r\nAuthentication-Results: mx; spf=pass smtp.mailfrom=a@example.com\r\n\r\nhi")
    assert not [i for i in inds if i.category == "DOMAIN"]


# --------------------------------------------------------------------------- content + dedup
def test_content_indicators_fire_on_phishing_text():
    inds, _ = analyze(b"From: a@example.com\r\n\r\nURGENT ACTION REQUIRED. Please verify your account now.")
    assert {"URGENT_ACTION_REQUIRED", "VERIFY_ACCOUNT"} <= ids(inds)


def test_same_phrase_in_plain_and_html_bodies_counts_once():
    raw = (b"From: a@example.com\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n"
          b"--b\r\nContent-Type: text/plain\r\n\r\nPlease verify your account.\r\n"
          b"--b\r\nContent-Type: text/html\r\n\r\n<p>Please verify your account.</p>\r\n--b--\r\n")
    inds, _ = analyze(raw)
    assert [i.indicator_id for i in inds].count("VERIFY_ACCOUNT") == 1


# --------------------------------------------------------------------------- BEC correlation
BEC = (b'From: "Sarah, CEO" <s@gmail.com>\r\nReply-To: x@other-mail.net\r\n\r\n'
       b"Please process an urgent payment and arrange a wire transfer to the new bank account details.")


def test_bec_correlation_fires_when_financial_and_sender_risk_combine():
    assert "BEC_CORRELATION" in ids(analyze(BEC)[0])


def test_bec_correlation_does_not_fire_on_financial_language_alone():
    raw = b"From: billing@example.com\r\n\r\nPlease arrange a wire transfer for the invoice."
    inds, _ = analyze(raw)
    assert "WIRE_TRANSFER" in ids(inds) and "BEC_CORRELATION" not in ids(inds)


def test_bec_correlation_does_not_fire_on_sender_risk_alone():
    raw = b"From: a@example.com\r\nReply-To: b@other.net\r\n\r\nSee you at lunch tomorrow."
    assert "BEC_CORRELATION" not in ids(analyze(raw)[0])


# --------------------------------------------------------------------------- authentication indicators
def test_dmarc_failure_indicator():
    raw = (b"From: a@example.com\r\nAuthentication-Results: mx; spf=fail smtp.mailfrom=x@evil.com; dkim=fail header.d=evil.com\r\n\r\nhi")
    assert "DMARC_FAILURE" in ids(analyze(raw)[0])


def test_passing_dmarc_has_no_authentication_indicator():
    raw = b"From: a@example.com\r\nAuthentication-Results: mx; spf=pass smtp.mailfrom=a@example.com\r\n\r\nhi"
    assert not [i for i in analyze(raw)[0] if i.category == "AUTHENTICATION"]


# --------------------------------------------------------------------------- verdict scoring
def test_clean_email_is_benign_with_high_confidence():
    raw = (b"From: a@example.com\r\nAuthentication-Results: mx; spf=pass smtp.mailfrom=a@example.com\r\n\r\nSee you Monday.")
    _, v = analyze(raw)
    assert v.classification == "BENIGN" and v.score == 0 and v.confidence == "HIGH"


def test_single_weak_indicator_alone_stays_benign():
    """The spec's explicit requirement: never call something malicious from one weak signal."""
    raw = (b"From: a@example.com\r\nAuthentication-Results: mx; spf=pass smtp.mailfrom=a@example.com\r\n\r\n"
          b"Your verification code is 12345.")
    _, v = analyze(raw)
    assert v.classification == "BENIGN"


def test_bec_reaches_malicious():
    assert analyze(BEC)[1].classification == "MALICIOUS"


def test_credential_phishing_sample_is_phishing_not_malicious():
    raw = (b"From: a@example-verify.net\r\nReply-To: b@other-domain.net\r\n"
          b"Authentication-Results: mx; spf=fail smtp.mailfrom=example-verify.net; dkim=none\r\n\r\n"
          b"URGENT ACTION REQUIRED. Verify your identity within 24 hours. Click here to verify.")
    assert analyze(raw)[1].classification == "PHISHING"


def test_repeated_similar_signals_have_diminishing_returns():
    def make(*sev):
        inds = [PhishingIndicator(f"X{n}", "CONTENT", s, "d", "e") for n, s in enumerate(sev)]
        return compute_verdict(inds).category_scores["CONTENT"]
    one, four = make(Severity.MEDIUM.value), make(*[Severity.MEDIUM.value] * 4)
    assert four < one * 4  # not linear
    assert four > one      # but still additive


def test_category_scores_and_reasons_are_explainable():
    _, v = analyze(BEC)
    assert v.reasons and all(isinstance(r, str) for r in v.reasons)
    assert v.category_scores["BEC"] == POINTS[Severity.CRITICAL.value]


def test_unknown_when_no_from_header():
    _, v = analyze(b"Subject: no sender at all\r\n\r\nhi")
    assert v.classification == "UNKNOWN"


def test_score_is_capped_at_100():
    assert analyze(BEC)[1].score == 100


def test_verdict_to_dict_is_json_serializable():
    import json
    json.dumps(analyze(BEC)[1].to_dict())
