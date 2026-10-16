"""Content indicator tests (Phase 3): phrase-based social-engineering detection."""

import time

from regexsoc.email_security.textmatch import display_name_claims_executive_title, find_content_indicators


def categories(text):
    return {m.category for m in find_content_indicators(text)}


def test_phishing_body_flags_urgency_and_credential_harvesting():
    body = ("URGENT ACTION REQUIRED\n\nWe detected unusual sign-in activity on your account. "
           "Verify your identity within 24 hours or your account will be suspended.\n"
           "Please click here to verify your account and update your payment information.")
    cats = categories(body)
    assert "URGENCY" in cats and "CREDENTIAL_HARVESTING" in cats


def test_bec_body_flags_financial_pressure():
    body = ("I need you to process an urgent payment for a supplier invoice that is overdue. "
           "Please arrange a wire transfer to the new bank account details attached.")
    matches = find_content_indicators(body)
    ids = {m.pattern_id for m in matches}
    assert {"wire_transfer", "urgent_payment", "invoice_overdue"} <= ids


def test_evidence_is_the_actual_matched_text_not_just_a_boolean():
    match = find_content_indicators("Please verify your account today.")[0]
    assert match.evidence.lower() == "verify your account"


def test_none_body_returns_no_indicators():
    assert find_content_indicators(None) == []


def test_empty_body_returns_no_indicators():
    assert find_content_indicators("") == []


BENIGN_BODIES = [
    "Hi team, here's this week's newsletter. Your package will arrive within 24 hours.",
    "Please find attached the invoice for last month's services. Let us know if you have questions.",
    "Reminder: your subscription renews soon. You can manage your account settings any time.",
    "Thanks for your order! Your account was created successfully.",
    "The invoice for our services is fully paid and not overdue at all, thanks for your business.",
]


def test_ordinary_transactional_emails_do_not_false_positive():
    """Direct regression test for the spec's warning against pure keyword matching: none of these
    ordinary business emails should trigger any indicator."""
    for body in BENIGN_BODIES:
        assert find_content_indicators(body) == [], f"false positive on: {body!r}"


def test_invoice_overdue_allows_a_few_words_between_invoice_and_overdue():
    assert find_content_indicators("the invoice that is overdue needs paying")


def test_content_matching_is_not_vulnerable_to_redos():
    adversarial = "invoice " + "word " * 50000
    start = time.time()
    find_content_indicators(adversarial)
    assert time.time() - start < 2.0


def test_display_name_executive_title_detection():
    assert display_name_claims_executive_title("John Smith, CEO") == "CEO"
    assert display_name_claims_executive_title("Alice Johnson") is None
    assert display_name_claims_executive_title(None) is None
