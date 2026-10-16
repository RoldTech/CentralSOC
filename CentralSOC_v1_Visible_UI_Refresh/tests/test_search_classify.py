import pytest

from regexsoc.web.search import classify


@pytest.mark.parametrize("q,kind", [
    ("203.0.113.5", "ip"),
    ("2001:db8::5", "ip"),
    ("ALERT-1A2B3C4D5E", "alert_id"),
    ("alert-1a2b3c4d5e", "alert_id"),  # case-insensitive
    ("CVE-2021-44228", "cve"),
    ("cve-2021-44228", "cve"),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash"),          # 32 hex = MD5
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash"),  # 40 hex = SHA1
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash"),  # 64 hex = SHA256
    ("malicious-example.xyz", "domain_or_url"),
    ("http://malicious-example.xyz/x.php", "domain_or_url"),
    ("admin", "text"),
    ("root", "text"),
    ("", "text"),
])
def test_classify(q, kind):
    assert classify(q).kind == kind


def test_hash_is_lowercased_for_matching():
    assert classify("D41D8CD98F00B204E9800998ECF8427E").value == "d41d8cd98f00b204e9800998ecf8427e"


def test_alert_id_is_uppercased():
    assert classify("alert-deadbeef00").value == "ALERT-DEADBEEF00"


def test_wrong_length_hex_is_treated_as_text_not_hash():
    assert classify("abc123").kind == "text"        # too short
    assert classify("a" * 50).kind == "text"          # not 32/40/64


def test_username_that_happens_to_be_hex_length_is_still_text_if_not_pure_hex():
    assert classify("system-admin-99").kind == "text"


def test_query_is_trimmed():
    assert classify("  203.0.113.5  ").value == "203.0.113.5"
