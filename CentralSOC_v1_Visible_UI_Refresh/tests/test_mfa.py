import pytest

from regexsoc.security.mfa import (
    generate_backup_codes, generate_secret, provisioning_uri, totp_now, verify_totp,
)

# RFC 6238 test vector: secret "12345678901234567890" (ASCII) base32-encoded, SHA-1, time=59 -> 94287082
RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_rfc6238_vector():
    # The published RFC 6238 vector is an 8-digit code; RegexSOC defaults to 6 digits (its last 6 digits).
    assert totp_now(RFC_SECRET_B32, for_time=59, digits=8) == "94287082"
    assert totp_now(RFC_SECRET_B32, for_time=59) == "287082"


def test_verify_accepts_current_code():
    secret = generate_secret()
    assert verify_totp(secret, totp_now(secret, for_time=1_700_000_000), for_time=1_700_000_000)


def test_verify_rejects_wrong_code():
    secret = generate_secret()
    assert not verify_totp(secret, "000000", for_time=1_700_000_000)


def test_verify_tolerates_clock_drift_within_window():
    secret = generate_secret()
    code = totp_now(secret, for_time=1_700_000_000)
    assert verify_totp(secret, code, for_time=1_700_000_000 + 30)   # one step later
    assert verify_totp(secret, code, for_time=1_700_000_000 - 30)   # one step earlier


def test_verify_rejects_code_outside_window():
    secret = generate_secret()
    code = totp_now(secret, for_time=1_700_000_000)
    assert not verify_totp(secret, code, for_time=1_700_000_000 + 300)


@pytest.mark.parametrize("code", ["", "12345", "abcdef", "1234567", None])
def test_verify_rejects_malformed_codes(code):
    assert not verify_totp(generate_secret(), code)


def test_different_secrets_give_different_codes():
    a, b = generate_secret(), generate_secret()
    assert totp_now(a, for_time=1_700_000_000) != totp_now(b, for_time=1_700_000_000)


def test_secret_is_random_and_valid_base32():
    import base64
    secrets_ = {generate_secret() for _ in range(20)}
    assert len(secrets_) == 20
    for s in secrets_:
        base64.b32decode(s + "=" * (-len(s) % 8))  # must not raise


def test_provisioning_uri_contains_expected_fields():
    uri = provisioning_uri("ABCD1234", "alice@example.com", issuer="RegexSOC")
    assert uri.startswith("otpauth://totp/")
    assert "secret=ABCD1234" in uri and "issuer=RegexSOC" in uri and "alice%40example.com" in uri


def test_backup_codes_are_unique_and_unambiguous():
    codes = generate_backup_codes(20)
    assert len(codes) == len(set(codes)) == 20
    for c in codes:
        assert not any(ch in c for ch in "0O1I")
