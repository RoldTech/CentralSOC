import pytest

from regexsoc.security.passwords import (
    hash_password, needs_rehash, validate_password_strength, verify_password,
)


def test_hash_and_verify_roundtrip():
    h = hash_password("Correct-Horse-Battery-Staple")
    assert verify_password("Correct-Horse-Battery-Staple", h)
    assert not verify_password("wrong-password", h)


def test_hash_is_salted_and_scheme_tagged():
    h1, h2 = hash_password("same-password-123"), hash_password("same-password-123")
    assert h1 != h2  # different salts
    assert h1.split("$", 1)[0] in {"argon2", "scrypt"}


def test_empty_password_rejected():
    with pytest.raises(ValueError):
        hash_password("")


@pytest.mark.parametrize("bad_hash", ["", "not-a-hash", "bcrypt$garbage", "scrypt$garbage",
                                      "scrypt$1$1$1$notb64$notb64"])
def test_verify_never_raises_on_malformed_hash(bad_hash):
    assert verify_password("anything", bad_hash) is False


def test_verify_rejects_empty_password():
    assert verify_password("", hash_password("something-long-enough")) is False


def test_scrypt_needs_rehash_detects_weaker_params():
    weak = "scrypt$4$8$1$" + "A" * 22 + "$" + "B" * 43
    assert needs_rehash(weak) is True


def test_unknown_scheme_needs_rehash():
    assert needs_rehash("plaintext$hunter2") is True


@pytest.mark.parametrize("pw,username,expect_ok", [
    ("Sup3r-Long-Passphrase!", None, True),
    ("short", None, False),
    ("123456789012345", None, False),      # long but all digits
    ("password", None, False),             # common weak
    ("alice12345678", "alice12345678", False),  # matches username
])
def test_password_strength_policy(pw, username, expect_ok):
    assert (validate_password_strength(pw, username) == []) is expect_ok


def test_strength_violations_are_descriptive():
    problems = validate_password_strength("short")
    assert any("12 characters" in p for p in problems)
