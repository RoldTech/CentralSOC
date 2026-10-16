import time

from regexsoc.security.csrf import TOKEN_MAX_AGE_SECONDS, issue_token, verify_token

KEY = "test-secret-key"


def test_valid_token_verifies():
    token = issue_token(KEY, "session-abc")
    assert verify_token(KEY, "session-abc", token)


def test_token_bound_to_session_id():
    token = issue_token(KEY, "session-abc")
    assert not verify_token(KEY, "different-session", token)


def test_token_rejected_with_wrong_secret_key():
    token = issue_token(KEY, "session-abc")
    assert not verify_token("a-different-key", "session-abc", token)


def test_missing_or_tampered_token_rejected():
    assert not verify_token(KEY, "session-abc", None)
    assert not verify_token(KEY, "session-abc", "")
    token = issue_token(KEY, "session-abc")
    assert not verify_token(KEY, "session-abc", token[:-1] + ("x" if token[-1] != "x" else "y"))


def test_token_expires():
    token = issue_token(KEY, "session-abc")
    old_max_age = TOKEN_MAX_AGE_SECONDS
    from regexsoc.security import csrf
    csrf.TOKEN_MAX_AGE_SECONDS = 0
    try:
        time.sleep(1.1)
        assert not verify_token(KEY, "session-abc", token)
    finally:
        csrf.TOKEN_MAX_AGE_SECONDS = old_max_age


def test_garbage_token_does_not_raise():
    assert not verify_token(KEY, "session-abc", "not-a-real-token-at-all")
