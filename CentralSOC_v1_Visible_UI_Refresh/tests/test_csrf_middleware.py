from regexsoc.web.csrf_middleware import current_token, csrf_allows, ensure_session_id

KEY = "test-secret"


def test_safe_methods_always_allowed():
    session = {}
    for method in ("GET", "HEAD", "OPTIONS"):
        assert csrf_allows(session, KEY, method, None)


def test_unsafe_method_without_token_blocked():
    session = {}
    assert not csrf_allows(session, KEY, "POST", None)


def test_unsafe_method_with_valid_token_allowed():
    session = {}
    token = current_token(session, KEY)
    assert csrf_allows(session, KEY, "POST", token)


def test_token_from_a_different_session_is_rejected():
    session_a, session_b = {}, {}
    token_a = current_token(session_a, KEY)
    ensure_session_id(session_b)
    assert not csrf_allows(session_b, KEY, "POST", token_a)


def test_session_id_is_stable_across_calls():
    session = {}
    assert ensure_session_id(session) == ensure_session_id(session)


def test_all_unsafe_methods_are_checked():
    session = {}
    token = current_token(session, KEY)
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert csrf_allows(session, KEY, method, token)
        assert not csrf_allows(session, KEY, method, "wrong-token")
