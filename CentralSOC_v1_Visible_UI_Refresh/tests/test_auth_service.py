"""Auth-service tests. Skipped automatically when SQLAlchemy is not installed."""

import pytest

pytest.importorskip("sqlalchemy")

from regexsoc.db import models  # noqa: E402
from regexsoc.db.auth_service import (  # noqa: E402
    AccountDisabled, AccountLocked, InvalidCredentials, MFARequired, authenticate, begin_mfa_enrollment,
    change_password, confirm_mfa_enrollment, create_user, disable_mfa, set_active, set_role, verify_mfa_login,
)
from regexsoc.db.service import list_audit  # noqa: E402
from regexsoc.db.session import init_db, make_engine, session_scope  # noqa: E402
from regexsoc.security.lockout import LockoutPolicy  # noqa: E402
from regexsoc.security.mfa import totp_now  # noqa: E402

STRONG_PW = "Correct-Horse-Battery-Staple-1"
TIGHT = LockoutPolicy(max_failures=3, window_minutes=15, cooldown_minutes=15)


def fresh_engine():
    engine = make_engine("sqlite://")
    init_db(engine)
    return engine


def make_user(engine, username="alice", role="ANALYST", password=STRONG_PW):
    with session_scope(engine) as s:
        create_user(s, username, password, role, created_by="system")


def test_create_user_rejects_weak_password():
    engine = fresh_engine()
    with session_scope(engine) as s:
        with pytest.raises(ValueError, match="weak password"):
            create_user(s, "bob", "short", "VIEWER")


def test_create_user_rejects_duplicate_username():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        with pytest.raises(ValueError, match="already taken"):
            create_user(s, "alice", STRONG_PW, "VIEWER")


def test_create_user_rejects_invalid_role():
    engine = fresh_engine()
    with session_scope(engine) as s:
        with pytest.raises(ValueError, match="role"):
            create_user(s, "bob", STRONG_PW, "SUPERUSER")


def test_create_user_is_audited_without_leaking_password():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        entries = [a for a in list_audit(s) if a.action == "USER_CREATED"]
    assert entries and STRONG_PW not in entries[0].detail


def test_successful_login_without_mfa():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        result = authenticate(s, "alice", STRONG_PW)
        assert result.user.username == "alice" and result.user.last_login_at is not None


def test_wrong_password_raises_and_is_audited():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        with pytest.raises(InvalidCredentials):
            authenticate(s, "alice", "totally-wrong-password")
    with session_scope(engine) as s:
        failures = [a for a in list_audit(s) if a.action == "LOGIN_FAILED"]
    assert failures


def test_unknown_username_raises_invalid_credentials_not_a_different_error():
    engine = fresh_engine()
    with session_scope(engine) as s:
        with pytest.raises(InvalidCredentials):
            authenticate(s, "ghost", STRONG_PW)


def test_disabled_account_is_rejected():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        set_active(s, "alice", False, changed_by="admin")
    with session_scope(engine) as s:
        with pytest.raises(AccountDisabled):
            authenticate(s, "alice", STRONG_PW)


def test_lockout_after_repeated_failures():
    engine = fresh_engine()
    make_user(engine)
    for _ in range(3):
        with session_scope(engine) as s:
            with pytest.raises(InvalidCredentials):
                authenticate(s, "alice", "wrong", policy=TIGHT)
    with session_scope(engine) as s:
        with pytest.raises(AccountLocked):
            authenticate(s, "alice", STRONG_PW, policy=TIGHT)  # even the correct password is now blocked


def test_lockout_does_not_apply_to_other_users():
    engine = fresh_engine()
    make_user(engine, "alice")
    make_user(engine, "bob")
    for _ in range(3):
        with session_scope(engine) as s:
            with pytest.raises(InvalidCredentials):
                authenticate(s, "alice", "wrong", policy=TIGHT)
    with session_scope(engine) as s:
        assert authenticate(s, "bob", STRONG_PW, policy=TIGHT).user.username == "bob"


def test_successful_login_resets_the_lockout_streak():
    engine = fresh_engine()
    make_user(engine)
    for _ in range(2):
        with session_scope(engine) as s:
            with pytest.raises(InvalidCredentials):
                authenticate(s, "alice", "wrong", policy=TIGHT)
    with session_scope(engine) as s:
        authenticate(s, "alice", STRONG_PW, policy=TIGHT)  # success
    for _ in range(2):
        with session_scope(engine) as s:
            with pytest.raises(InvalidCredentials):
                authenticate(s, "alice", "wrong", policy=TIGHT)
    with session_scope(engine) as s:  # only 2 consecutive failures since the reset; still under threshold 3
        assert authenticate(s, "alice", STRONG_PW, policy=TIGHT).user.username == "alice"


def test_full_mfa_enrollment_and_login_flow():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        uid = s.scalar(__import__("sqlalchemy").select(models.User).where(models.User.username == "alice")).id
        secret, uri = begin_mfa_enrollment(s, uid)
        assert uri.startswith("otpauth://") and "alice" in uri
    with session_scope(engine) as s:
        with pytest.raises(InvalidCredentials):
            confirm_mfa_enrollment(s, uid, "000000")
    with session_scope(engine) as s:
        confirm_mfa_enrollment(s, uid, totp_now(secret))
    with session_scope(engine) as s:
        user = s.get(models.User, uid)
        assert user.mfa_enabled and user.mfa_secret == secret and user.pending_mfa_secret is None

    with session_scope(engine) as s:
        with pytest.raises(MFARequired) as exc:
            authenticate(s, "alice", STRONG_PW)
        assert exc.value.user_id == uid
    with session_scope(engine) as s:
        with pytest.raises(InvalidCredentials):
            verify_mfa_login(s, uid, "000000")
    with session_scope(engine) as s:
        result = verify_mfa_login(s, uid, totp_now(secret))
        assert result.user.username == "alice"


def test_disable_mfa_clears_secret():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        import sqlalchemy as sa
        uid = s.scalar(sa.select(models.User).where(models.User.username == "alice")).id
        secret, _ = begin_mfa_enrollment(s, uid)
        confirm_mfa_enrollment(s, uid, totp_now(secret))
    with session_scope(engine) as s:
        disable_mfa(s, uid, disabled_by="admin")
    with session_scope(engine) as s:
        user = s.get(models.User, uid)
        assert not user.mfa_enabled and user.mfa_secret is None


def test_set_role_updates_and_audits():
    engine = fresh_engine()
    make_user(engine, role="VIEWER")
    with session_scope(engine) as s:
        set_role(s, "alice", "ADMIN", changed_by="root")
    with session_scope(engine) as s:
        import sqlalchemy as sa
        user = s.scalar(sa.select(models.User).where(models.User.username == "alice"))
        assert user.role == "ADMIN"
        entries = [a for a in list_audit(s) if a.action == "USER_ROLE_CHANGED"]
        assert entries and "VIEWER" in entries[0].detail and "ADMIN" in entries[0].detail


def test_set_role_rejects_invalid_role():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        with pytest.raises(ValueError):
            set_role(s, "alice", "SUPERUSER", changed_by="root")


def test_set_role_unknown_user_raises():
    engine = fresh_engine()
    with session_scope(engine) as s:
        with pytest.raises(LookupError):
            set_role(s, "ghost", "ADMIN", changed_by="root")


def test_change_password_succeeds_with_correct_current_password():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        import sqlalchemy as sa
        uid = s.scalar(sa.select(models.User).where(models.User.username == "alice")).id
        change_password(s, uid, STRONG_PW, "A-New-Strong-Password-2")
    with session_scope(engine) as s:
        assert authenticate(s, "alice", "A-New-Strong-Password-2").user.username == "alice"


def test_change_password_rejects_wrong_current_password():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        import sqlalchemy as sa
        uid = s.scalar(sa.select(models.User).where(models.User.username == "alice")).id
        with pytest.raises(InvalidCredentials):
            change_password(s, uid, "totally-wrong", "A-New-Strong-Password-2")
    # old password still works; nothing changed
    with session_scope(engine) as s:
        assert authenticate(s, "alice", STRONG_PW).user.username == "alice"


def test_change_password_rejects_weak_new_password():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        import sqlalchemy as sa
        uid = s.scalar(sa.select(models.User).where(models.User.username == "alice")).id
        with pytest.raises(ValueError, match="weak password"):
            change_password(s, uid, STRONG_PW, "short")


def test_change_password_is_audited_without_leaking_either_password():
    engine = fresh_engine()
    make_user(engine)
    with session_scope(engine) as s:
        import sqlalchemy as sa
        uid = s.scalar(sa.select(models.User).where(models.User.username == "alice")).id
        change_password(s, uid, STRONG_PW, "A-New-Strong-Password-2")
    with session_scope(engine) as s:
        entries = [a for a in list_audit(s) if a.detail and "password changed" in a.detail]
    assert entries
    for a in entries:
        assert STRONG_PW not in (a.detail or "") and "A-New-Strong-Password-2" not in (a.detail or "")


def test_change_password_unknown_user_raises():
    engine = fresh_engine()
    with session_scope(engine) as s:
        with pytest.raises(LookupError):
            change_password(s, 9999, "x", "A-New-Strong-Password-2")
