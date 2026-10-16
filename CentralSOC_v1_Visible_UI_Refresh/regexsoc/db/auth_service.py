"""Authentication service: user management, login (with lockout), MFA enrollment.

Every security-relevant action is audited. Passwords and TOTP secrets are never written to the
audit log (regexsoc.security.audit redacts them defensively even so).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from regexsoc.db import models
from regexsoc.security.audit import AuditAction, clean_text
from regexsoc.security.lockout import DEFAULT_POLICY, LockoutPolicy, is_locked, seconds_remaining
from regexsoc.security.mfa import generate_secret, provisioning_uri, verify_totp
from regexsoc.security.passwords import (
    hash_password, needs_rehash, validate_password_strength, verify_password,
)
from regexsoc.security.rbac import ROLES
from regexsoc.db.service import record_audit


class AuthError(Exception):
    """Base class for authentication failures. ``reason`` is safe to show to the user."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class InvalidCredentials(AuthError):
    pass


class AccountLocked(AuthError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(f"account temporarily locked; try again in {retry_after_seconds}s")
        self.retry_after_seconds = retry_after_seconds


class AccountDisabled(AuthError):
    def __init__(self) -> None:
        super().__init__("account is disabled")


class MFARequired(AuthError):
    """Password was correct; the caller must now collect and verify a TOTP code."""

    def __init__(self, user: models.User) -> None:
        super().__init__("multi-factor authentication code required")
        self.user_id = user.id


@dataclass
class LoginResult:
    user: models.User
    rehashed: bool = False


# --------------------------------------------------------------------------- users
def create_user(session: Session, username: str, password: str, role: str, *, email: str | None = None,
                created_by: str = "system", ip_address: str | None = None) -> models.User:
    """Create a user. Raises ValueError on policy violations or a duplicate username."""
    username = username.strip()
    if not username:
        raise ValueError("username must not be empty")
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if session.scalar(select(models.User).where(models.User.username == username)) is not None:
        raise ValueError(f"username {username!r} is already taken")
    problems = validate_password_strength(password, username)
    if problems:
        raise ValueError("weak password: " + "; ".join(problems))
    user = models.User(username=username, email=email, password_hash=hash_password(password), role=role,
                       is_active=True, created_at=models.utcnow())
    session.add(user)
    session.flush()
    record_audit(session, AuditAction.USER_CREATED, created_by, "SUCCESS", ip_address=ip_address,
                resource=f"user:{user.id}", detail={"username": username, "role": role})
    return user


def set_role(session: Session, username: str, new_role: str, *, changed_by: str,
            ip_address: str | None = None) -> models.User:
    if new_role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    user = session.scalar(select(models.User).where(models.User.username == username))
    if user is None:
        raise LookupError(f"user {username!r} not found")
    old_role = user.role
    user.role = new_role
    session.flush()
    record_audit(session, AuditAction.USER_ROLE_CHANGED, changed_by, "SUCCESS", ip_address=ip_address,
                resource=f"user:{user.id}", detail={"username": username, "from": old_role, "to": new_role})
    return user


def set_active(session: Session, username: str, active: bool, *, changed_by: str,
               ip_address: str | None = None) -> models.User:
    user = session.scalar(select(models.User).where(models.User.username == username))
    if user is None:
        raise LookupError(f"user {username!r} not found")
    user.is_active = active
    session.flush()
    record_audit(session, AuditAction.CONFIG_CHANGED, changed_by, "SUCCESS", ip_address=ip_address,
                resource=f"user:{user.id}", detail={"username": username, "active": active})
    return user


def user_count(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(models.User)) or 0


# --------------------------------------------------------------------------- login
def _recent_attempts(session: Session, username: str, minutes: int) -> list[tuple[datetime, bool]]:
    since = models.utcnow() - timedelta(minutes=minutes)
    rows = session.scalars(
        select(models.LoginAttempt)
        .where(models.LoginAttempt.username == username, models.LoginAttempt.timestamp >= since)
        .order_by(models.LoginAttempt.timestamp.desc())
    ).all()
    return [(r.timestamp, r.success) for r in rows]


def _record_attempt(session: Session, username: str, success: bool, ip_address: str | None) -> None:
    session.add(models.LoginAttempt(username=clean_text(username, 80), ip_address=ip_address,
                                    timestamp=models.utcnow(), success=success))
    session.flush()


def authenticate(session: Session, username: str, password: str, *, ip_address: str | None = None,
                 policy: LockoutPolicy = DEFAULT_POLICY) -> LoginResult:
    """Check lockout, then credentials. Raises AccountLocked, InvalidCredentials, AccountDisabled or
    MFARequired (a *successful* password check whose caller must still verify a TOTP code)."""
    username = username.strip()
    now = models.utcnow()
    attempts = _recent_attempts(session, username, policy.window_minutes)
    if is_locked(attempts, now, policy):
        record_audit(session, AuditAction.LOGIN_FAILED, username, "DENIED", ip_address=ip_address,
                    detail="account locked")
        raise AccountLocked(seconds_remaining(attempts, now, policy))

    user = session.scalar(select(models.User).where(models.User.username == username))
    ok = user is not None and user.is_active and verify_password(password, user.password_hash)
    _record_attempt(session, username, ok, ip_address)

    if not ok:
        record_audit(session, AuditAction.LOGIN_FAILED, username, "FAILURE", ip_address=ip_address)
        if user is not None and not user.is_active:
            raise AccountDisabled()
        raise InvalidCredentials("invalid username or password")

    rehashed = False
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        rehashed = True
    user.last_login_at = now
    session.flush()

    if user.mfa_enabled:
        record_audit(session, AuditAction.LOGIN, username, "SUCCESS", ip_address=ip_address,
                    detail="password ok, awaiting MFA code")
        raise MFARequired(user)

    record_audit(session, AuditAction.LOGIN, username, "SUCCESS", ip_address=ip_address)
    return LoginResult(user, rehashed)


def verify_mfa_login(session: Session, user_id: int, code: str, *, ip_address: str | None = None) -> LoginResult:
    """Second step of login for an MFA-enabled account."""
    user = session.get(models.User, user_id)
    if user is None or not user.mfa_enabled or not user.mfa_secret:
        raise InvalidCredentials("MFA is not set up for this account")
    if verify_totp(user.mfa_secret, code):
        user.last_login_at = models.utcnow()
        session.flush()
        record_audit(session, AuditAction.LOGIN, user.username, "SUCCESS", ip_address=ip_address,
                    detail="MFA verified")
        return LoginResult(user)
    record_audit(session, AuditAction.LOGIN_FAILED, user.username, "FAILURE", ip_address=ip_address,
                detail="invalid MFA code")
    raise InvalidCredentials("invalid authentication code")


# --------------------------------------------------------------------------- MFA enrollment
def begin_mfa_enrollment(session: Session, user_id: int) -> tuple[str, str]:
    """Generate (and store as *pending*) a new secret; MFA is not active until confirm_mfa_enrollment."""
    user = session.get(models.User, user_id)
    if user is None:
        raise LookupError(f"user {user_id} not found")
    secret = generate_secret()
    user.pending_mfa_secret = secret
    session.flush()
    return secret, provisioning_uri(secret, user.username)


def confirm_mfa_enrollment(session: Session, user_id: int, code: str, *,
                           ip_address: str | None = None) -> models.User:
    """Activate MFA once the user proves they can generate a valid code from the pending secret."""
    user = session.get(models.User, user_id)
    if user is None or not user.pending_mfa_secret:
        raise InvalidCredentials("no MFA enrollment in progress")
    if not verify_totp(user.pending_mfa_secret, code):
        record_audit(session, AuditAction.CONFIG_CHANGED, user.username, "FAILURE", ip_address=ip_address,
                    detail="MFA enrollment: invalid code")
        raise InvalidCredentials("invalid authentication code")
    user.mfa_secret = user.pending_mfa_secret
    user.pending_mfa_secret = None
    user.mfa_enabled = True
    session.flush()
    record_audit(session, AuditAction.CONFIG_CHANGED, user.username, "SUCCESS", ip_address=ip_address,
                resource=f"user:{user.id}", detail="MFA enabled")
    return user


def change_password(session: Session, user_id: int, current_password: str, new_password: str, *,
                    ip_address: str | None = None) -> models.User:
    """Change a user's own password. Verifies the current password and the new password's strength."""
    user = session.get(models.User, user_id)
    if user is None:
        raise LookupError(f"user {user_id} not found")
    if not verify_password(current_password, user.password_hash):
        record_audit(session, AuditAction.CONFIG_CHANGED, user.username, "FAILURE", ip_address=ip_address,
                    detail="password change: current password incorrect")
        raise InvalidCredentials("current password is incorrect")
    problems = validate_password_strength(new_password, user.username)
    if problems:
        raise ValueError("weak password: " + "; ".join(problems))
    user.password_hash = hash_password(new_password)
    session.flush()
    record_audit(session, AuditAction.CONFIG_CHANGED, user.username, "SUCCESS", ip_address=ip_address,
                resource=f"user:{user.id}", detail="password changed")
    return user


def disable_mfa(session: Session, user_id: int, *, disabled_by: str, ip_address: str | None = None) -> models.User:
    user = session.get(models.User, user_id)
    if user is None:
        raise LookupError(f"user {user_id} not found")
    user.mfa_enabled, user.mfa_secret, user.pending_mfa_secret = False, None, None
    session.flush()
    record_audit(session, AuditAction.CONFIG_CHANGED, disabled_by, "SUCCESS", ip_address=ip_address,
                resource=f"user:{user.id}", detail="MFA disabled")
    return user
