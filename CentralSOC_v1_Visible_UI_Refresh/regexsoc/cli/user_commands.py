"""CLI handlers for `regexsoc users ...`."""

from __future__ import annotations

import argparse
import getpass


def _engine():
    from regexsoc.db.session import init_db, make_engine

    engine = make_engine()
    init_db(engine)
    return engine


def create(args: argparse.Namespace) -> int:
    from sqlalchemy import select

    from regexsoc.db import models
    from regexsoc.db.auth_service import create_user, user_count
    from regexsoc.db.session import session_scope

    engine = _engine()
    password = args.password or getpass.getpass("Password: ")
    if not args.password and password != getpass.getpass("Confirm password: "):
        print("Passwords did not match.")
        return 2
    with session_scope(engine) as session:
        first_user = user_count(session) == 0
        try:
            user = create_user(session, args.username, password, args.role, email=args.email,
                               created_by=f"cli:{getpass.getuser()}")
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
        if first_user and args.role != "ADMIN":
            print(f"Note: {user.username} is the first user but was created as {args.role}, not ADMIN. "
                 f"Run 'python -m regexsoc users set-role {user.username} ADMIN' if that was a mistake.")
    print(f"Created user {user.username} ({user.role})")
    return 0


def list_users(args: argparse.Namespace) -> int:
    from sqlalchemy import select

    from regexsoc.db import models
    from regexsoc.db.session import session_scope

    engine = _engine()
    with session_scope(engine) as session:
        for u in session.scalars(select(models.User).order_by(models.User.id)):
            flags = ("active" if u.is_active else "DISABLED") + (", mfa" if u.mfa_enabled else "")
            print(f"{u.id:>4}  {u.username:<20} {u.role:<8} {flags}")
    return 0


def set_role(args: argparse.Namespace) -> int:
    from regexsoc.db.auth_service import set_role as _set_role
    from regexsoc.db.session import session_scope

    engine = _engine()
    with session_scope(engine) as session:
        try:
            user = _set_role(session, args.username, args.role, changed_by=f"cli:{getpass.getuser()}")
        except (ValueError, LookupError) as exc:
            print(f"error: {exc}")
            return 2
    print(f"{user.username} is now {user.role}")
    return 0


def set_active(args: argparse.Namespace, active: bool) -> int:
    from regexsoc.db.auth_service import set_active as _set_active
    from regexsoc.db.session import session_scope

    engine = _engine()
    with session_scope(engine) as session:
        try:
            user = _set_active(session, args.username, active, changed_by=f"cli:{getpass.getuser()}")
        except LookupError as exc:
            print(f"error: {exc}")
            return 2
    print(f"{user.username} is now {'active' if active else 'disabled'}")
    return 0
