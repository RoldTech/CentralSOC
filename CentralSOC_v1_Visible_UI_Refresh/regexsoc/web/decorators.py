"""Auth/RBAC decorators. Expect ``before_request`` in the app factory to have set ``g.db`` (a
SQLAlchemy Session) and, if logged in, ``g.current_user``.
"""

from __future__ import annotations

from functools import wraps

from flask import g, jsonify, redirect, request, url_for

from regexsoc.security.rbac import has_permission
from regexsoc.web.request_utils import wants_json


def _deny(status: int, message: str):
    if wants_json():
        return jsonify(error=message), status
    if status == 401:
        return redirect(url_for("auth.login_form", next=request.path))
    return message, status


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if getattr(g, "current_user", None) is None:
            return _deny(401, "authentication required")
        return view(*args, **kwargs)

    return wrapped


def permission_required(permission: str):
    """Stack under ``login_required`` (or use standalone; it also enforces login)."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return _deny(401, "authentication required")
            if not has_permission(user.role, permission):
                return _deny(403, f"role {user.role} lacks permission {permission!r}")
            return view(*args, **kwargs)

        return wrapped

    return decorator
