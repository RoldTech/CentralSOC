"""Small helpers shared across decorators, error handlers, and routes."""

from __future__ import annotations

from flask import request


def wants_json() -> bool:
    """True if the response should be JSON: API paths always; other paths only on explicit request."""
    return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"
