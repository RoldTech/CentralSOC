import json

import pytest

from regexsoc.security.audit import REDACTED, clean_text, format_detail, redact
from regexsoc.security.files import sanitize_filename


def test_newlines_cannot_forge_audit_lines():
    text = clean_text("alice\n2024-01-01 admin LOGIN SUCCESS\r\nx")
    assert "\n" not in text and "\r" not in text


@pytest.mark.parametrize("raw", ["password=hunter2", "login failed password: hunter2 ok", "token=abc123",
                                 "Authorization: Bearer abc.def.ghi", "api_key='k-123'", "cookie=sessionid=xyz"])
def test_inline_secrets_are_redacted(raw):
    out = clean_text(raw)
    assert REDACTED in out
    for secret in ("hunter2", "abc123", "abc.def.ghi", "k-123", "xyz"):
        assert secret not in out


def test_normal_text_is_untouched():
    assert clean_text("uploaded ssh_auth.log (67 events)") == "uploaded ssh_auth.log (67 events)"


def test_truncation():
    out = clean_text("a" * 1000, max_len=50)
    assert len(out) == 50 and out.endswith("\u2026")


def test_redact_nested_structures():
    data = {"user": "bob", "password": "x", "nested": {"session_token": "y", "ok": 1}, "list": [{"api_key": "z"}]}
    out = redact(data)
    assert out["user"] == "bob" and out["password"] == REDACTED
    assert out["nested"] == {"session_token": REDACTED, "ok": 1}
    assert out["list"][0]["api_key"] == REDACTED


def test_format_detail_mapping_never_leaks():
    out = format_detail({"password": "hunter2", "note": "password=hunter2", "file": "a.log"})
    assert "hunter2" not in out and json.loads(out)["file"] == "a.log"


def test_format_detail_none():
    assert format_detail(None) is None


@pytest.mark.parametrize("name,expected", [
    ("../../etc/passwd", "passwd"),
    ("C:\\Users\\a b\\evil.log", "evil.log"),
    ("..", "upload.log"),
    (".hidden", "hidden"),
    ("we ird;$(name).log", "we_ird___name_.log"),
    ("", "upload.log"),
    (None, "upload.log"),
    ("ok-file_1.log", "ok-file_1.log"),
])
def test_sanitize_filename(name, expected):
    assert sanitize_filename(name) == expected


def test_sanitize_filename_length_limit():
    assert len(sanitize_filename("a" * 500 + ".log")) <= 120
