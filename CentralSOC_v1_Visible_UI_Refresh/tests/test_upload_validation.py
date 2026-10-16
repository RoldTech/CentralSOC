import io

import pytest

from regexsoc.web.upload import UploadRejected, looks_like_text, save_stream_to_temp, validate_upload


def test_valid_extensions_accepted():
    assert validate_upload("auth.log", 100) == "auth.log"
    assert validate_upload("notes.txt", 100) == "notes.txt"


@pytest.mark.parametrize("name", ["malware.exe", "script.py", "archive.zip", "noext", "shell.sh"])
def test_disallowed_extensions_rejected(name):
    with pytest.raises(UploadRejected, match="extension"):
        validate_upload(name, 100)


def test_oversized_declared_length_rejected(monkeypatch):
    monkeypatch.setattr("regexsoc.config.max_upload_bytes", lambda: 10)
    with pytest.raises(UploadRejected, match="limit"):
        validate_upload("a.log", 1000)


def test_path_traversal_in_filename_is_neutralised():
    assert validate_upload("../../etc/passwd.log", 10) == "passwd.log"


def test_looks_like_text_accepts_plain_logs():
    assert looks_like_text(b"Mar 10 10:00:00 host sshd[1]: Failed password for root\n")
    assert looks_like_text(b"")


def test_looks_like_text_rejects_binary():
    assert not looks_like_text(bytes(range(0, 50)))  # lots of control bytes and a NUL
    assert not looks_like_text(b"\x00\x01\x02binary")


def test_save_stream_enforces_limit_even_if_header_lied(tmp_path):
    stream = io.BytesIO(b"x" * 2_000_000)
    with pytest.raises(UploadRejected, match="limit"):
        save_stream_to_temp(stream, max_bytes=1000)


def test_save_stream_rejects_binary_content():
    stream = io.BytesIO(b"\x00\x01\x02\x03" * 100)
    with pytest.raises(UploadRejected, match="text"):
        save_stream_to_temp(stream, max_bytes=10_000)


def test_save_stream_writes_valid_text_and_cleans_up_temp_name(tmp_path):
    content = b"Mar 10 10:00:00 host sshd[1]: Accepted password for root from 192.0.2.1 port 1 ssh2\n"
    path = save_stream_to_temp(io.BytesIO(content), max_bytes=10_000)
    try:
        assert path.exists() and path.read_bytes() == content
    finally:
        path.unlink()
