"""Secure log upload: validated, saved to a private temp path, then handed to the existing (Phase 2)
ingest pipeline, which stores it under a random name, hashes it and never executes it.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from regexsoc import config
from regexsoc.security.files import sanitize_filename

CONTROL_CHAR_RATIO_LIMIT = 0.05  # a text log should be almost entirely printable/whitespace


class UploadRejected(ValueError):
    pass


def handle_upload(db_session, file_storage, *, uploaded_by: str, ip_address: str | None):
    """Validate and ingest an uploaded file. Used by both the REST API and the dashboard's Log
    Analysis page, so the two never diverge. Raises UploadRejected on any validation failure;
    the caller decides how to present that (JSON error vs. a flashed message)."""
    from regexsoc.db.service import ingest_file

    if file_storage is None or not file_storage.filename:
        raise UploadRejected("no file was provided")
    safe_name = validate_upload(file_storage.filename, file_storage.content_length)
    tmp_path = save_stream_to_temp(file_storage.stream, config.max_upload_bytes())
    try:
        try:
            return ingest_file(db_session, tmp_path, uploaded_by=uploaded_by, upload_dir=config.upload_dir(),
                               ip_address=ip_address, original_name=safe_name)
        except ValueError as exc:
            raise UploadRejected(str(exc)) from exc
    finally:
        tmp_path.unlink(missing_ok=True)


def validate_upload(filename: str | None, content_length: int | None) -> str:
    """Check extension and declared size before any bytes are read. Returns the sanitized display name."""
    safe_name = sanitize_filename(filename)
    ext = Path(safe_name).suffix.lower()
    if ext not in config.ALLOWED_UPLOAD_EXTENSIONS:
        raise UploadRejected(
            f"unsupported file extension {ext or '(none)'!r}; allowed: {', '.join(config.ALLOWED_UPLOAD_EXTENSIONS)}"
        )
    if content_length is not None and content_length > config.max_upload_bytes():
        raise UploadRejected(f"file is {content_length} bytes; the limit is {config.max_upload_bytes()}")
    return safe_name


def looks_like_text(sample: bytes) -> bool:
    """Heuristic: reject obviously binary content (executables, images...) without needing python-magic."""
    if b"\x00" in sample:
        return False
    if not sample:
        return True
    control = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return (control / len(sample)) <= CONTROL_CHAR_RATIO_LIMIT


def save_stream_to_temp(stream, max_bytes: int) -> Path:
    """Copy an upload stream to a private temp file, enforcing the size limit while copying (a
    declared Content-Length can lie). Raises UploadRejected and cleans up if the limit is exceeded."""
    fd, tmp_path = tempfile.mkstemp(prefix="regexsoc_upload_", suffix=".part")
    written = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := stream.read(1024 * 1024):
                written += len(chunk)
                if written > max_bytes:
                    raise UploadRejected(f"file exceeds the {max_bytes}-byte limit")
                out.write(chunk)
        with open(tmp_path, "rb") as f:
            if not looks_like_text(f.read(4096)):
                raise UploadRejected("file does not look like a text log")
    except BaseException:
        Path(tmp_path).unlink(missing_ok=True)
        raise
    return Path(tmp_path)
