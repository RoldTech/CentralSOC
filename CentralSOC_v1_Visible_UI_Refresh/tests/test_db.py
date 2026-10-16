"""Database-layer tests. Skipped automatically when SQLAlchemy is not installed."""

import os
import re
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import delete, func, select, update  # noqa: E402

from regexsoc.cli import main  # noqa: E402
from regexsoc.db import models  # noqa: E402
from regexsoc.db.service import (  # noqa: E402
    ingest_file, list_alerts, list_audit, record_audit, update_alert_status, verify_log_file,
)
from regexsoc.db.session import init_db, make_engine, session_scope  # noqa: E402
from regexsoc.security.integrity import sha256_file  # noqa: E402
from regexsoc.services import Analyzer  # noqa: E402

SAMPLE = Path(__file__).resolve().parent.parent / "sample_logs" / "ssh_auth.log"


def fresh_engine():
    engine = make_engine("sqlite://")
    init_db(engine)
    return engine


def do_ingest(engine, tmp_path, path=SAMPLE, user="analyst1"):
    with session_scope(engine) as s:
        return ingest_file(s, path, uploaded_by=user, upload_dir=tmp_path / "uploads",
                           analyzer=Analyzer(default_year=2024))


def count(engine, model):
    with session_scope(engine) as s:
        return s.scalar(select(func.count()).select_from(model))


def verify(engine, tmp_path, file_id=1):
    with session_scope(engine) as s:
        return verify_log_file(s, file_id, upload_dir=tmp_path / "uploads")


def test_ingest_persists_everything(tmp_path):
    engine = fresh_engine()
    expected = Analyzer(default_year=2024).analyze_file(SAMPLE)
    result = do_ingest(engine, tmp_path)
    assert not result.duplicate
    assert count(engine, models.Event) == len(expected.events)
    assert count(engine, models.Alert) == len(expected.alerts)
    assert count(engine, models.Detection) == len(expected.detections)
    assert count(engine, models.IOC) == len(expected.iocs)


def test_stored_copy_has_random_name_and_matching_hash(tmp_path):
    engine = fresh_engine()
    lf = do_ingest(engine, tmp_path).log_file
    stored = tmp_path / "uploads" / lf.stored_name
    assert stored.exists() and lf.stored_name != SAMPLE.name
    assert re.fullmatch(r"[0-9a-f]{32}\.log", lf.stored_name)
    assert lf.sha256 == sha256_file(SAMPLE) == sha256_file(stored)


def test_duplicate_upload_is_idempotent(tmp_path):
    engine = fresh_engine()
    first = do_ingest(engine, tmp_path)
    second = do_ingest(engine, tmp_path)
    assert second.duplicate and second.log_file.id == first.log_file.id
    assert count(engine, models.LogFile) == 1
    assert len(list((tmp_path / "uploads").iterdir())) == 1  # the duplicate copy was discarded


def test_intact_data_verifies(tmp_path):
    engine = fresh_engine()
    do_ingest(engine, tmp_path)
    report = verify(engine, tmp_path)
    assert report.ok and report.file_status == "OK" and report.original_hash == report.current_hash


def test_modified_event_row_is_detected(tmp_path):
    engine = fresh_engine()
    do_ingest(engine, tmp_path)
    with session_scope(engine) as s:
        s.execute(update(models.Event).where(models.Event.seq == 5).values(username="mallory"))
    report = verify(engine, tmp_path)
    assert not report.ok and report.chain.broken_at == 5 and report.file_status == "OK"


def test_deleted_event_row_is_detected(tmp_path):
    engine = fresh_engine()
    do_ingest(engine, tmp_path)
    with session_scope(engine) as s:
        s.execute(delete(models.Event).where(models.Event.seq == 3))
    report = verify(engine, tmp_path)
    assert not report.ok and report.chain.broken_at == 3


def test_tampered_stored_file_is_detected(tmp_path):
    engine = fresh_engine()
    lf = do_ingest(engine, tmp_path).log_file
    stored = tmp_path / "uploads" / lf.stored_name
    os.chmod(stored, 0o600)
    with open(stored, "a", encoding="utf-8") as handle:
        handle.write("Mar 10 10:00:00 web01 sshd[1]: Accepted password for root from 203.0.113.99 port 1 ssh2\n")
    report = verify(engine, tmp_path)
    assert report.file_status == "TAMPERED" and report.original_hash != report.current_hash and not report.ok


def test_missing_stored_file_is_reported(tmp_path):
    engine = fresh_engine()
    lf = do_ingest(engine, tmp_path).log_file
    stored = tmp_path / "uploads" / lf.stored_name
    os.chmod(stored, 0o600)
    stored.unlink()
    report = verify(engine, tmp_path)
    assert report.file_status == "MISSING" and report.current_hash is None


def test_verify_unknown_file_raises(tmp_path):
    engine = fresh_engine()
    with pytest.raises(LookupError):
        verify(engine, tmp_path, file_id=99)


def test_alert_ids_are_unique_and_prefixed(tmp_path):
    engine = fresh_engine()
    do_ingest(engine, tmp_path)
    with session_scope(engine) as s:
        ids = list(s.scalars(select(models.Alert.alert_id)))
    assert ids and len(ids) == len(set(ids)) and all(re.fullmatch(r"ALERT-[0-9A-F]{10}", i) for i in ids)


def test_alert_status_update_is_audited(tmp_path):
    engine = fresh_engine()
    do_ingest(engine, tmp_path)
    with session_scope(engine) as s:
        alert_id = list_alerts(s)[0].alert_id
    with session_scope(engine) as s:
        alert = update_alert_status(s, alert_id, "investigating", "carol", note="looking into it")
        assert alert.status == "Investigating" and alert.updated_by == "carol"
    with session_scope(engine) as s:
        entries = [a for a in list_audit(s) if a.action == "ALERT_STATUS_CHANGED"]
    assert entries and entries[0].username == "carol" and entries[0].result == "SUCCESS"
    assert "Investigating" in entries[0].detail


def test_false_positive_status_accepts_friendly_spellings(tmp_path):
    engine = fresh_engine()
    do_ingest(engine, tmp_path)
    with session_scope(engine) as s:
        alert_id = list_alerts(s)[0].alert_id
        assert update_alert_status(s, alert_id, "false-positive", "x").status == "False Positive"


def test_invalid_status_is_rejected(tmp_path):
    engine = fresh_engine()
    do_ingest(engine, tmp_path)
    with session_scope(engine) as s:
        alert_id = list_alerts(s)[0].alert_id
    with pytest.raises(ValueError):
        with session_scope(engine) as s:
            update_alert_status(s, alert_id, "closed-lol", "x")


def test_unknown_alert_raises_and_the_failed_attempt_is_audited(tmp_path):
    engine = fresh_engine()
    with session_scope(engine) as s:
        with pytest.raises(LookupError):
            update_alert_status(s, "ALERT-DOESNOTEXIST", "resolved", "mallory")
        s.commit()  # keep the audit row that was written before the error
        failures = [a for a in list_audit(s) if a.result == "FAILURE"]
    assert failures and failures[0].username == "mallory"


def test_list_alerts_filters(tmp_path):
    engine = fresh_engine()
    do_ingest(engine, tmp_path)
    with session_scope(engine) as s:
        critical = list_alerts(s, min_severity="critical")
        assert critical and all(a.severity == "CRITICAL" for a in critical)
        assert list_alerts(s, status="resolved") == []


def test_audit_log_never_stores_secrets_or_forged_lines():
    engine = fresh_engine()
    with session_scope(engine) as s:
        row = record_audit(s, "LOGIN_FAILED", "bob\nFAKE LINE", "FAILURE", ip_address="203.0.113.5",
                           detail={"password": "hunter2", "note": "password=hunter2", "totp": "123456"})
        assert "hunter2" not in row.detail and "123456" not in row.detail
        assert "\n" not in row.username


def test_audit_rejects_invalid_result():
    engine = fresh_engine()
    with session_scope(engine) as s:
        with pytest.raises(ValueError):
            record_audit(s, "X", "u", "MAYBE")


def test_oversized_file_is_rejected_and_nothing_is_stored(tmp_path, monkeypatch):
    monkeypatch.setenv("REGEXSOC_MAX_INPUT_BYTES", "100")
    engine = fresh_engine()
    with pytest.raises(ValueError):
        do_ingest(engine, tmp_path)
    assert not (tmp_path / "uploads").exists() or not list((tmp_path / "uploads").iterdir())
    assert count(engine, models.LogFile) == 0


def test_failed_ingest_leaves_no_partial_data(tmp_path):
    engine = fresh_engine()

    class Boom(Analyzer):
        def analyze_file(self, path):
            raise RuntimeError("parser exploded")

    with pytest.raises(RuntimeError):
        with session_scope(engine) as s:
            ingest_file(s, SAMPLE, uploaded_by="x", upload_dir=tmp_path / "uploads", analyzer=Boom())
    assert count(engine, models.LogFile) == 0 and not list((tmp_path / "uploads").iterdir())


def test_hmac_key_changes_hashes_and_is_required_to_verify(tmp_path, monkeypatch):
    monkeypatch.setenv("REGEXSOC_INTEGRITY_KEY", "unit-test-key")
    engine = fresh_engine()
    do_ingest(engine, tmp_path)
    assert verify(engine, tmp_path).ok
    monkeypatch.setenv("REGEXSOC_INTEGRITY_KEY", "a-different-key")
    assert not verify(engine, tmp_path).ok


def test_cli_ingest_verify_alerts_roundtrip(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    monkeypatch.setenv("REGEXSOC_UPLOAD_DIR", str(tmp_path / "up"))
    assert main(["ingest", str(SAMPLE), "--year", "2024", "--user", "tester"]) == 0
    assert "sha256" in capsys.readouterr().out
    assert main(["ingest", str(SAMPLE), "--year", "2024", "--user", "tester"]) == 0
    assert "Already ingested" in capsys.readouterr().out
    assert main(["verify"]) == 0
    assert "[OK]" in capsys.readouterr().out
    assert main(["alerts", "list", "--severity", "critical"]) == 0
    listing = capsys.readouterr().out
    alert_id = re.search(r"ALERT-[0-9A-F]{10}", listing).group(0)
    assert main(["alerts", "set-status", alert_id, "resolved", "--user", "tester"]) == 0
    assert "Resolved" in capsys.readouterr().out
    assert main(["audit"]) == 0
    assert "ALERT_STATUS_CHANGED" in capsys.readouterr().out
    assert main(["alerts", "set-status", "ALERT-NOPE", "resolved"]) == 2
