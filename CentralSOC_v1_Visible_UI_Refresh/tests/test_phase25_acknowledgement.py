"""Phase 25: first acknowledgement, transactionality, timing calculations."""
from datetime import datetime, timedelta
import pytest
from sqlalchemy import select
from regexsoc.db import models
from regexsoc.db.session import make_engine, init_db, session_scope
from regexsoc.db.service import acknowledge_alert, alert_activity
from regexsoc.db.dashboard_queries import acknowledgement_metrics

def seed():
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    with session_scope(engine) as s:
        f = models.LogFile(original_name="a.log", stored_name="one", size_bytes=1, sha256="a"*64, uploaded_by="test")
        s.add(f); s.flush()
        s.add(models.Alert(alert_id="AL-P25", log_file_id=f.id, rule_id="RULE", rule_name="Example",
                           timestamp=datetime(2026, 1, 1, 12), severity="LOW", risk_score=10,
                           reason="Synthetic", recommended_response="Review"))
    return engine

def test_first_acknowledgement_is_idempotent_and_audited():
    engine=seed()
    with session_scope(engine) as s:
        row=acknowledge_alert(s,"AL-P25","alice")
        assert row.acknowledged_by == "alice"
        first=row.acknowledged_at
        row=acknowledge_alert(s,"AL-P25","bob")
        assert row.acknowledged_at == first
    with session_scope(engine) as s:
        assert s.scalar(select(models.Alert)).acknowledged_by == "alice"
        assert [a.action for a in alert_activity(s,"AL-P25")] == ["ALERT_ACKNOWLEDGED"]
        assert acknowledgement_metrics(s)["pending"] == 0

def test_failed_transaction_rolls_back_acknowledgement_and_audit():
    engine=seed()
    with pytest.raises(RuntimeError):
        with session_scope(engine) as s:
            acknowledge_alert(s,"AL-P25","alice")
            raise RuntimeError("abort")
    with session_scope(engine) as s:
        assert s.scalar(select(models.Alert)).acknowledged_at is None
        assert alert_activity(s,"AL-P25") == []

def test_unknown_alert_and_actor_validation():
    engine=seed()
    with session_scope(engine) as s:
        with pytest.raises(LookupError): acknowledge_alert(s,"missing","alice")
        with pytest.raises(ValueError): acknowledge_alert(s,"AL-P25", "")

def test_mt_ack_excludes_negative_and_missing_timestamps():
    engine=seed()
    with session_scope(engine) as s:
        row=s.scalar(select(models.Alert))
        row.acknowledged_at=row.timestamp+timedelta(minutes=5)
        row.acknowledged_by="alice"
        assert acknowledgement_metrics(s)["mean_time_to_ack_seconds"] == 300.0
        row.acknowledged_at=row.timestamp-timedelta(seconds=1)
        assert acknowledgement_metrics(s)["mean_time_to_ack_seconds"] is None
        assert acknowledgement_metrics(s)["sample_size"] == 0
