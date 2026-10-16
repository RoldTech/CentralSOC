"""Regression tests for conservative within-batch alert deduplication."""
from datetime import datetime, timezone
from regexsoc.detectors.base import Detection
from regexsoc.services.alerts import build_alerts


def detection(*, event_ids=None, reason="match", risk_score=80, username="alice", rule_id="R-1"):
    return Detection(
        rule_id=rule_id, rule_name="Test", category="auth", severity="HIGH",
        risk_score=risk_score, recommended_response="Investigate", reason=reason,
        source_ip="192.0.2.10", username=username, timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        event_ids=event_ids or [1], evidence=[reason],
    )


def test_duplicate_alerts_merge_evidence_and_event_ids():
    alerts = build_alerts([detection(), detection(event_ids=[1, 2], reason="additional", risk_score=90)], 70)
    assert len(alerts) == 1
    assert alerts[0].risk_score == 90
    assert alerts[0].event_ids == [1, 2]
    assert alerts[0].evidence == ["match", "additional"]


def test_distinct_rules_and_accounts_remain_separate():
    alerts = build_alerts([detection(), detection(rule_id="R-2"), detection(username="bob")], 70)
    assert len(alerts) == 3


def test_alert_score_threshold_applied_before_merging():
    alerts = build_alerts([detection(risk_score=60), detection(risk_score=80)], 70)
    assert len(alerts) == 1
    assert alerts[0].risk_score == 80
