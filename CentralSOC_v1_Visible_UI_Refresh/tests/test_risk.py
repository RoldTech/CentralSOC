import json

import pytest

from conftest import ssh_fail, web
from regexsoc.services import Analyzer, ScoringConfig
from regexsoc.services.risk import profile_entities


def test_default_bands():
    c = ScoringConfig()
    assert [c.severity_for(s) for s in (0, 29, 30, 59, 60, 79, 80, 100)] == [
        "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]


def test_rule_severity_matches_score_bands():
    from regexsoc.rules import default_rules
    c = ScoringConfig()
    for r in default_rules():
        assert c.severity_for(r.risk_score) == r.severity, r.id


def test_profile_lists_reasons_and_caps_at_100():
    lines = [ssh_fail(i * 5) for i in range(12)] + [web(100, "/.env", 200, ip="203.0.113.5")]
    profile = Analyzer(default_year=2024).analyze_lines(lines).profiles["203.0.113.5"]
    texts = [str(r) for r in profile.reasons]
    assert any(t.startswith("+90 SSH Brute Force") for t in texts)
    assert any("Sensitive File Access" in t for t in texts)
    assert any("Repeated" in t for t in texts)
    assert profile.score == 100 and profile.severity == "CRITICAL"


def test_each_distinct_rule_counts_once_plus_repeat_bonus():
    lines = [web(i, "/.env") for i in range(3)]  # 3 hits of one rule
    p = Analyzer().analyze_lines(lines).profiles["203.0.113.9"]
    assert p.score == 30 + 10


def test_points_are_configurable():
    cfg = ScoringConfig(points={"RULE-010": 55})
    alerts = Analyzer(scoring=cfg).analyze_lines([web(0, "/.env")]).alerts
    assert alerts[0].risk_score == 55 and alerts[0].severity == "MEDIUM"


def test_alert_threshold_controls_alerting():
    lines = [web(0, "/.env")]
    assert Analyzer(scoring=ScoringConfig(alert_threshold=50)).analyze_lines(lines).alerts == []
    assert len(Analyzer(scoring=ScoringConfig(alert_threshold=30)).analyze_lines(lines).alerts) == 1


def test_scoring_file_rejects_unknown_keys(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"points": {}, "bogus": 1}))
    with pytest.raises(ValueError):
        ScoringConfig.from_file(f)


def test_points_are_clamped():
    assert ScoringConfig(points={"X": 999}).points_for("X", 1) == 100
    assert ScoringConfig(points={"X": -5}).points_for("X", 1) == 0


def test_known_ioc_adds_40_points():
    a = Analyzer(watchlist=["203.0.113.9"])
    r = a.analyze_lines([web(0, "/index.html")])
    hit = next(d for d in r.detections if d.rule_id == "RULE-024")
    assert hit.risk_score == 40
    assert Analyzer().analyze_lines([web(0, "/index.html")]).detections == []


def test_alert_ids_are_deterministic_and_have_new_status():
    lines = [web(0, "/.env")]
    a1 = Analyzer().analyze_lines(lines).alerts[0]
    a2 = Analyzer().analyze_lines(lines).alerts[0]
    assert a1.alert_id == a2.alert_id and a1.status == "New" and a1.evidence


def test_profile_ignores_zero_score_entities():
    assert profile_entities([], ScoringConfig()) == {}
