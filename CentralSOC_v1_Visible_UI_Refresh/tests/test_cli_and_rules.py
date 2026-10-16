import json
from pathlib import Path

import pytest

from regexsoc.cli import main
from regexsoc.rules import UnknownRuleError, load_rules, set_enabled
from regexsoc.rules.docs import render_markdown
from regexsoc.services.monitor import StreamAnalyzer
from regexsoc.services import Analyzer
from conftest import ssh_fail

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"


def test_analyze_json_on_sample(capsys):
    assert main(["analyze", str(SAMPLES / "ssh_auth.log"), "--year", "2024", "--format", "json", "--severity", "high"]) == 0
    data = json.loads(capsys.readouterr().out)
    ids = {a["rule_id"] for a in data["alerts"]}
    assert {"RULE-002", "RULE-003", "RULE-004"} <= ids


def test_analyze_text_severity_filter(capsys):
    main(["analyze", str(SAMPLES / "apache_access.log"), "--severity", "high"])
    out = capsys.readouterr().out
    assert "RULE-006" in out and "RULE-013" not in out


def test_benign_sample_has_no_alerts(capsys):
    main(["analyze", str(SAMPLES / "benign_traffic.log"), "--year", "2024", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["alerts"] == []


def test_extract_iocs_cli(capsys):
    main(["extract-iocs", str(SAMPLES / "ioc_sample.log"), "--type", "sha256"])
    assert "e3b0c442" in capsys.readouterr().out


def test_report_cli(capsys):
    main(["report", str(SAMPLES / "windows_auth.log")])
    out = capsys.readouterr().out
    assert "Risk profiles" in out and "RULE-002" in out and "never takes action" in out


def test_missing_file_returns_error_code(capsys):
    assert main(["analyze", "/nonexistent/file.log"]) == 2
    assert "error" in capsys.readouterr().err


def test_csv_output_is_sanitised(capsys):
    main(["analyze", str(SAMPLES / "apache_access.log"), "--format", "csv"])
    assert "rule_id" in capsys.readouterr().out.splitlines()[0]


def test_rule_enable_disable_persists(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("REGEXSOC_RULE_STATE", str(tmp_path / "state.json"))
    assert main(["rules", "disable", "rule-006"]) == 0
    assert next(r for r in load_rules() if r.id == "RULE-006").enabled is False
    assert main(["rules", "enable", "RULE-006"]) == 0
    assert next(r for r in load_rules() if r.id == "RULE-006").enabled is True


def test_unknown_rule_is_rejected(tmp_path):
    with pytest.raises(UnknownRuleError):
        set_enabled("RULE-999", True, tmp_path / "s.json")


def test_corrupt_rule_state_is_reported_not_ignored(tmp_path):
    bad = tmp_path / "s.json"
    bad.write_text("{not json")
    with pytest.raises(RuntimeError):
        load_rules(bad)


def test_all_required_rules_present_and_documented():
    rules = load_rules()
    assert [r.id for r in rules][:21] == [f"RULE-{i:03d}" for i in range(1, 22)]
    md = render_markdown(rules)
    for r in rules:
        assert f"## {r.id}: {r.name}" in md
        assert r.example and r.why and r.false_positives and r.recommended_response


def test_all_rule_patterns_compile_and_have_metadata():
    for r in load_rules():
        assert r.patterns and r.regexes and 0 <= r.risk_score <= 100


def test_stream_analyzer_alerts_once_per_cooldown():
    stream = StreamAnalyzer(Analyzer(default_year=2024))
    alerts = []
    for i in range(30):
        alerts += stream.feed(ssh_fail(i * 2))
    assert [a.rule_id for a in alerts].count("RULE-002") == 1


def test_stream_analyzer_ignores_blank_lines():
    assert StreamAnalyzer(Analyzer()).feed("   ") == []
