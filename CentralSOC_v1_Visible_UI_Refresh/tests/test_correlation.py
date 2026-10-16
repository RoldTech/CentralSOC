from conftest import ssh_fail, ssh_ok, web
from regexsoc.services import Analyzer


def rules_fired(lines: list[str]) -> dict[str, list]:
    result = Analyzer(default_year=2024).analyze_lines(lines)
    out: dict[str, list] = {}
    for d in result.detections:
        out.setdefault(d.rule_id, []).append(d)
    return out


def test_brute_force_detected_with_score_and_evidence():
    fired = rules_fired([ssh_fail(i * 5) for i in range(47)])
    d = fired["RULE-002"][0]
    assert d.risk_score == 90 and d.severity == "CRITICAL"
    assert d.source_ip == "203.0.113.5" and d.details["count"] == 47 and len(d.evidence) == 5


def test_slow_failures_do_not_trigger_brute_force():
    assert "RULE-002" not in rules_fired([ssh_fail(i * 120) for i in range(12)])  # 1 per 2 min


def test_below_threshold_does_not_trigger():
    assert "RULE-002" not in rules_fired([ssh_fail(i) for i in range(9)])


def test_brute_force_is_per_source_ip():
    lines = [ssh_fail(i, ip=f"203.0.113.{i + 1}") for i in range(20)]  # 20 IPs, 1 failure each
    assert "RULE-002" not in rules_fired(lines)


def test_password_spraying_detected():
    users = ["admin", "root", "test", "oracle", "ubuntu", "deploy"]
    fired = rules_fired([ssh_fail(i * 30, user=u) for i, u in enumerate(users)])
    assert fired["RULE-003"][0].details["distinct"] == 6
    assert "RULE-002" not in fired


def test_brute_force_on_few_accounts_is_not_spraying():
    lines = [ssh_fail(i * 3, user=("root", "admin")[i % 2]) for i in range(30)]
    fired = rules_fired(lines)
    assert "RULE-002" in fired and "RULE-003" not in fired


def test_success_after_multiple_failures():
    fired = rules_fired([ssh_fail(i * 5, user="deploy") for i in range(6)] + [ssh_ok(40, user="deploy")])
    d = fired["RULE-004"][0]
    assert d.username == "deploy" and d.risk_score == 85


def test_success_without_prior_failures_is_not_flagged():
    assert "RULE-004" not in rules_fired([ssh_ok(0)])


def test_success_after_few_failures_is_not_flagged():
    assert "RULE-004" not in rules_fired([ssh_fail(0), ssh_fail(5), ssh_ok(10)])


def test_success_from_different_ip_is_not_flagged():
    lines = [ssh_fail(i * 5) for i in range(8)] + [ssh_ok(60, ip="192.0.2.99")]
    assert "RULE-004" not in rules_fired(lines)


def test_port_scan_detected_from_firewall_logs():
    lines = [f"Mar 10 10:00:{i:02d} fw kernel: [UFW BLOCK] SRC=203.0.113.200 DST=10.0.0.5 PROTO=TCP SPT=4000 DPT={20 + i}"
             for i in range(20)]
    assert "RULE-005" in rules_fired(lines)


def test_repeated_connections_to_one_port_are_not_a_scan():
    lines = [f"Mar 10 10:00:{i:02d} fw kernel: [UFW BLOCK] SRC=203.0.113.200 DST=10.0.0.5 PROTO=TCP SPT=4000 DPT=443"
             for i in range(30)]
    assert "RULE-005" not in rules_fired(lines)


def test_excessive_404s_and_403s():
    assert "RULE-011" in rules_fired([web(i, f"/p{i}", 404) for i in range(25)])
    assert "RULE-012" in rules_fired([web(i, f"/p{i}", 403) for i in range(20)])


def test_few_404s_are_normal():
    assert "RULE-011" not in rules_fired([web(i * 10, f"/p{i}", 404) for i in range(5)])


def test_events_without_timestamps_do_not_crash_correlation():
    lines = ["login failed for user=x from 203.0.113.5"] * 30
    Analyzer().analyze_lines(lines)  # must not raise


def test_success_for_different_account_is_not_correlated():
    # All failures come from alice, but the successful authentication is bob.
    lines = [ssh_fail(i * 5, user="alice") for i in range(7)] + [ssh_ok(40, user="bob")]
    assert "RULE-004" not in rules_fired(lines)
