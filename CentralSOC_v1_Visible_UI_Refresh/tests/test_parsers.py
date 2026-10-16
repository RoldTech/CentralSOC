import pytest

from regexsoc.models import EventType
from regexsoc.parsers import parse_line, parse_lines

SSH_FAIL = "Mar 10 10:15:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2"
SSH_OK = "Mar 10 10:15:09 web01 sshd[1234]: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2"
APACHE = '203.0.113.9 - bob [10/Mar/2024:10:15:01 +0000] "GET /a/b.php?id=5&x=y HTTP/1.1" 404 196 "-" "Mozilla/5.0"'
WINDOWS = "2024-03-10T10:15:01Z DC01 Security EventID=4625 TargetUserName=admin IpAddress=198.51.100.7 IpPort=49152 LogonType=10"
FIREWALL = "Mar 10 10:15:01 fw kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.50 DST=10.0.0.5 PROTO=TCP SPT=40000 DPT=22"


def test_ssh_failed_login_fields():
    e = parse_line(SSH_FAIL, year=2024)
    assert e.event_type == EventType.FAILED_LOGIN
    assert e.source_ip == "203.0.113.5"
    assert e.username == "admin"
    assert e.source_port == 54321
    assert e.destination_port == 22
    assert e.protocol == "SSH"
    assert e.auth_status == "FAILURE"
    assert e.timestamp.year == 2024 and e.timestamp.hour == 10
    assert e.raw_log == SSH_FAIL


def test_ssh_successful_login():
    e = parse_line(SSH_OK, year=2024)
    assert e.event_type == EventType.LOGIN_SUCCESS and e.username == "alice" and e.auth_status == "SUCCESS"


def test_invalid_user_line_is_not_counted_as_failed_login():
    e = parse_line("Mar 10 10:15:01 web01 sshd[9]: Invalid user guest from 203.0.113.5 port 60002", year=2024)
    assert e.event_type == EventType.INVALID_USER


def test_ipv6_source_extraction():
    e = parse_line("Mar 10 10:15:01 web01 sshd[9]: Failed password for root from 2001:db8::5 port 4000 ssh2", year=2024)
    assert e.source_ip == "2001:db8::5" and e.source_port == 4000


def test_apache_fields():
    e = parse_line(APACHE)
    assert (e.source_ip, e.username, e.http_method, e.http_path, e.http_status) == (
        "203.0.113.9", "bob", "GET", "/a/b.php", 404)
    assert e.request_params == {"id": "5", "x": "y"}
    assert e.user_agent == "Mozilla/5.0" and e.protocol == "HTTP"
    assert e.timestamp.isoformat() == "2024-03-10T10:15:01+00:00"


def test_apache_timezone_is_normalized_to_utc():
    e = parse_line('203.0.113.9 - - [10/Mar/2024:12:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "x"')
    assert e.timestamp.hour == 10


def test_nginx_combined_with_ipv6_client():
    e = parse_line('2001:db8::1 - - [10/Mar/2024:10:15:01 +0000] "POST /login HTTP/2.0" 401 12 "-" "curl/8.0"')
    assert e.source_ip == "2001:db8::1" and e.http_method == "POST" and e.http_status == 401


def test_malformed_request_line_still_parses():
    e = parse_line('203.0.113.9 - - [10/Mar/2024:10:15:01 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"')
    assert e is not None and e.http_status == 400 and e.http_method is None


def test_windows_event():
    e = parse_line(WINDOWS)
    assert e.event_type == EventType.FAILED_LOGIN and e.username == "admin"
    assert e.source_ip == "198.51.100.7" and e.source_port == 49152 and e.protocol == "RDP"


def test_firewall_event():
    e = parse_line(FIREWALL, year=2024)
    assert e.event_type == EventType.CONNECTION_BLOCKED
    assert (e.source_ip, e.destination_ip, e.destination_port, e.protocol) == ("203.0.113.50", "10.0.0.5", 22, "TCP")


def test_generic_fallback():
    e = parse_line("2024-03-10 10:15:01 login failed for user=bob from 192.0.2.44")
    assert e.source_format == "generic" and e.event_type == EventType.FAILED_LOGIN
    assert e.username == "bob" and e.source_ip == "192.0.2.44"


@pytest.mark.parametrize("line", ["", "   ", "# comment"])
def test_blank_and_comment_lines_are_skipped(line):
    assert parse_line(line) is None


def test_garbage_does_not_crash_and_long_lines_are_truncated():
    e = parse_line("\x00\x01 garbage " + "A" * 50_000)
    assert e is not None and len(e.raw_log) <= 8192


def test_invalid_ip_is_rejected():
    e = parse_line("Mar 10 10:15:01 web01 sshd[9]: Failed password for root from 999.1.1.1 port 4000 ssh2", year=2024)
    assert e.source_ip is None


def test_parse_lines_assigns_sequential_ids():
    events = parse_lines([SSH_FAIL, "", SSH_OK], year=2024)
    assert [e.id for e in events] == [1, 2]
