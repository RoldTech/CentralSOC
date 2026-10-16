from regexsoc.detectors import extract_iocs
from regexsoc.parsers import parse_line
from regexsoc.rules import default_rules

RULES = default_rules()


def iocs(line: str) -> set[tuple[str, str]]:
    event = parse_line(line, year=2024)
    event.id = 1
    return {(i.ioc_type, i.value) for i in extract_iocs(event, RULES)}


def test_ipv4_and_ipv6():
    found = iocs("conn from 203.0.113.5 and 2001:db8::5 ok")
    assert ("IPV4", "203.0.113.5") in found and ("IPV6", "2001:db8::5") in found


def test_invalid_ipv4_not_extracted():
    assert not any(t == "IPV4" for t, _ in iocs("value 999.999.999.999 here"))


def test_time_strings_are_not_ipv6():
    assert not any(t == "IPV6" for t, _ in iocs("started at 13:04:00 and ended 10:15:30"))


def test_domain_url_email():
    found = iocs("user=a url=http://evil.example.com/x.php?a=1, mail=bob@example.org")
    assert ("URL", "http://evil.example.com/x.php?a=1") in found
    assert ("DOMAIN", "evil.example.com") in found
    assert ("EMAIL", "bob@example.org") in found


def test_url_trailing_punctuation_trimmed():
    assert ("URL", "http://a.example.com/x") in iocs("see (http://a.example.com/x).")


def test_hashes_by_length_without_cross_matching():
    md5, sha1, sha256 = "d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    found = iocs(f"m={md5} s1={sha1} s2={sha256}")
    assert {("MD5", md5), ("SHA1", sha1), ("SHA256", sha256)} <= found
    assert sum(1 for t, _ in found if t == "MD5") == 1  # SHA-256 must not also yield a 32-char MD5


def test_uppercase_hash_is_normalized():
    assert ("MD5", "d41d8cd98f00b204e9800998ecf8427e") in iocs("H=D41D8CD98F00B204E9800998ECF8427E")


def test_cve():
    assert ("CVE", "CVE-2021-44228") in iocs("blocked cve-2021-44228 attempt")


def test_file_paths():
    found = iocs(r"ran C:\Windows\Temp\update.exe and /tmp/.x/run.sh")
    assert ("FILE_PATH", r"C:\Windows\Temp\update.exe") in found and ("FILE_PATH", "/tmp/.x/run.sh") in found


def test_ioc_records_provenance():
    event = parse_line("2024-03-10T10:00:00Z proxy blocked 203.0.113.5")
    event.id = 7
    ioc = next(i for i in extract_iocs(event, RULES) if i.ioc_type == "IPV4")
    assert ioc.event_id == 7 and ioc.timestamp == event.timestamp and "203.0.113.5" in ioc.context


def test_no_iocs_in_plain_text():
    assert iocs("nothing interesting here at all") == set()
