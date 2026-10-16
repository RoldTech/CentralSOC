"""Detection rule catalogue.

Rules are plain data, kept separate from the parsers and detectors. A rule may carry several
focused patterns (any one match fires the rule) instead of one giant regex.

``target`` says what the patterns are matched against:
    raw          the raw log line
    request      the URL-decoded HTTP request target (web events only)
    user_agent   the User-Agent header (web events only)
    correlation  patterns SELECT candidate events; ``params`` describe the window logic
    ioc          patterns EXTRACT indicators (extraction only, no alert by themselves)
    watchlist    fires when an extracted IOC is on a user-supplied watchlist
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache

from regexsoc.utils.patterns import IPV4

# Detection categories
AUTH, WEB, NETWORK, RECON, IOC = "Authentication", "Web Attack", "Network", "Reconnaissance", "IOC"
BEHAVIOR, CONFIG, SYSTEM = "Suspicious Behavior", "Configuration", "System Security"


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


@dataclass
class Rule:
    """A single detection rule."""

    id: str
    name: str
    description: str
    patterns: tuple[str, ...]
    category: str
    severity: str
    risk_score: int
    recommended_response: str
    enabled: bool = True
    target: str = "raw"
    params: dict = field(default_factory=dict)
    why: str = ""
    example: str = ""
    false_positives: str = ""

    @property
    def regexes(self) -> tuple[re.Pattern[str], ...]:
        return tuple(_compile(p) for p in self.patterns)

    def search(self, text: str) -> re.Match[str] | None:
        """Return the first match from any of the rule's patterns."""
        for rx in self.regexes:
            m = rx.search(text)
            if m:
                return m
        return None

    def to_dict(self) -> dict:
        return asdict(self)


FAILED_LOGIN_RX = (
    r"(?i)\bFailed (?:password|publickey|keyboard-interactive/pam) for\b",
    r"\bEventID=4625\b",
    r"(?i)\b(?:login|logon|authentication)\b.{0,20}\b(?:failed|failure|denied)\b",
)
SUCCESS_LOGIN_RX = (
    r"\bAccepted (?:password|publickey|keyboard-interactive/pam) for\b",
    r"\bEventID=4624\b",
)

_SSH_EXAMPLE = "Mar 10 10:15:01 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 54321 ssh2"


def _rules() -> list[Rule]:
    return [
        Rule(
            "RULE-001", "Failed SSH Login", "A single failed SSH authentication attempt.",
            (r"\bFailed (?:password|publickey|keyboard-interactive/pam) for\b",),
            AUTH, "LOW", 10,
            "Note the source IP and account. No action for isolated failures; watch for repetition.",
            why="Failed logins are the raw material of brute-force and credential-stuffing attacks.",
            example=_SSH_EXAMPLE,
            false_positives="Users mistyping passwords; expired credentials; misconfigured automation.",
        ),
        Rule(
            "RULE-002", "SSH Brute Force",
            "Many failed logins from one source IP within a short time window.",
            FAILED_LOGIN_RX, AUTH, "CRITICAL", 90,
            "Review affected accounts; enable MFA; apply authentication rate limiting; check source IP "
            "reputation; consider temporary blocking per organizational policy; check whether a "
            "successful login followed the failures (see RULE-004).",
            target="correlation",
            params={"kind": "threshold", "threshold": 10, "window_seconds": 300},
            why="Sustained guessing against one or more accounts is the classic precursor to account takeover.",
            example="47 x 'Failed password for root from 203.0.113.5' within 5 minutes",
            false_positives="Shared NAT egress IPs, misconfigured monitoring or backup jobs with stale credentials.",
        ),
        Rule(
            "RULE-003", "Password Spraying Indicator",
            "One source IP fails logins against many distinct accounts, with only a few tries per account.",
            FAILED_LOGIN_RX, AUTH, "HIGH", 75,
            "Review all targeted accounts, force resets where any succeeded, enable MFA, review lockout "
            "policy, and hunt for successful logins from the same source.",
            target="correlation",
            params={"kind": "distinct", "field": "username", "threshold": 5, "window_seconds": 600,
                    "max_per_value": 3},
            why="Spraying stays below per-account lockout thresholds, so brute-force rules alone miss it.",
            example="failures for admin, root, test, oracle, ubuntu from one IP inside 10 minutes",
            false_positives="Vulnerability scanners with credentialed checks; shared jump hosts.",
        ),
        Rule(
            "RULE-004", "Successful Login After Multiple Failures",
            "A successful login from an IP that just produced several failures.",
            SUCCESS_LOGIN_RX, AUTH, "CRITICAL", 85,
            "Treat the account as potentially compromised: verify with the user, reset credentials, "
            "terminate active sessions, review post-login activity.",
            target="correlation",
            params={"kind": "success_after_failures", "min_failures": 5, "window_seconds": 600,
                    "failure_patterns": list(FAILED_LOGIN_RX)},
            why="A success after a burst of failures is the moment a guessing attack actually worked.",
            example="5+ failed passwords for 'deploy' from one IP, then 'Accepted password for deploy'",
            false_positives="A legitimate user who forgot their password and finally got it right.",
        ),
        Rule(
            "RULE-005", "Possible Port Scan",
            "One source IP hits many distinct destination ports in a short window (firewall logs).",
            (r"\bSRC=\S+.*\bDPT=\d+",), NETWORK, "HIGH", 65,
            "Check whether the source is internal or external, review reputation, confirm the firewall "
            "blocked the probes, and look for follow-up access to any port that answered.",
            target="correlation",
            params={"kind": "distinct", "field": "destination_port", "threshold": 15, "window_seconds": 60},
            why="Port scanning is reconnaissance: attackers map open services before choosing an exploit.",
            example="[UFW BLOCK] SRC=203.0.113.50 DST=10.0.0.5 PROTO=TCP SPT=40000 DPT=22 (x 15+ ports)",
            false_positives="Authorised vulnerability scanners, monitoring/health probes, peer-to-peer traffic.",
        ),
        Rule(
            "RULE-006", "SQL Injection Indicator",
            "SQL syntax appearing in a request (UNION SELECT, tautologies, time-based functions...).",
            (
                r"(?i)\bunion\b[\s/*]+(?:all[\s/*]+)?select\b",
                r"(?i)\b(?:or|and)\s+['\"]?(\d+)['\"]?\s*=\s*['\"]?\1\b",
                r"(?i)'\s*(?:or|and)\s*'",
                r"(?i)\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\b\s*\(?\s*['\"]?\d",
                r"(?i)\binformation_schema\b|\bxp_cmdshell\b|;\s*(?:drop|truncate|delete)\s+(?:table|from)\b",
            ),
            WEB, "HIGH", 70,
            "Review the affected endpoint and application logs, use parameterized queries, validate "
            "input, and check the database for unexpected reads or errors around this time.",
            target="request",
            why="Injected SQL can expose or modify database contents.",
            example='GET /item.php?id=1%27%20OR%201=1-- HTTP/1.1',
            false_positives="Developer tooling, security scanners, forum posts that discuss SQL.",
        ),
        Rule(
            "RULE-007", "XSS Indicator",
            "Script tags, javascript: URIs or inline event handlers in a request.",
            (
                r"(?i)<\s*script\b",
                r"(?i)\bjavascript\s*:",
                r"(?i)\bon(?:error|load|click|mouseover|focus)\s*=",
                r"(?i)<\s*(?:img|svg|iframe|body)\b[^>]*\b(?:src|onload|onerror)\s*=",
                r"(?i)document\.cookie",
            ),
            WEB, "HIGH", 60,
            "Review the endpoint, ensure output encoding and a strict Content-Security-Policy, and "
            "check whether the payload was stored or reflected.",
            target="request",
            why="Cross-site scripting lets attackers run script in victims' browsers (session theft, defacement).",
            example='GET /search?q=<script>alert(1)</script> HTTP/1.1',
            false_positives="Rich-text editors that legitimately submit HTML; security testing.",
        ),
        Rule(
            "RULE-008", "Directory Traversal Indicator",
            "Parent-directory sequences (../) including URL-encoded and double-encoded forms.",
            (r"\.\.[/\\]",), WEB, "HIGH", 65,
            "Review web server logs, validate and canonicalize file paths in the application, keep "
            "sensitive files outside the web root and enforce access controls.",
            target="request",
            why="Traversal attempts to read files outside the intended directory.",
            example="GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1",
            false_positives="Rare: badly built relative links, some legacy clients.",
        ),
        Rule(
            "RULE-009", "Command Injection Indicator",
            "Shell metacharacters followed by common commands, or JNDI/shell-path payloads.",
            (
                r"(?i)(?:;|\|\|?|&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|"
                r"powershell|cmd(?:\.exe)?|ping|nslookup)(?:\s|$|\)|`)",
                r"(?i)\$\{\s*jndi\s*:",
                r"(?i)/bin/(?:ba)?sh\b",
            ),
            WEB, "HIGH", 75,
            "Review the endpoint for shell calls, avoid passing input to a shell, use allow-lists, and "
            "inspect the host for unexpected processes or outbound connections.",
            target="request",
            why="Successful command injection means arbitrary code execution on the server.",
            example="GET /ping?host=8.8.8.8;cat%20/etc/passwd HTTP/1.1",
            false_positives="Admin panels that legitimately accept commands; unusual but harmless query strings.",
        ),
        Rule(
            "RULE-010", "Sensitive File Access",
            "Requests for credentials, config files, VCS metadata, backups or admin endpoints.",
            (
                r"(?i)/etc/(?:passwd|shadow|hosts|sudoers)\b",
                r"(?i)/\.(?:env|git|htpasswd|aws|ssh)\b",
                r"(?i)/(?:wp-config\.php|config\.php|web\.config|id_rsa)\b",
                r"(?i)/(?:phpmyadmin|admin|administrator|config|backup|backups)(?:/|\?|$)",
                r"(?i)\.(?:bak|sql|old|orig)(?:\?|$)",
            ),
            WEB, "MEDIUM", 30,
            "Confirm the file is not web-accessible, check the response status/size for exposure, and "
            "restrict access to admin endpoints. '/login' is deliberately excluded (see docs).",
            target="request",
            why="Exposed configuration and credentials give attackers a direct path in.",
            example="GET /.env HTTP/1.1  ->  200",
            false_positives="Legitimate admins visiting /admin; internal tooling.",
        ),
        Rule(
            "RULE-011", "Excessive HTTP 404 Responses",
            "One client generates many 404s in a window (content discovery / forced browsing).",
            (r'"\s+404\s+(?:\d+|-)',), RECON, "MEDIUM", 45,
            "Review the source and requested paths for scanner patterns; consider rate limiting or WAF rules.",
            target="correlation",
            params={"kind": "threshold", "threshold": 20, "window_seconds": 300},
            why="Wordlist-driven scanners produce bursts of not-found responses.",
            example='203.0.113.9 - - [..] "GET /backup.zip HTTP/1.1" 404 196 (x 20+)',
            false_positives="Broken links after a site migration; crawlers; missing favicon/asset loops.",
        ),
        Rule(
            "RULE-012", "Excessive HTTP 403 Responses",
            "One client generates many 403s in a window (probing protected resources).",
            (r'"\s+403\s+(?:\d+|-)',), RECON, "MEDIUM", 45,
            "Review the source and targeted resources; confirm access controls are working and consider blocking.",
            target="correlation",
            params={"kind": "threshold", "threshold": 15, "window_seconds": 300},
            why="Repeated forbidden responses suggest someone is probing for resources they should not reach.",
            example='203.0.113.9 - - [..] "GET /admin/ HTTP/1.1" 403 199 (x 15+)',
            false_positives="Misconfigured permissions affecting real users; hotlink protection.",
        ),
        Rule(
            "RULE-013", "Suspicious User-Agent",
            "User-Agent strings of well-known scanners and attack tools.",
            (
                r"(?i)\b(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|acunetix|nessus|"
                r"zgrab|nuclei|burpsuite)\b",
                r"(?i)\b(?:zmeu|havij|w3af|metasploit)\b",
            ),
            WEB, "MEDIUM", 40,
            "Confirm whether this is an authorised scan; otherwise review the requests it made and consider blocking.",
            target="user_agent",
            why="Tool signatures identify automated scanning. Attackers can spoof UAs, so absence proves nothing.",
            example='"GET / HTTP/1.1" 200 512 "-" "sqlmap/1.7.2#stable"',
            false_positives="Your own security team's scanners; penetration tests.",
        ),
        Rule(
            "RULE-014", "IPv4 IOC", "IPv4 address extracted from a log line.",
            (IPV4,), IOC, "LOW", 0,
            "Enrich with reputation data; compare with threat-intel feeds.",
            target="ioc", params={"ioc_type": "IPV4", "validator": "ipv4"},
            why="IP addresses are the most common pivot point for correlating activity.",
            example="Failed password for root from 203.0.113.5",
            false_positives="Private addresses, version strings that look like IPs (1.2.3.4).",
        ),
        Rule(
            "RULE-015", "IPv6 IOC", "IPv6 address extracted from a log line.",
            (r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])",),
            IOC, "LOW", 0, "Enrich with reputation data; compare with threat-intel feeds.",
            target="ioc", params={"ioc_type": "IPV6", "validator": "ipv6"},
            why="Attackers increasingly use IPv6, which IPv4-only tooling misses.",
            example="Failed password for root from 2001:db8::5 port 4000",
            false_positives="MAC addresses and time strings are rejected by validation; some hex sequences may slip through.",
        ),
        Rule(
            "RULE-016", "Domain IOC", "Domain name (allow-listed TLDs) extracted from a log line.",
            (
                r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
                r"(?:com|net|org|edu|gov|io|co|info|biz|xyz|top|ru|cn|de|uk|us|ph|in|br|fr|nl|tk|cc|site|online|club|pw|su)\b",
            ),
            IOC, "LOW", 0, "Check domain age and reputation; look for DNS/proxy activity to the domain.",
            target="ioc", params={"ioc_type": "DOMAIN", "validator": "domain"},
            why="Command-and-control, phishing and exfiltration commonly use domains.",
            example="Referer: http://malicious-example.xyz/login",
            false_positives="Legitimate CDN and SaaS domains; file names that end in a TLD-like suffix.",
        ),
        Rule(
            "RULE-017", "URL IOC", "HTTP(S) URL extracted from a log line.",
            (r"(?i)\bhttps?://[^\s\"'<>]+",), IOC, "LOW", 0,
            "Analyse the URL in a sandbox or reputation service; never open it from a production workstation.",
            target="ioc", params={"ioc_type": "URL", "validator": "url"},
            why="URLs in logs often point to payload hosting or phishing pages.",
            example='GET /?u=http://198.51.100.9/shell.txt',
            false_positives="Normal Referer headers and API callbacks.",
        ),
        Rule(
            "RULE-018", "MD5 IOC", "32-hex-character MD5 hash.",
            (r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])",), IOC, "LOW", 0,
            "Look the hash up in malware-intelligence services.",
            target="ioc", params={"ioc_type": "MD5", "validator": None},
            why="File hashes identify known malware samples.",
            example="file_hash=d41d8cd98f00b204e9800998ecf8427e",
            false_positives="Session IDs, ETags and cache keys have the same shape.",
        ),
        Rule(
            "RULE-019", "SHA-1 IOC", "40-hex-character SHA-1 hash.",
            (r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])",), IOC, "LOW", 0,
            "Look the hash up in malware-intelligence services.",
            target="ioc", params={"ioc_type": "SHA1", "validator": None},
            why="File hashes identify known malware samples.",
            example="sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709",
            false_positives="Git commit IDs are SHA-1 hashes.",
        ),
        Rule(
            "RULE-020", "SHA-256 IOC", "64-hex-character SHA-256 hash.",
            (r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])",), IOC, "LOW", 0,
            "Look the hash up in malware-intelligence services.",
            target="ioc", params={"ioc_type": "SHA256", "validator": None},
            why="File hashes identify known malware samples.",
            example="sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            false_positives="Container image digests and content-addressed IDs.",
        ),
        Rule(
            "RULE-021", "CVE Identifier", "CVE identifier mentioned in a log line.",
            (r"(?i)\bCVE-\d{4}-\d{4,7}\b",), IOC, "LOW", 0,
            "Check whether the referenced vulnerability affects your assets and whether a patch exists.",
            target="ioc", params={"ioc_type": "CVE", "validator": None},
            why="IDS/WAF messages often name the vulnerability an exploit attempt targets.",
            example="WAF: blocked exploit attempt CVE-2021-44228",
            false_positives="Informational mentions in scanner output.",
        ),
        Rule(
            "RULE-022", "Email Address IOC", "Email address extracted from a log line.",
            (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b",),
            IOC, "LOW", 0, "Check whether the address relates to a phishing campaign or a known-compromised account.",
            target="ioc", params={"ioc_type": "EMAIL", "validator": None},
            why="Addresses tie activity to accounts and phishing infrastructure.",
            example="login attempt for admin@example.com",
            false_positives="Ordinary user IDs that are email addresses.",
        ),
        Rule(
            "RULE-023", "File Path IOC", "Unix or Windows file path extracted from a log line.",
            (
                r"(?<![\w:/.\-])(?:/[\w.\-]+){2,}",
                r"\b[A-Za-z]:\\(?:[\w.\- ]+\\)*[\w.\-]+",
            ),
            IOC, "LOW", 0, "Check whether the path is expected for the host; look for dropped or modified files.",
            target="ioc", params={"ioc_type": "FILE_PATH", "validator": None},
            why="Paths reveal targeted files, persistence locations and dropped payloads.",
            example=r"Process started: C:\Windows\Temp\update.exe",
            false_positives="Ordinary application paths.",
        ),
        Rule(
            "RULE-024", "Known IOC Match", "An extracted IOC appears on the analyst-supplied watchlist.",
            (r"(?s).",), IOC, "MEDIUM", 40,
            "Treat as a confirmed-intelligence hit: scope the activity, block or monitor per policy.",
            target="watchlist",
            why="A hit on your own threat-intelligence list is higher-confidence than a generic pattern.",
            example="Watchlist contains 203.0.113.5 and a log line mentions 203.0.113.5",
            false_positives="Stale watchlist entries; shared or reassigned infrastructure.",
        ),
    ]


def default_rules() -> list[Rule]:
    """Return a fresh copy of the built-in rules (safe to mutate)."""
    return _rules()
