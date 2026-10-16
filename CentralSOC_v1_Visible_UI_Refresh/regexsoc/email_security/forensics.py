"""Offline, bounded, non-executing email URL and attachment metadata triage.

These are investigative leads, never independently verified maliciousness.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

from regexsoc.email_security.models import ParsedEmail

_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_RISKY_EXT = frozenset({"exe", "scr", "js", "jse", "vbs", "vbe", "ps1", "bat", "cmd", "hta", "lnk", "iso", "img", "msi", "jar"})
_ARCHIVE_EXT = frozenset({"zip", "rar", "7z"})
_MAX_BODY = 100_000
_MAX_URLS = 100


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str
    summary: str
    evidence: str


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            self._href = dict(attrs).get('href')
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == 'a' and self._href is not None:
            if len(self.links) < _MAX_URLS:
                self.links.append((self._href, ''.join(self._text).strip()))
            self._href = None
            self._text = []


def _host(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in ('http', 'https'):
            return None
        hostname = parsed.hostname
        return hostname.lower().rstrip('.') if hostname else None
    except ValueError:
        return None


def analyze_message_metadata(parsed: ParsedEmail) -> list[Finding]:
    """Returns at most 200 bounded evidence leads; does not fetch URLs or open attachments."""
    findings: list[Finding] = []
    html = (parsed.html_body or '')[:_MAX_BODY]
    plain = (parsed.plain_text_body or '')[:_MAX_BODY]
    parser = _Links()
    parser.feed(html)
    candidates = [(u, '') for u in _URL.findall(plain)]
    candidates.extend((u, '') for u in _URL.findall(html))
    candidates.extend(parser.links)
    seen: set[tuple[str, str]] = set()
    for url, label in candidates[:_MAX_URLS * 3]:
        # Evidence is deliberately bounded, and full URLs are not turned into clickable links.
        host = _host(url)
        if not host or (host, label) in seen:
            continue
        seen.add((host, label))
        if len(seen) > _MAX_URLS:
            break
        if url.lower().startswith('http://'):
            findings.append(Finding('URL', 'LOW', 'Unencrypted HTTP link in message', host[:200]))
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            findings.append(Finding('URL', 'MEDIUM', 'Link targets a literal IP address', host[:200]))
        visible = _URL.search(label)
        if visible:
            shown = _host(visible.group(0).rstrip('.,)'))
            if shown and shown != host:
                findings.append(Finding('URL', 'HIGH', 'Displayed URL host differs from actual link host', f'displayed {shown[:120]} → actual {host[:120]}'))
    for part in parsed.attachments[:100]:
        filename = (part.sanitized_filename or part.filename or '').lower()
        chunks = filename.rsplit('.', 2)
        suffix = chunks[-1] if len(chunks) > 1 else ''
        if suffix in _RISKY_EXT:
            findings.append(Finding('ATTACHMENT', 'HIGH', 'Attachment filename has an executable or script extension', filename[:160]))
        elif suffix in _ARCHIVE_EXT:
            findings.append(Finding('ATTACHMENT', 'LOW', 'Archive attachment requires manual inspection', filename[:160]))
        if len(chunks) == 3 and chunks[-2] in {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png'} and suffix in _RISKY_EXT:
            findings.append(Finding('ATTACHMENT', 'HIGH', 'Double-extension attachment can disguise executable content', filename[:160]))
    if parsed.defects:
        findings.append(Finding('STRUCTURE', 'LOW', 'Parser reported MIME/message defects', f'{len(parsed.defects)} defect(s)'))
    return findings[:200]
