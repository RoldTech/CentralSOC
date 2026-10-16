"""Detection scoping, offline enrichment, bounded report safety and validation."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from regexsoc.services.analyzer import Analyzer
from regexsoc.services.export import to_csv
from regexsoc.services.threat_feed import load_feed


def test_detection_rules_remain_distinct_per_account():
    from regexsoc.detectors.correlation import correlate
    from regexsoc.parsers import parse_lines
    events = parse_lines([
        'Oct 15 10:00:00 host sshd[1]: Failed password for alice from 192.0.2.11 port 1234 ssh2',
        'Oct 15 10:00:01 host sshd[2]: Accepted password for bob from 192.0.2.11 port 1234 ssh2',
    ], year=2026)
    result = Analyzer().analyze_events(events)
    assert not any('success after' in d.reason.lower() and d.username == 'bob' for d in result.detections)


def test_offline_feed_never_accepts_stale_entries(tmp_path):
    path = tmp_path / 'feed.json'
    path.write_text(json.dumps([{'type':'ipv4','value':'192.0.2.7','source':'review',
        'expires_at':'2020-01-01T00:00:00Z'}]), encoding='utf8')
    assert load_feed(path) == ()
    assert not Analyzer.from_feed_file(path).watchlist


def test_report_escapes_formula_like_title_and_headers():
    output = to_csv([{'title':'\t=HYPERLINK("bad")','status':'Open'}], ['title','status'])
    assert "'\t=HYPERLINK" in output
    assert to_csv([{'=cmd':'value'}], ['=cmd']).startswith("'=cmd")


def test_uploaded_sample_never_requires_external_network(tmp_path):
    from regexsoc.db.session import make_engine, init_db, session_scope
    from regexsoc.db.service import ingest_file
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    sample = Path(__file__).resolve().parents[1] / 'sample_logs' / 'ssh_auth.log'
    with session_scope(engine) as session:
        result = ingest_file(session, sample, uploaded_by='regression', upload_dir=tmp_path)
        assert result.events > 0
