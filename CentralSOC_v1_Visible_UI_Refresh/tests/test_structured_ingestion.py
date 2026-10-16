import json
from datetime import UTC

import pytest

from regexsoc.parsers.structured import StructuredParseError, parse_structured
from regexsoc.services.analyzer import Analyzer


def test_json_normalizes_authentication_events(tmp_path):
    path = tmp_path / 'events.json'
    path.write_text(json.dumps([{"timestamp":"2026-10-15T08:00:00+08:00", "source_ip":"192.0.2.2", "username":"bob", "auth_status":"failure"}]), encoding='utf-8')
    events = parse_structured(path, '.json')
    assert len(events) == 1
    assert events[0].timestamp.tzinfo == UTC
    assert events[0].timestamp.hour == 0
    assert events[0].event_type == 'FAILED_LOGIN'
    assert Analyzer(rules=[]).analyze_file(path).events[0].source_format == 'json'


def test_csv_normalizes(tmp_path):
    path = tmp_path / 'auth.csv'
    path.write_text('timestamp,source_ip,username,auth_status\n2026-10-15T00:00:00Z,192.0.2.4,alice,SUCCESS\n')
    assert parse_structured(path, '.csv')[0].event_type == 'LOGIN_SUCCESS'


def test_jsonl_normalizes(tmp_path):
    path = tmp_path / 'auth.jsonl'
    path.write_text('{"username":"alice","auth_status":"FAILURE"}\n')
    assert parse_structured(path, '.jsonl')[0].event_type == 'FAILED_LOGIN'


@pytest.mark.parametrize('name,content', [
    ('bad.json', '{'),
    ('bad.json', '[1]'),
    ('bad.json', '[{"source_ip":"999.0.0.1"}]'),
    ('bad.json', '{"x":1,"x":2}'),
    ('bad.jsonl', '{bad}\n'),
    ('bad.csv', 'username,auth_status\nbob,FAILURE,extra\n'),
    ('bad.csv', 'username,username\nbob,alice\n'),
])
def test_bad_structured_data_is_not_silently_accepted(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    with pytest.raises(StructuredParseError):
        parse_structured(path, path.suffix)
