import json
from datetime import datetime, timezone
import pytest
from regexsoc.services.threat_feed import load_feed


def test_expired_iocs_are_not_used_and_provenance_survives(tmp_path):
    file = tmp_path / 'feed.json'
    file.write_text(json.dumps([
        {'type':'ipv4','value':'192.0.2.7','source':'internal-review','expires_at':'2030-01-01T00:00:00Z'},
        {'type':'domain','value':'expired.example','source':'old','expires_at':'2020-01-01T00:00:00Z'}]))
    entries = load_feed(file, now=datetime(2026, 10, 15, tzinfo=timezone.utc))
    assert len(entries) == 1 and entries[0].source == 'internal-review'


@pytest.mark.parametrize('data', [
    '[{"type":"ipv4","value":"127.0.0.1","source":"x","expires_at":"2030-01-01"}]',
    '[{"type":"ipv4","value":"x","source":"x","expires_at":"2030-01-01Z"}]',
    '[{"type":"domain","value":"bad..domain","source":"x","expires_at":"2030-01-01Z"}]',
    '[{"type":"ipv4","type":"ipv6","value":"::1","source":"x","expires_at":"2030-01-01Z"}]',
])
def test_invalid_feed_rejected(tmp_path, data):
    file = tmp_path / 'feed.json'
    file.write_text(data)
    with pytest.raises(ValueError):
        load_feed(file)
