from types import SimpleNamespace as NS

from regexsoc.security.integrity import (
    build_chain, canonical_event, event_hash, sha256_file, sha256_text, verify_chain,
)


def make_events(n=5):
    return [NS(timestamp=None, source_ip=f"203.0.113.{i}", destination_ip=None, source_port=None,
               destination_port=22, protocol="SSH", username="root", auth_status="FAILURE",
               http_method=None, http_path=None, http_status=None, user_agent=None, host="h",
               event_type="FAILED_LOGIN", source_format="syslog", raw_log=f"line {i}") for i in range(n)]


def stored_rows(events, genesis="g" * 64, key=None):
    return [NS(**e.__dict__, seq=s, prev_hash=p, hash=h) for e, (s, p, h) in zip(events, build_chain(genesis, events, key))]


def test_sha256_file_known_vectors(tmp_path):
    empty, abc = tmp_path / "e", tmp_path / "a"
    empty.write_bytes(b"")
    abc.write_bytes(b"abc")
    assert sha256_file(empty) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_file(abc) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_file_streams_large_input(tmp_path):
    f = tmp_path / "big"
    f.write_bytes(b"x" * (3 * 1024 * 1024 + 7))
    import hashlib
    assert sha256_file(f, chunk_size=1000) == hashlib.sha256(b"x" * (3 * 1024 * 1024 + 7)).hexdigest()


def test_sha256_text():
    assert sha256_text("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_intact_chain_verifies():
    rows = stored_rows(make_events())
    result = verify_chain("g" * 64, rows, expected_count=5)
    assert result.ok and result.checked == 5 and result.broken_at is None


def test_modified_event_is_detected_at_its_position():
    rows = stored_rows(make_events())
    rows[2].username = "mallory"
    result = verify_chain("g" * 64, rows, expected_count=5)
    assert not result.ok and result.broken_at == 3 and "modified" in result.reason


def test_deleted_middle_event_is_detected():
    rows = stored_rows(make_events())
    del rows[1]
    result = verify_chain("g" * 64, rows, expected_count=5)
    assert not result.ok and result.broken_at == 2


def test_deleted_last_event_is_detected_via_count():
    rows = stored_rows(make_events())[:-1]
    result = verify_chain("g" * 64, rows, expected_count=5)
    assert not result.ok and "removed" in result.reason


def test_reordered_events_are_detected():
    rows = stored_rows(make_events())
    rows[1], rows[2] = rows[2], rows[1]
    assert not verify_chain("g" * 64, rows, expected_count=5).ok


def test_wrong_genesis_file_hash_breaks_chain():
    rows = stored_rows(make_events(), genesis="a" * 64)
    assert not verify_chain("b" * 64, rows).ok  # events no longer tied to the original file hash


def test_inserted_event_is_detected():
    events = make_events()
    rows = stored_rows(events)
    forged = stored_rows(events[:1])[0]
    rows.insert(1, forged)
    assert not verify_chain("g" * 64, rows, expected_count=5).ok


def test_hmac_chain_cannot_be_rebuilt_without_key():
    events = make_events()
    keyed = stored_rows(events, key=b"secret-key")
    assert verify_chain("g" * 64, keyed, key=b"secret-key").ok
    assert not verify_chain("g" * 64, keyed).ok            # plain verification fails
    forged = stored_rows(events)                            # attacker recomputes with no key
    assert not verify_chain("g" * 64, forged, key=b"secret-key").ok


def test_hash_ignores_severity_but_covers_raw_log():
    e = make_events(1)[0]
    base = event_hash("p", 1, e)
    e.severity = "HIGH"
    assert event_hash("p", 1, e) == base
    e.raw_log = "changed"
    assert event_hash("p", 1, e) != base


def test_canonical_event_is_deterministic():
    e = make_events(1)[0]
    assert canonical_event(1, e) == canonical_event(1, e)
