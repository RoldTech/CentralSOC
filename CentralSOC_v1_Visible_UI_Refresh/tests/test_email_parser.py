"""Email parser tests (Phase 1: parsing only, no SPF/DKIM/DMARC evaluation yet)."""

from email.message import EmailMessage

import pytest

from regexsoc.email_security.parser import DEFAULT_MAX_BYTES, EmailParseError, parse_email, parse_email_file


def build(**headers) -> EmailMessage:
    msg = EmailMessage()
    for key, value in headers.items():
        msg[key.replace("_", "-")] = value
    return msg


def raw_msg(body="body", **headers) -> bytes:
    msg = build(**headers)
    msg.set_content(body)
    return msg.as_bytes()


# --------------------------------------------------------------------------- basic headers
def test_basic_header_extraction():
    p = parse_email(raw_msg(From="alice@example.com", To="bob@example.com", Subject="Hello",
                            Message_ID="<abc123@example.com>"))
    assert p.headers.from_[0].address == "alice@example.com"
    assert p.headers.to[0].address == "bob@example.com"
    assert p.headers.subject == "Hello"
    assert p.headers.message_id == "<abc123@example.com>"


def test_missing_headers_return_none_or_empty_not_crash():
    p = parse_email(raw_msg())
    assert p.headers.subject is None and p.headers.to == [] and p.headers.reply_to == []
    assert p.headers.message_id is None


def test_display_names_with_multiple_addresses():
    raw = b'To: "Alice A" <alice@x.com>, "Bob B" <bob@y.com>\r\nFrom: c@d.com\r\n\r\nbody'
    p = parse_email(raw)
    assert [(a.display_name, a.address) for a in p.headers.to] == [("Alice A", "alice@x.com"), ("Bob B", "bob@y.com")]


def test_reply_to_and_return_path_extracted_separately_from_from():
    raw = (b"From: legit@example.com\r\nReply-To: attacker@evil.com\r\n"
          b"Return-Path: <bounce@evil.com>\r\n\r\nbody")
    p = parse_email(raw)
    assert p.headers.from_[0].address == "legit@example.com"
    assert p.headers.reply_to[0].address == "attacker@evil.com"
    assert p.headers.return_path == "<bounce@evil.com>"


def test_cc_extracted():
    p = parse_email(raw_msg(To="a@x.com", Cc="b@x.com, c@x.com"))
    assert [a.address for a in p.headers.cc] == ["b@x.com", "c@x.com"]


# --------------------------------------------------------------------------- duplicate headers
def test_duplicate_received_headers_all_preserved_in_order():
    raw = (b"From: a@b.com\r\nReceived: from mx1.example.com\r\nReceived: from mx2.example.com\r\n\r\nbody")
    p = parse_email(raw)
    assert p.headers.received == ["from mx1.example.com", "from mx2.example.com"]
    assert p.raw_headers["received"] == ["from mx1.example.com", "from mx2.example.com"]


def test_duplicate_authentication_results_all_preserved():
    raw = (b"From: a@b.com\r\nAuthentication-Results: mx.a.com; spf=pass\r\n"
          b"Authentication-Results: mx.b.com; spf=fail\r\n\r\nbody")
    p = parse_email(raw)
    assert len(p.headers.authentication_results) == 2
    assert "spf=pass" in p.headers.authentication_results[0]
    assert "spf=fail" in p.headers.authentication_results[1]


def test_raw_headers_are_case_insensitively_keyed_lowercase():
    p = parse_email(raw_msg(From="a@b.com", Subject="Test"))
    assert "subject" in p.raw_headers and p.raw_headers["subject"] == ["Test"]


# --------------------------------------------------------------------------- auth-adjacent headers
def test_spf_dkim_arc_headers_captured_raw_not_evaluated():
    raw = (b"From: a@b.com\r\n"
          b"Received-SPF: pass (google.com: domain of a@b.com designates 1.2.3.4 as permitted sender)\r\n"
          b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; b=abcdef\r\n"
          b"ARC-Seal: i=1; a=rsa-sha256; d=example.com\r\n"
          b"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com\r\n"
          b"ARC-Authentication-Results: i=1; mx.google.com\r\n\r\nbody")
    p = parse_email(raw)
    assert "domain of a@b.com" in p.headers.received_spf[0]
    assert "d=example.com" in p.headers.dkim_signature[0]
    assert len(p.headers.arc_seal) == 1 and len(p.headers.arc_message_signature) == 1
    assert len(p.headers.arc_authentication_results) == 1


def test_misc_single_headers():
    raw = (b"From: a@b.com\r\nX-Originating-IP: [203.0.113.5]\r\nX-Mailer: Outlook 16.0\r\n"
          b"User-Agent: Thunderbird\r\nMIME-Version: 1.0\r\n\r\nbody")
    p = parse_email(raw)
    assert p.headers.x_originating_ip == "[203.0.113.5]"
    assert p.headers.x_mailer == "Outlook 16.0"
    assert p.headers.user_agent == "Thunderbird"
    assert p.headers.mime_version == "1.0"


# --------------------------------------------------------------------------- date handling
def test_valid_date_is_parsed():
    p = parse_email(raw_msg(Date="Sun, 10 Mar 2024 10:15:01 +0000"))
    assert p.headers.date is not None and p.headers.date.year == 2024


def test_malformed_date_kept_raw_without_a_fabricated_parse():
    # Built directly as raw bytes: the EmailMessage *builder* API normalizes/empties an invalid
    # Date value on serialization (a quirk of its specialized DateHeader), which would test that
    # quirk instead of the parser. Raw bytes is what a real malformed message looks like on the wire.
    p = parse_email(b"From: a@b.com\r\nDate: not a real date\r\n\r\nbody")
    assert p.headers.date is None and p.headers.date_raw == "not a real date"


def test_no_date_header_at_all():
    p = parse_email(raw_msg())
    assert p.headers.date is None and p.headers.date_raw is None


# --------------------------------------------------------------------------- body extraction
def test_plain_text_body_extraction():
    p = parse_email(raw_msg(body="Hello world"))
    assert p.plain_text_body.strip() == "Hello world"
    assert p.html_body is None


def test_plain_and_html_alternative_bodies_both_extracted():
    msg = build(From="a@b.com", To="c@d.com", Subject="hi")
    msg.set_content("Plain version")
    msg.add_alternative("<p>HTML version</p>", subtype="html")
    p = parse_email(msg.as_bytes())
    assert "Plain version" in p.plain_text_body
    assert "<p>HTML version</p>" in p.html_body


# --------------------------------------------------------------------------- attachments / MIME structure
def test_attachments_detected_with_metadata_not_confused_with_body_parts():
    msg = build(From="a@b.com", To="c@d.com", Subject="Invoice")
    msg.set_content("Plain body")
    msg.add_alternative("<p>HTML body</p>", subtype="html")
    msg.add_attachment(b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="invoice.pdf")
    p = parse_email(msg.as_bytes())
    assert len(p.attachments) == 1
    assert p.attachments[0].filename == "invoice.pdf"
    assert p.attachments[0].content_type == "application/pdf"
    assert p.attachments[0].size_bytes > 0
    non_attachment_parts = [part for part in p.parts if not part.is_attachment]
    assert len(non_attachment_parts) == 2  # plain + html, correctly NOT flagged as attachments


def test_double_extension_filename_preserved_verbatim_for_later_phishing_checks():
    msg = build(From="a@b.com")
    msg.set_content("body")
    msg.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    p = parse_email(msg.as_bytes())
    assert p.attachments[0].filename == "invoice.pdf.exe"


def test_attachment_filename_is_also_sanitized_defensively():
    msg = build(From="a@b.com")
    msg.set_content("body")
    msg.add_attachment(b"x", maintype="application", subtype="octet-stream", filename="../../etc/passwd")
    p = parse_email(msg.as_bytes())
    assert p.attachments[0].filename == "../../etc/passwd"  # raw preserved
    assert p.attachments[0].sanitized_filename == "passwd"  # sanitized version also available


def test_email_with_no_attachments_has_empty_attachment_list():
    p = parse_email(raw_msg())
    assert p.attachments == []


# --------------------------------------------------------------------------- robustness
def test_garbage_input_never_raises():
    result = parse_email(b"\x00\x01\xff not an email\r\n\r\nblah")
    assert result.headers.subject is None


def test_empty_input_never_raises():
    result = parse_email(b"")
    assert result.plain_text_body is None or result.plain_text_body == ""


def test_oversized_email_is_rejected():
    with pytest.raises(EmailParseError, match="limit"):
        parse_email(b"x" * 100, max_bytes=10)


def test_default_max_bytes_is_reasonable():
    assert 1_000_000 <= DEFAULT_MAX_BYTES <= 100_000_000


def test_str_input_accepted_as_well_as_bytes():
    p = parse_email("From: a@b.com\r\nSubject: hi\r\n\r\nbody")
    assert p.headers.subject == "hi"


def test_str_input_with_non_ascii_does_not_crash():
    p = parse_email("From: a@b.com\r\nSubject: caf\u00e9 promo\r\n\r\nbody")
    assert p.headers.subject is not None


# --------------------------------------------------------------------------- file parsing + serialization
def test_parse_email_file(tmp_path):
    f = tmp_path / "test.eml"
    f.write_bytes(raw_msg(From="a@b.com", Subject="File test"))
    p = parse_email_file(str(f))
    assert p.headers.subject == "File test"


def test_parse_email_file_respects_size_limit(tmp_path):
    f = tmp_path / "big.eml"
    f.write_bytes(b"x" * 1000)
    with pytest.raises(EmailParseError):
        parse_email_file(str(f), max_bytes=100)


def test_to_dict_is_json_serializable():
    import json
    p = parse_email(raw_msg(From="a@b.com", To="c@d.com", Subject="Test"))
    json.dumps(p.to_dict())  # must not raise


def test_defects_list_exists_and_is_a_list():
    p = parse_email(raw_msg())
    assert isinstance(p.defects, list)
