from regexsoc.email_security.parser import parse_email
from regexsoc.email_security.forensics import analyze_message_metadata


def test_visible_link_host_mismatch_and_no_network():
    raw = 'From: test@example.org\nMIME-Version: 1.0\nContent-Type: text/html\n\n<a href="https://example.net/login">https://example.org/login</a>'
    flags = analyze_message_metadata(parse_email(raw))
    assert any(f.summary.startswith('Displayed URL host') and f.severity == 'HIGH' for f in flags)


def test_attachment_double_extension():
    raw = ('From: a@example.org\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="xyz"\n\n'
           '--xyz\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="invoice.pdf.exe"\n\nabc\n--xyz--\n')
    flags = analyze_message_metadata(parse_email(raw))
    assert any('Double-extension' in f.summary for f in flags)


def test_benign_email_has_no_metadata_flags():
    assert analyze_message_metadata(parse_email('From: a@example.org\nSubject: Hello\n\nThanks')) == []


def test_url_limits():
    raw = 'From: a@example.org\n\n' + ' '.join('http://192.0.2.%d/x' % (i % 200 + 1) for i in range(500))
    assert len(analyze_message_metadata(parse_email(raw))) <= 200
