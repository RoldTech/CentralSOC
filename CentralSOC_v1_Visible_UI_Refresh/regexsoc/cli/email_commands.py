"""CLI handlers for `regexsoc email ...`."""

from __future__ import annotations

import argparse

from regexsoc.email_security.auth import evaluate_dkim, evaluate_dmarc, evaluate_spf
from regexsoc.email_security.indicators import collect_indicators
from regexsoc.email_security.verdict import compute_verdict
from regexsoc.email_security.parser import EmailParseError, parse_email_file
from regexsoc.services.export import to_json


def parse(args: argparse.Namespace) -> int:
    try:
        parsed = parse_email_file(args.eml_file)
    except (EmailParseError, OSError) as exc:
        print(f"error: {exc}")
        return 2

    if args.format == "json":
        print(to_json(parsed.to_dict()))
        return 0

    h = parsed.headers
    print("=" * 72)
    print(f"From       : {'; '.join(a.raw for a in h.from_) or '(none)'}")
    print(f"To         : {'; '.join(a.raw for a in h.to) or '(none)'}")
    if h.cc:
        print(f"Cc         : {'; '.join(a.raw for a in h.cc)}")
    if h.reply_to:
        print(f"Reply-To   : {'; '.join(a.raw for a in h.reply_to)}  "
             f"{'(differs from From)' if {a.address for a in h.reply_to} != {a.address for a in h.from_} else ''}")
    print(f"Subject    : {h.subject or '(none)'}")
    print(f"Date       : {h.date.isoformat() if h.date else f'(unparseable: {h.date_raw!r})' if h.date_raw else '(none)'}")
    print(f"Message-ID : {h.message_id or '(none)'}")
    print(f"Size       : {parsed.size_bytes} bytes")
    print()
    print(f"Authentication-Results header(s) present: {len(h.authentication_results)}  "
         "(as reported by the receiving mail server — not independently verified here yet)")
    print(f"DKIM-Signature header(s) present        : {len(h.dkim_signature)}")
    print(f"Received-SPF header(s) present           : {len(h.received_spf)}")
    print(f"Received hop(s)                          : {len(h.received)}")
    print()
    print(f"Body        : plain={'yes' if parsed.plain_text_body else 'no'}  "
         f"html={'yes' if parsed.html_body else 'no'}")
    print(f"Attachments : {len(parsed.attachments)}")
    for a in parsed.attachments:
        print(f"  - {a.filename}  ({a.content_type}, {a.size_bytes} bytes)")
    if parsed.defects:
        print(f"\nParser defects (malformed structure, not necessarily malicious): {len(parsed.defects)}")
        for d in parsed.defects[:10]:
            print(f"  - {d}")
    return 0


def _fmt(result) -> str:
    return result.value if hasattr(result, "value") else str(result)


def analyze(args: argparse.Namespace) -> int:
    try:
        parsed = parse_email_file(args.eml_file)
    except (EmailParseError, OSError) as exc:
        print(f"error: {exc}")
        return 2

    spf = evaluate_spf(parsed.headers)
    dkim = evaluate_dkim(parsed.headers)
    dmarc = evaluate_dmarc(parsed.headers)
    internal = frozenset(d.strip().lower() for d in (args.internal_domain or []))
    indicators = collect_indicators(parsed.headers, parsed.plain_text_body, parsed.html_body, dmarc, internal)
    verdict = compute_verdict(indicators, header_from_present=bool(parsed.headers.from_))

    if args.format == "json":
        print(to_json({"headers": parsed.headers.to_dict(), "spf": spf.to_dict(), "dkim": dkim.to_dict(),
                       "dmarc": dmarc.to_dict(), "verdict": verdict.to_dict()}))
        return 0

    print("=" * 72)
    print("EMAIL AUTHENTICATION")
    print("=" * 72)
    print(f"SPF Authentication     {_fmt(spf.result)}")
    print(f"SPF Alignment          {_fmt(spf.alignment)}  ({spf.alignment_mode.value.lower()})")
    print()
    print(f"DKIM Authentication    {_fmt(dkim.result)}")
    for s in dkim.signatures:
        note = "" if s.verified_by == "authentication-results" else f"  [{s.verified_by}]"
        print(f"  - d={s.signing_domain or '(none)'}  {_fmt(s.result)}  alignment={_fmt(s.alignment)}{note}")
    print()
    print(f"DMARC                  {_fmt(dmarc.result)}")
    if dmarc.reported_result is not None:
        print(f"  (message's own Authentication-Results reported dmarc={_fmt(dmarc.reported_result)} — "
             "shown for comparison, not used as our verdict)")
    print(f"Reason: {dmarc.reason}")
    if dmarc.policy:
        print(f"\nDMARC Policy: {dmarc.policy.p or '(none)'}  "
             f"(subdomain policy: {dmarc.policy.sp or 'same as p'}, pct={dmarc.policy.pct})")
        print("Note: policy tells enforcement guidance; it is independent of whether THIS message passed.")
    else:
        print("\nDMARC Policy: unavailable (no DNS lookup performed — see docs/email-security.md)")

    print()
    print("=" * 72)
    print("PHISHING ANALYSIS")
    print("=" * 72)
    print(f"Classification : {verdict.classification}   (confidence: {verdict.confidence})")
    print(f"Risk score     : {verdict.score}/100   {verdict.category_scores}")
    if indicators:
        print("\nIndicators:")
        for ind in sorted(indicators, key=lambda i: -{"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[i.severity]):
            detail = f"  ({ind.evidence})" if ind.evidence else ""
            print(f"  [{ind.severity:<8}] {ind.description}{detail}")
    else:
        print("\nNo phishing indicators found.")
    print("\nURL and attachment analysis are not yet implemented (later phases).")
    print("The score is a triage aid built from the indicators above, not a probability.")
    return 0
