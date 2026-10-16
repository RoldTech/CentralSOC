"""Email Security & Phishing Detection module.

Phase 1 (current): parsing raw email messages (.eml / RFC 5322) into structured headers, body
and MIME-part metadata. Nothing here evaluates SPF/DKIM/DMARC or scores phishing risk yet — that
starts in Phase 2 onward. See docs/email-security.md for the full roadmap and scope boundaries.
"""
