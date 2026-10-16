# Sample emails

Fictional demonstration data for the Email Security module (Phase 1: parsing only). All domains,
addresses and IPs are fictional (`example.com`/`.org`/`.net`, RFC 5737 documentation IPs). No real
people or organizations.

| File | What it shows |
|---|---|
| `benign_newsletter.eml` | A normal, single-part email with clean headers and a matching Reply-To/From |
| `phishing_password_reset.eml` | A multipart/alternative message with a **Reply-To that doesn't match From**, an SPF/DMARC failure reported in its `Authentication-Results` header, and urgency language — the kind of characteristics later phases will score. Phase 1 only parses the structure; it does not yet classify this as phishing. |

Try them:
```
python -m regexsoc email parse sample_emails/benign_newsletter.eml
python -m regexsoc email analyze sample_emails/phishing_password_reset.eml --format json
```
