# Email Security & Phishing Detection

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Email parser: headers, body, MIME/attachment structure | **Done, tested** |
| 2 | SPF/DKIM/DMARC evaluation (authentication + alignment + policy) | **Done, tested** |
| 3 | Phishing indicator engine (sender, domain, content, BEC correlation) + risk scoring/verdict | **Done, tested** |
| 4 | URL and attachment risk analysis | Planned |
| 5 | IOC extraction into the existing IOC system | Planned |
| 6 | Email alerts into the existing Alert engine | Planned |
| 7 | Investigation workspace, dashboard, search integration | Planned |
| 8 | Security hardening (ReDoS, SSRF, decompression-bomb guards) + full test pass | Planned |

This module extends the existing RegexSOC (log analyzer + dashboard), not a separate app: email
findings are intended to become normal RegexSOC events, alerts and IOCs once later phases connect
this parser to the existing detection/alert/database layers.

**Correction to an earlier design note:** the original request described integrating with "existing
multi-tenancy" and an "existing investigation system." Neither exists yet in RegexSOC today — there
is one shared database with no `organization_id`/tenant isolation, and no dedicated investigation
module beyond the Alert status workflow (New → Investigating → Resolved → False Positive). Later
phases will either build those or explicitly scope around their absence; claiming tenant isolation
before it exists would be a false security claim, not just a documentation gap.

## What Phase 1 does

`regexsoc.email_security.parser.parse_email()` turns a raw RFC 5322 message (or a `.eml` file) into
a `ParsedEmail`: structured headers (From/To/Cc/Reply-To/Return-Path/Subject/Date/Message-ID),
every `Received`, `Authentication-Results`, `Received-SPF`, `DKIM-Signature` and `ARC-*` header
(duplicates preserved, since a message can legitimately carry several), the plain-text and HTML
bodies, and metadata for every MIME part (content type, filename, size, whether it's an attachment).

Uses only the Python standard library (`email` package, `policy.default`/`EmailMessage`), so there
is no new dependency. Nothing is executed: no attachment content is decoded beyond measuring its
size, no URL is fetched, no HTML/JavaScript is rendered.

## What Phase 1 deliberately does NOT do

- **No SPF/DKIM/DMARC evaluation.** The `Authentication-Results` header is captured as raw text,
  exactly as the receiving mail server reported it — RegexSOC does not yet parse its `spf=`/`dkim=`
  result codes or independently verify anything. Phase 2 adds a real evaluation engine, distinct
  from trusting this self-reported header, with the "reported by sender infrastructure" vs.
  "independently verified by RegexSOC" distinction always shown separately.
- **No phishing scoring.** A Reply-To/From mismatch or SPF failure appearing in the sample data is
  not flagged as "phishing" anywhere yet — Phase 3 adds that.
- **No IOC extraction, no alerts, no database storage.** This phase produces an in-memory
  `ParsedEmail` object only.

## Security notes for this phase

- Input size is capped (`DEFAULT_MAX_BYTES`, 25 MB); `parse_email_file` also caps how much it reads
  from disk, so an oversized file can't be loaded fully into memory before the check runs.
- Parsing never raises on malformed input (RFC 5322 parsing is inherently lenient); structural
  problems are surfaced via `ParsedEmail.defects` instead of being hidden or crashing.
- Attachment filenames are kept exactly as received (needed for later double-extension detection,
  e.g. `invoice.pdf.exe`) *and* a sanitized version is computed alongside via the existing
  `regexsoc.security.files.sanitize_filename`, for any future code path that touches the filesystem.
- Attachment *content* is only read to measure its size in this phase — never decompressed,
  executed, or interpreted.

## What Phase 2 does

`regexsoc.email_security.auth` evaluates the SPF/DKIM/DMARC information a message already carries:

- **SPF**: reads the result from `Authentication-Results` (preferred) or `Received-SPF` (fallback),
  extracts the envelope-from domain, and checks it for **alignment** against the RFC5322.From domain.
- **DKIM**: for every `DKIM-Signature` header, matches it against any `dkim=` result the receiving
  server reported (by signing domain) and checks alignment. A signature with no matching report is
  explicitly labeled `"signature present, not independently verified"` — never silently PASS.
- **DMARC**: computed independently from SPF/DKIM authentication + alignment per RFC 7489 section
  3.1 — **DMARC passes when SPF OR DKIM both authenticates and aligns (an OR, never an AND)**. The
  message's own self-reported `dmarc=` value (if present) is surfaced separately for comparison,
  never used as the computed verdict.
- **DMARC policy** (`p=`/`sp=`/`pct=`/`adkim=`/`aspf=`/`rua=`/`ruf=`) has a pure parser
  (`parse_dmarc_record`), kept deliberately independent from the authentication result: a `p=reject`
  policy does **not** make a genuinely-passing message FAIL. Fetching the record is a separate
  `DMARCPolicyProvider` abstraction — see below for why the default never does a DNS lookup.

Try it:
```
python -m regexsoc email analyze sample_emails/benign_newsletter.eml
python -m regexsoc email analyze sample_emails/phishing_password_reset.eml --format json
```

## What Phase 2 deliberately does NOT do

- **No DNS-based SPF verification.** Real SPF evaluation means querying the domain's SPF TXT record
  and walking its mechanisms (`ip4`/`a`/`mx`/`include`/...), which needs a DNS resolver and careful
  hardening against SSRF-like abuse (the domain is attacker-controlled). `evaluate_spf` only reads
  what the receiving mail server already reported.
- **No cryptographic DKIM verification.** `d=`/`s=`/`b=` are parsed from the signature, but the
  actual RSA/Ed25519 signature (`b=`) is never checked — that needs a dedicated crypto library and
  the signer's public key (another DNS lookup). A DKIM result of PASS here always means "the
  receiving mail server reported this as passing," which is shown in `verified_by`.
- **No DMARC record DNS lookup.** `DMARCPolicyProvider` is an abstraction boundary: the default
  (`NullDMARCPolicyProvider`) always returns "unavailable" so the rest of the evaluation works
  correctly with zero network access. `StaticDMARCPolicyProvider` lets an analyst supply a
  known/already-fetched record. A real resolver-backed provider is future work, and should not be
  added without rate limiting, timeouts, and blocking requests to internal/link-local addresses.

## Known limitation: organizational-domain approximation

Relaxed alignment (the common case) needs each domain's "organizational domain" — normally
determined via the official Public Suffix List (~9,000 entries). Bundling or fetching the full PSL
was judged not worth the new dependency for this phase, so `organizational_domain()` uses a small
hardcoded list of common two-label suffixes (`co.uk`, `com.au`, ...) plus a naive last-two-labels
fallback for everything else. This is correct for the common cases (including the ones tested), but
will misclassify alignment for less common multi-part suffixes not in that list. For authoritative
results, replace it with the `tldextract` package or the official PSL data file.


