# Log Integrity

**Hashing provides integrity verification, not confidentiality.** A SHA-256 hash shows whether data changed; it does
not hide the data, and anyone who can read the file can still read its contents.

## What is protected

1. **File hash.** At ingest a read-only copy is stored under a random name and hashed (`log_files.sha256`, the *original hash*).
   `verify` re-hashes the stored copy (the *current hash*) and reports `OK`, `TAMPERED` or `MISSING`.
2. **Event hash chain.** Each event stores `hash = SHA-256(prev_hash | canonical_event)`. The first `prev_hash` is the file's
   SHA-256, so the events are cryptographically tied to the exact file they came from. `verify` recomputes the chain and reports:
   - a **modified** event (at its sequence number)
   - a **deleted** or **reordered** event (sequence gap)
   - **removed trailing events** (count mismatch with `event_count`)
   - an **inserted** event (its link does not match)

Covered fields: timestamp, IPs, ports, protocol, username, auth status, HTTP method/path/status, user agent, host, event type,
source format and the raw log line. Severity is deliberately excluded because it can change if a log is re-analyzed.

## What it does not protect against

- A plain chain is **tamper-evident, not tamper-proof.** Someone with full database write access can recompute every hash.
- Optional mitigation: set `REGEXSOC_INTEGRITY_KEY`. The chain then uses HMAC-SHA256, so forging it also needs the key.
  Changing or losing the key makes verification fail, so keep it in a secrets manager. It is never written to the database or audit log.
- For stronger guarantees, periodically export the final chain hash to a separate write-once system.
- Tampering *before* ingest is not detectable, because the hash is taken at ingest time.

## Commands

```
python -m regexsoc ingest sample_logs/ssh_auth.log --year 2024 --user alice
python -m regexsoc verify            # all files; exit code 1 if anything fails
python -m regexsoc verify 1
```
