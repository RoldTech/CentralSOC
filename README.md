# CentralSOC
### Security Log Analyzer & Threat Detection Tool

CentralSOC is a defensive security project that turns raw logs into
normalized events, rule-based alerts, and documented investigations.

It brings log analysis, alert triage, incident tracking, and analyst
decision history into one interface.

## Live Demo

**Website:** https://central-soc.vercel.app

| Field | Demo credentials |
|---|---|
| Username | `DEMO_VIEWER` |
| Password | `Centralsoc01` |
| Role | Read-only Viewer |

The demo account can browse existing events, alerts, indicators of
compromise, detection rules, statistics, and incidents.

Uploads and operational changes are restricted. Password changes and
two-factor authentication setup/changes are blocked for this shared
demo account. Some restricted controls may still appear in the UI.

## Core Features

- **Log analysis:** Parse Linux/SSH, Apache/Nginx, Windows-style,
  and firewall logs into a normalized event model.
- **Threat detection:** Apply detection rules and event correlation
  to identify suspicious activity.
- **IOC extraction:** Extract indicators of compromise for investigation.
- **Risk scoring:** Prioritize alerts using transparent risk scores.
- **Alert triage:** Support ownership, status updates, and analyst verdicts.
- **Incident tracking:** Group related alerts and evidence into cases.
- **Security Memory:** Search saved analyst decisions and linked evidence.
- **Investigation support:** Generate and save evidence briefs.
- **Response workflow:** Request, approve, and execute one-time local
  evidence snapshots.
- **Reporting:** Export supported datasets as CSV or JSON.

## Security Features

- Role-based access control for viewers, analysts, managers, and admins
- Argon2 password hashing
- Optional TOTP two-factor authentication for regular accounts
- Login lockout controls
- Session expiration and CSRF protection
- File upload validation and size limits
- SHA-256 file hashing and event hash chaining for integrity verification
- Audit logging for supported security and analyst actions
- Server-side restrictions on shared demo account security settings

These controls are part of the implementation, not a claim of an
independent security audit or production certification.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Database access | SQLAlchemy |
| Schema migrations | Alembic |
| Hosted database | PostgreSQL on Neon |
| Demo hosting | Vercel |
| Tests | pytest |

## Project Vision

The long-term vision is a **Cybersecurity Flight Recorder +
Digital Immune System**: preserve evidence, retain investigation
knowledge, and support more effective responses.

The current version is a developing prototype—not a complete
autonomous security platform.

## Current Limitations

- Security Memory stores analyst decisions; it is not automatic AI learning.
- Optional AI investigation requires server configuration and explicit
  per-request consent. It is disabled in the public demo.
- External containment actions, such as isolating hosts, blocking IPs,
  and disabling accounts, are not implemented.
- Uploaded files and local snapshots on the Vercel demo use temporary
  storage. They are not durable forensic evidence storage.
- Demo database records are stored separately in Neon PostgreSQL.
- Further deployment hardening and end-to-end verification are needed
  before operational production use.

## Repository Guide

Application code and technical documentation are located in:

[`CentralSOC_v1_Visible_UI_Refresh/`](./CentralSOC_v1_Visible_UI_Refresh/)

- [Application README](./CentralSOC_v1_Visible_UI_Refresh/README.md)
- [Documentation](./CentralSOC_v1_Visible_UI_Refresh/docs/)
- [Tests](./CentralSOC_v1_Visible_UI_Refresh/tests/)

## Feedback

Feedback on detection quality, investigation workflows, usability,
and documentation is welcome through GitHub Issues.

Please do not include passwords, API keys, private logs, or sensitive
evidence in public issues.

## Intended Use

Built for defensive security monitoring, log analysis, and education.
Use only with systems and data you are authorized to analyze.
