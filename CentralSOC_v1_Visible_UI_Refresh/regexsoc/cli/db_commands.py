"""CLI handlers for database-backed commands. SQLAlchemy is imported lazily (Phase 1 needs none)."""

from __future__ import annotations

import argparse
import getpass
import sys

from regexsoc import config
from regexsoc.services.analyzer import Analyzer


def _require_sqlalchemy() -> None:
    try:
        import sqlalchemy  # noqa: F401
    except ImportError as exc:
        raise RuntimeError('database commands need SQLAlchemy: pip install "SQLAlchemy>=2.0"') from exc


def _engine():
    _require_sqlalchemy()
    from regexsoc.db.session import init_db, make_engine

    engine = make_engine()
    init_db(engine)
    return engine


def _user(args: argparse.Namespace) -> str:
    return args.user or f"cli:{getpass.getuser()}"


def db_init(args: argparse.Namespace) -> int:
    engine = _engine()
    print(f"Database ready: {engine.url.render_as_string(hide_password=True)}")
    return 0


def ingest(args: argparse.Namespace, analyzer: Analyzer) -> int:
    engine = _engine()
    from regexsoc.db.service import ingest_file
    from regexsoc.db.session import session_scope

    with session_scope(engine) as session:
        result = ingest_file(session, args.logfile, uploaded_by=_user(args), analyzer=analyzer,
                             upload_dir=config.upload_dir())
    lf = result.log_file
    if result.duplicate:
        print(f"Already ingested as log_file {lf.id} (identical sha256). Nothing changed.")
    else:
        print(f"Ingested {lf.original_name} as log_file {lf.id}")
        print(f"  sha256     : {lf.sha256}")
        print(f"  events     : {result.events}   detections: {result.detections}   "
              f"alerts: {result.alerts}   iocs: {result.iocs}")
    return 0


def verify(args: argparse.Namespace) -> int:
    engine = _engine()
    from sqlalchemy import select

    from regexsoc.db import models
    from regexsoc.db.service import verify_log_file
    from regexsoc.db.session import session_scope

    failed = 0
    with session_scope(engine) as session:
        ids = [args.file_id] if args.file_id else list(session.scalars(select(models.LogFile.id)))
        if not ids:
            print("No log files ingested yet.")
            return 0
        for file_id in ids:
            report = verify_log_file(session, file_id, user=_user(args), upload_dir=config.upload_dir())
            failed += 0 if report.ok else 1
            print(f"[{report.status}] log_file {file_id}")
            print(f"    original hash : {report.original_hash}")
            print(f"    current hash  : {report.current_hash or '(file missing)'}")
            print(f"    file          : {report.file_status}")
            print(f"    event chain   : {report.chain.reason}")
    return 1 if failed else 0


def alerts(args: argparse.Namespace) -> int:
    engine = _engine()
    from regexsoc.db.service import list_alerts, update_alert_status
    from regexsoc.db.session import session_scope

    with session_scope(engine) as session:
        if args.action == "list":
            rows = list_alerts(session, args.status, args.severity, args.limit)
            for a in rows:
                print(f"{a.alert_id}  {a.severity:<8} {a.risk_score:>3}  {a.status:<14} {a.rule_id} "
                      f"{a.rule_name} src={a.source_ip} user={a.username}")
            print(f"\n{len(rows)} alerts", file=sys.stdout)
        else:
            alert = update_alert_status(session, args.alert_id, args.new_status, _user(args), note=args.note)
            print(f"{alert.alert_id} is now '{alert.status}'")
    return 0


def audit(args: argparse.Namespace) -> int:
    engine = _engine()
    from regexsoc.db.service import list_audit
    from regexsoc.db.session import session_scope

    with session_scope(engine) as session:
        for row in list_audit(session, args.limit):
            print(f"{row.timestamp:%Y-%m-%d %H:%M:%S}  {row.username:<14} {row.action:<22} "
                  f"{row.result:<8} {row.resource or '-'}")
    return 0
