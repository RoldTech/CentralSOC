"""RegexSOC command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from regexsoc import __version__
from regexsoc.cli import db_commands, email_commands, user_commands
from regexsoc.detectors.ioc import IOC
from regexsoc.models import Severity
from regexsoc.rules import UnknownRuleError, load_rules, set_enabled
from regexsoc.rules.docs import render_markdown
from regexsoc.services import Analyzer, ScoringConfig
from regexsoc.services.export import to_csv, to_json
from regexsoc.services.monitor import StreamAnalyzer, follow
from regexsoc.services.report import filter_by_severity, group_findings, render_findings, render_report
from regexsoc.utils.net import is_private

SEVERITIES = [s.value.lower() for s in Severity]


def _analyzer(args: argparse.Namespace) -> Analyzer:
    scoring = ScoringConfig.from_file(args.scoring) if getattr(args, "scoring", None) else None
    watchlist = None
    if getattr(args, "watchlist", None):
        watchlist = Path(args.watchlist).read_text(encoding="utf-8").splitlines()
    return Analyzer(scoring=scoring, watchlist=watchlist, default_year=getattr(args, "year", None))


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("logfile")
    p.add_argument("--year", type=int, help="year for syslog timestamps (syslog omits it); default: current year")
    p.add_argument("--watchlist", help="file with one known-bad IOC per line")
    p.add_argument("--scoring", help="JSON file overriding scoring points/thresholds")


def cmd_analyze(args: argparse.Namespace) -> int:
    result = _analyzer(args).analyze_file(args.logfile)
    findings = filter_by_severity(result.detections, args.severity)
    if args.format == "json":
        data = result.to_dict()
        data["detections"] = [d.to_dict() for d in findings]
        print(to_json(data))
    elif args.format == "csv":
        print(to_csv(group_findings(findings)), end="")
    else:
        s = result.summary
        print(f"Parsed {s['total_events']} events; {len(result.detections)} detections, {len(result.alerts)} alerts.\n")
        print(render_findings(findings), end="")
    return 0


def cmd_extract_iocs(args: argparse.Namespace) -> int:
    result = _analyzer(args).analyze_file(args.logfile)
    iocs: list[IOC] = result.iocs
    if args.type:
        iocs = [i for i in iocs if i.ioc_type == args.type.upper()]
    if args.exclude_private:
        iocs = [i for i in iocs if not (i.ioc_type in {"IPV4", "IPV6"} and is_private(i.value))]
    if args.format == "json":
        print(to_json([i.to_dict() for i in iocs]))
    elif args.format == "csv":
        print(to_csv([i.to_dict() for i in iocs]), end="")
    else:
        counts: dict[tuple[str, str], int] = {}
        for i in iocs:
            counts[(i.ioc_type, i.value)] = counts.get((i.ioc_type, i.value), 0) + 1
        for (kind, value), n in sorted(counts.items()):
            print(f"{kind:<10} {value}  (x{n})")
        print(f"\n{len(counts)} unique IOCs")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    result = _analyzer(args).analyze_file(args.logfile)
    text = render_report(result, args.logfile, args.severity)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(text, end="")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    if args.action == "list":
        for r in load_rules():
            state = "on " if r.enabled else "off"
            print(f"{r.id}  [{state}]  {r.severity:<8} {r.risk_score:>3}  {r.category:<15} {r.name}")
    elif args.action in {"enable", "disable"}:
        rule = set_enabled(args.rule_id, args.action == "enable")
        print(f"{rule.id} ({rule.name}) is now {'enabled' if rule.enabled else 'disabled'}")
    elif args.action == "show":
        match = next((r for r in load_rules() if r.id == args.rule_id.upper()), None)
        if match is None:
            raise UnknownRuleError(args.rule_id)
        print(to_json(match.to_dict()))
    elif args.action == "docs":
        target = Path(args.output or "docs/detection-rules.md")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_markdown(load_rules()), encoding="utf-8")
        print(f"Wrote {target}")
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    stream = StreamAnalyzer(_analyzer(args))
    floor = Severity.parse(args.severity).rank
    print(f"Monitoring {args.logfile} (read-only). Ctrl+C to stop.", file=sys.stderr)
    try:
        for line in follow(args.logfile, args.poll_interval, args.from_start):
            for alert in stream.feed(line):
                if Severity.parse(alert.severity).rank >= floor:
                    print(f"[{alert.severity}] {alert.alert_id} {alert.rule_id} {alert.rule_name} "
                          f"src={alert.source_ip} user={alert.username} score={alert.risk_score} :: {alert.reason}",
                          flush=True)
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
    return 0


def cmd_users(args: argparse.Namespace) -> int:
    if args.action == "create":
        return user_commands.create(args)
    if args.action == "list":
        return user_commands.list_users(args)
    if args.action == "set-role":
        return user_commands.set_role(args)
    if args.action == "enable":
        return user_commands.set_active(args, True)
    if args.action == "disable":
        return user_commands.set_active(args, False)
    return 2


def cmd_email(args: argparse.Namespace) -> int:
    if args.action == "parse":
        return email_commands.parse(args)
    if args.action == "analyze":
        return email_commands.analyze(args)
    return 2


def cmd_db(args: argparse.Namespace) -> int:
    return db_commands.db_init(args)


def cmd_ingest(args: argparse.Namespace) -> int:
    return db_commands.ingest(args, _analyzer(args))


def cmd_verify(args: argparse.Namespace) -> int:
    return db_commands.verify(args)


def cmd_alerts(args: argparse.Namespace) -> int:
    return db_commands.alerts(args)


def cmd_audit(args: argparse.Namespace) -> int:
    return db_commands.audit(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="regexsoc", description="Defensive, regex-driven security log analyzer.")
    parser.add_argument("--version", action="version", version=f"regexsoc {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="detect suspicious activity in a log file")
    _add_common(p)
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    p.add_argument("--severity", choices=SEVERITIES, default="low", help="minimum severity to show")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("extract-iocs", help="extract indicators of compromise")
    _add_common(p)
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    p.add_argument("--type", help="only this IOC type (IPV4, DOMAIN, URL, MD5, SHA256, CVE...)")
    p.add_argument("--exclude-private", action="store_true", help="drop private/reserved IPs")
    p.set_defaults(func=cmd_extract_iocs)

    p = sub.add_parser("report", help="full analyst report")
    _add_common(p)
    p.add_argument("--severity", choices=SEVERITIES, default="low")
    p.add_argument("--output", help="write the report to this file")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("rules", help="list, inspect, enable or disable detection rules")
    rsub = p.add_subparsers(dest="action", required=True)
    rsub.add_parser("list")
    for name in ("enable", "disable", "show"):
        rp = rsub.add_parser(name)
        rp.add_argument("rule_id")
    rp = rsub.add_parser("docs", help="regenerate docs/detection-rules.md")
    rp.add_argument("--output")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("monitor", help="follow a log file and alert in real time (read-only)")
    _add_common(p)
    p.add_argument("--severity", choices=SEVERITIES, default="medium")
    p.add_argument("--poll-interval", type=float, default=1.0)
    p.add_argument("--from-start", action="store_true", help="process existing content first")
    p.set_defaults(func=cmd_monitor)

    p = sub.add_parser("db", help="database maintenance (needs SQLAlchemy)")
    dsub = p.add_subparsers(dest="action", required=True)
    dsub.add_parser("init", help="create tables")
    p.set_defaults(func=cmd_db)

    p = sub.add_parser("ingest", help="analyze a log and store events, alerts and IOCs in the database")
    _add_common(p)
    p.add_argument("--user", help="analyst name recorded in the audit log (default: cli:<os user>)")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("verify", help="verify stored log files: SHA-256 and event hash chain")
    p.add_argument("file_id", nargs="?", type=int, help="log file id (default: all)")
    p.add_argument("--user")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("alerts", help="list alerts or change their status")
    asub = p.add_subparsers(dest="action", required=True)
    lp = asub.add_parser("list")
    lp.add_argument("--status", help="New, Investigating, Resolved or False Positive")
    lp.add_argument("--severity", choices=SEVERITIES, help="minimum severity")
    lp.add_argument("--limit", type=int, default=100)
    sp = asub.add_parser("set-status")
    sp.add_argument("alert_id")
    sp.add_argument("new_status", help='e.g. investigating, resolved, "false positive"')
    sp.add_argument("--note")
    sp.add_argument("--user", help="analyst name recorded in the audit log")
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("audit", help="show the application audit log")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("users", help="manage web-app user accounts (needs SQLAlchemy)")
    usub = p.add_subparsers(dest="action", required=True)
    cp = usub.add_parser("create", help="create a user (bootstrap the first ADMIN this way)")
    cp.add_argument("username")
    cp.add_argument("--role", choices=list(__import__("regexsoc.security.rbac", fromlist=["ROLES"]).ROLES), default="VIEWER")
    cp.add_argument("--email")
    cp.add_argument("--password", help="omit to be prompted (recommended: avoids shell history)")
    usub.add_parser("list")
    sp = usub.add_parser("set-role")
    sp.add_argument("username")
    sp.add_argument("role", choices=list(__import__("regexsoc.security.rbac", fromlist=["ROLES"]).ROLES))
    for name in ("enable", "disable"):
        ep = usub.add_parser(name)
        ep.add_argument("username")
    p.set_defaults(func=cmd_users)

    p = sub.add_parser("email", help="email security: parse .eml files (Phase 1 — no SPF/DKIM/DMARC evaluation yet)")
    esub = p.add_subparsers(dest="action", required=True)
    ep = esub.add_parser("parse", help="parse an .eml file and show its structure")
    ep.add_argument("eml_file")
    ep.add_argument("--format", choices=["text", "json"], default="text")
    ap = esub.add_parser("analyze", help="parse + evaluate SPF/DKIM/DMARC authentication and alignment")
    ap.add_argument("eml_file")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--internal-domain", action="append",
                    help="your organization's own domain (repeatable); enables external-sender-"
                         "claiming-executive-title detection")
    p.set_defaults(func=cmd_email)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except UnknownRuleError as exc:
        print(f"error: unknown rule {exc}", file=sys.stderr)
    except LookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
    return 2
