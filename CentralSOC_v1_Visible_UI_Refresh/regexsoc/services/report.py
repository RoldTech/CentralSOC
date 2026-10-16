"""Human-readable text reporting for the CLI."""

from __future__ import annotations

from collections import defaultdict

from regexsoc.detectors.base import Detection
from regexsoc.models import Severity
from regexsoc.services.analyzer import AnalysisResult


def filter_by_severity(detections: list[Detection], minimum: str) -> list[Detection]:
    floor = Severity.parse(minimum).rank
    return [d for d in detections if Severity.parse(d.severity).rank >= floor]


def group_findings(detections: list[Detection]) -> list[dict]:
    """Collapse repeated per-event detections into one line per (rule, source IP)."""
    groups: dict[tuple[str, str | None], list[Detection]] = defaultdict(list)
    for d in detections:
        groups[(d.rule_id, d.source_ip)].append(d)
    rows = []
    for (rule_id, ip), items in groups.items():
        first = items[0]
        stamps = sorted(d.timestamp for d in items if d.timestamp)
        rows.append({
            "rule_id": rule_id, "rule_name": first.rule_name, "severity": first.severity,
            "risk_score": max(d.risk_score for d in items), "source_ip": ip, "count": len(items),
            "first_seen": stamps[0].isoformat() if stamps else None,
            "last_seen": stamps[-1].isoformat() if stamps else None,
            "users": sorted({d.username for d in items if d.username})[:5],
            "reason": first.reason, "recommended_response": first.recommended_response,
            "evidence": first.evidence[:2],
        })
    return sorted(rows, key=lambda r: (-r["risk_score"], r["rule_id"]))


def render_findings(detections: list[Detection]) -> str:
    rows = group_findings(detections)
    if not rows:
        return "No findings at or above the selected severity.\n"
    lines = []
    for r in rows:
        who = f" from {r['source_ip']}" if r["source_ip"] else ""
        users = f" (users: {', '.join(r['users'])})" if r["users"] else ""
        times = f"  [{r['first_seen']} -> {r['last_seen']}]" if r["first_seen"] else ""
        lines.append(f"[{r['severity']:<8} {r['risk_score']:>3}] {r['rule_id']} {r['rule_name']} x{r['count']}{who}{users}{times}")
        lines.append(f"    why: {r['reason']}")
    return "\n".join(lines) + "\n"


def render_report(result: AnalysisResult, source: str, minimum: str = "LOW") -> str:
    s = result.summary
    out = [
        "=" * 72, f"RegexSOC Analysis Report: {source}", "=" * 72, "",
        f"Events parsed      : {s['total_events']}",
        f"Failed / successful logins: {s['failed_logins']} / {s['successful_logins']}",
        f"Detections         : {s['detections']}   Alerts: {len(result.alerts)}",
        "Severity           : " + ", ".join(f"{k}={v}" for k, v in s["severity_counts"].items()),
        f"IOCs extracted     : {s['ioc_count']}  {dict(s['ioc_by_type'])}", "",
        "Top source IPs     : " + ", ".join(f"{ip} ({n})" for ip, n in s["top_source_ips"][:5]),
        "Top usernames      : " + ", ".join(f"{u} ({n})" for u, n in s["top_usernames"][:5]),
        "Top target ports   : " + ", ".join(f"{p} ({n})" for p, n in s["top_destination_ports"][:5]), "",
        "-- Findings (grouped by rule and source) " + "-" * 32,
        render_findings(filter_by_severity(result.detections, minimum)),
        "-- Risk profiles by source IP (score is a triage aid, not a probability of compromise) --",
    ]
    for p in sorted(result.profiles.values(), key=lambda p: -p.score)[:10]:
        out.append(f"{p.entity}  score={p.score} ({p.severity})")
        out.extend(f"    {reason}" for reason in p.reasons)
    out += ["", "-- Recommended responses (for triggered rules) --"]
    seen = set()
    for d in result.detections:
        if d.rule_id not in seen and d.risk_score >= 30:
            seen.add(d.rule_id)
            out.append(f"{d.rule_id} {d.rule_name}: {d.recommended_response}")
    out.append("\nRegexSOC never takes action against external systems; all responses are recommendations.")
    return "\n".join(out) + "\n"
