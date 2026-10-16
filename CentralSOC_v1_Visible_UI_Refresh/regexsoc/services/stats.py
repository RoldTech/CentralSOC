"""Summary statistics (also the basis for the dashboard in Phase 4)."""

from __future__ import annotations

from collections import Counter

from regexsoc.detectors.base import Detection
from regexsoc.detectors.ioc import IOC
from regexsoc.models import Event, EventType


def summarize(events: list[Event], detections: list[Detection], iocs: list[IOC], top: int = 10) -> dict:
    types = Counter(e.event_type for e in events)
    sev = Counter(d.severity for d in detections)
    return {
        "total_events": len(events),
        "failed_logins": types[EventType.FAILED_LOGIN],
        "successful_logins": types[EventType.LOGIN_SUCCESS],
        "detections": len(detections),
        "severity_counts": {s: sev.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "detection_categories": dict(Counter(d.category for d in detections).most_common()),
        "event_types": dict(types.most_common()),
        "top_source_ips": Counter(e.source_ip for e in events if e.source_ip).most_common(top),
        "top_usernames": Counter(e.username for e in events if e.username).most_common(top),
        "top_destination_ports": Counter(e.destination_port for e in events if e.destination_port).most_common(top),
        "ioc_count": len(iocs),
        "ioc_by_type": dict(Counter(i.ioc_type for i in iocs).most_common()),
    }
