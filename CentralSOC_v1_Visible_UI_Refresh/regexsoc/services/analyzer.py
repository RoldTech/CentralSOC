"""The analysis pipeline: parse -> detect -> correlate -> extract IOCs -> score -> alert."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from regexsoc import config
from regexsoc.detectors import Detection, IOC, correlate, detect_event, extract_iocs
from regexsoc.models import Event, Severity
from regexsoc.parsers import parse_lines
from regexsoc.rules import Rule, load_rules
from regexsoc.services.alerts import Alert, build_alerts
from regexsoc.services.risk import RiskProfile, ScoringConfig, apply_scoring, profile_entities
from regexsoc.services.stats import summarize


@dataclass
class AnalysisResult:
    events: list[Event]
    detections: list[Detection]
    alerts: list[Alert]
    iocs: list[IOC]
    profiles: dict[str, RiskProfile]
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "alerts": [a.to_dict() for a in self.alerts],
            "detections": [d.to_dict() for d in self.detections],
            "iocs": [i.to_dict() for i in self.iocs],
            "risk_profiles": [p.to_dict() for p in sorted(self.profiles.values(), key=lambda p: -p.score)],
        }


def read_log_lines(path: str | Path) -> list[str]:
    """Read a log file as text without ever executing it. Enforces a size limit; never raises on bad bytes."""
    path = Path(path)
    size = path.stat().st_size
    if size > config.max_input_bytes():
        raise ValueError(f"{path} is {size} bytes; limit is {config.max_input_bytes()} (REGEXSOC_MAX_INPUT_BYTES)")
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


class Analyzer:
    """Runs the full detection pipeline over log lines."""

    def __init__(
        self,
        rules: list[Rule] | None = None,
        scoring: ScoringConfig | None = None,
        watchlist: Iterable[str] | None = None,
        default_year: int | None = None,
    ) -> None:
        self.rules = rules if rules is not None else load_rules()
        self.scoring = scoring or ScoringConfig()
        self.watchlist = {w.strip().lower() for w in (watchlist or ()) if w.strip()}
        self.default_year = default_year

    @classmethod
    def from_feed_file(cls, path: str | Path, **kwargs) -> "Analyzer":
        """Use only valid, unexpired IOCs from a local analyst-reviewed feed.

        The feed is not fetched over the network and never triggers automatic response.
        """
        from regexsoc.services.threat_feed import load_feed
        records = load_feed(path)
        analyzer = cls(watchlist=[item.value for item in records], **kwargs)
        analyzer.feed_provenance = {item.value: item.source for item in records}
        return analyzer

    def analyze_lines(self, lines: Iterable[str]) -> AnalysisResult:
        return self.analyze_events(parse_lines(lines, year=self.default_year))

    def analyze_file(self, path: str | Path, *, original_name: str | None = None) -> AnalysisResult:
        extension = Path(original_name or path).suffix.lower()
        if extension in (".csv", ".json", ".jsonl"):
            from regexsoc.parsers.structured import parse_structured
            return self.analyze_events(parse_structured(path, extension))
        return self.analyze_lines(read_log_lines(path))

    def analyze_events(self, events: list[Event]) -> AnalysisResult:
        detections: list[Detection] = []
        iocs: list[IOC] = []
        for event in events:
            detections.extend(detect_event(event, self.rules))
            iocs.extend(extract_iocs(event, self.rules))
        detections.extend(correlate(events, self.rules))
        detections.extend(self._watchlist_hits(iocs, {e.id: e for e in events}))
        for d in detections:
            apply_scoring(d, self.scoring)
        detections.sort(key=lambda d: (-d.risk_score, d.timestamp.isoformat() if d.timestamp else ""))

        by_id = {e.id: e for e in events}
        for d in detections:  # event severity = highest severity of any detection touching it
            for event_id in d.event_ids:
                event = by_id.get(event_id)
                if event and Severity.parse(d.severity).rank > Severity.parse(event.severity).rank:
                    event.severity = d.severity

        return AnalysisResult(
            events=events,
            detections=detections,
            alerts=build_alerts(detections, self.scoring.alert_threshold),
            iocs=iocs,
            profiles=profile_entities(detections, self.scoring),
            summary=summarize(events, detections, iocs),
        )

    def _watchlist_hits(self, iocs: list[IOC], events: dict[int, Event]) -> list[Detection]:
        rule = next((r for r in self.rules if r.target == "watchlist" and r.enabled), None)
        if rule is None or not self.watchlist:
            return []
        hits = []
        for ioc in iocs:
            if ioc.value.lower() in self.watchlist:
                event = events[ioc.event_id]
                hits.append(Detection.from_rule(
                    rule, reason=f"{ioc.ioc_type} {ioc.value} is on the watchlist." + (
                        f" Source: {self.feed_provenance[ioc.value.lower()]}"
                        if hasattr(self, "feed_provenance") and ioc.value.lower() in self.feed_provenance else ""),
                    source_ip=event.source_ip, username=event.username, event_type=event.event_type,
                    timestamp=event.timestamp, event_ids=[event.id], evidence=[event.raw_log],
                    details={"ioc_type": ioc.ioc_type, "ioc_value": ioc.value},
                ))
        return hits
