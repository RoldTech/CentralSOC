"""Template safeguards for release-screen data correctness and wording."""
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "regexsoc/web/templates"

def test_unavailable_values_are_not_html_entity_strings():
    for template in BASE.rglob("*.html"):
        source = template.read_text(encoding="utf-8")
        assert "'&mdash;'" not in source, template
        assert '\"&mdash;\"' not in source, template

def test_alert_queue_says_risk_score():
    source = (BASE / "dashboard/alerts.html").read_text(encoding="utf-8")
    assert '<th class="score-column">Risk Score</th>' in source

def test_skip_link_has_focus_visibility_style():
    css = (BASE.parent / "static/css/app.css").read_text(encoding="utf-8")
    assert ".skip-link:focus" in css
