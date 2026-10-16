"""Safe, concise incident activity descriptions for server-rendered analyst timelines.

Audit source records remain unchanged. Never interpret untrusted audit JSON as HTML.
"""
import json

from regexsoc.db.playbooks import PLAYBOOKS


def describe_activity(action: str, detail: str | None) -> str:
    try:
        values = json.loads(detail or '{}')
    except (TypeError, ValueError):
        return 'Activity recorded (details unavailable)'
    if not isinstance(values, dict):
        return 'Activity recorded'
    if action == 'INCIDENT_CREATED':
        return f"Incident created with {values.get('severity', 'unspecified')} severity"
    if action == 'INCIDENT_UPDATED':
        if 'owner_to' in values:
            return f"Assigned to {values['owner_to']}"
        if 'to' in values:
            return f"Status changed from {values.get('from', 'unknown')} to {values['to']}"
    if action == 'INCIDENT_NOTE_ADDED':
        return str(values.get('note', 'Note added'))
    if action == 'INCIDENT_ALERT_LINKED':
        return f"Linked alert {values.get('alert_id', 'unknown')}"
    if action == 'PLAYBOOK_SELECTED':
        playbook = PLAYBOOKS.get(values.get('playbook'))
        return f"Selected {playbook.title if playbook else 'response playbook'}"
    if action == 'PLAYBOOK_STEP_COMPLETED':
        playbook = PLAYBOOKS.get(values.get('playbook'))
        label = dict(playbook.steps).get(values.get('step'), 'checklist step') if playbook else 'checklist step'
        return f"Recorded completion: {label}"
    return 'Activity recorded'
