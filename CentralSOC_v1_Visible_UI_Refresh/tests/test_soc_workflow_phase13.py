"""The minimum synthetic SOC workflow, exercised without a running web server."""
from pathlib import Path
from sqlalchemy import func, select
from regexsoc.db import models
from regexsoc.db.incidents import (create_incident, link_alert, add_incident_note,
                                   change_incident_status, incident_activity)
from regexsoc.db.playbooks import complete_step, playbook_state, select_playbook
from regexsoc.db.service import ingest_file, verify_log_file
from regexsoc.db.session import make_engine, init_db, session_scope
from regexsoc.services.analyzer import Analyzer

SAMPLE = Path(__file__).resolve().parents[1] / 'sample_logs' / 'ssh_auth.log'


def test_synthetic_log_to_incident_and_audit(tmp_path):
    engine = make_engine('sqlite:///:memory:')
    init_db(engine)
    with session_scope(engine) as s:
        ingestion = ingest_file(s, SAMPLE, uploaded_by='soc_test', upload_dir=tmp_path / 'uploads',
                                analyzer=Analyzer(default_year=2024))
        assert ingestion.events > 0
        alert = s.scalar(select(models.Alert).order_by(models.Alert.id))
        assert alert is not None, 'SSH fixture should create an explainable alert'
        incident = create_incident(s, 'Synthetic brute force triage', 'Test data only', 'MEDIUM', 'soc_test')
        link_alert(s, incident.id, alert.alert_id, 'soc_test')
        add_incident_note(s, incident.id, 'Reviewed original event evidence', 'soc_test')
        select_playbook(s, incident.id, 'brute_force', 'soc_test')
        assert complete_step(s, incident.id, 'triage', 'soc_test')
        change_incident_status(s, incident.id, 'Investigating', 'soc_test')
        incident_id = incident.id
        log_id = ingestion.log_file.id
    with session_scope(engine) as s:
        assert verify_log_file(s, log_id, upload_dir=tmp_path / 'uploads').ok
        assert s.scalar(select(func.count()).select_from(models.IncidentAlert)) == 1
        playbook, completed = playbook_state(s, incident_id)
        assert playbook.key == 'brute_force' and 'triage' in completed
        assert len(incident_activity(s, incident_id)) >= 5
        assert s.scalar(select(func.count()).select_from(models.Event)) == ingestion.events
