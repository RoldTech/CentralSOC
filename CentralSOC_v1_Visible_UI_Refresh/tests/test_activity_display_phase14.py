from regexsoc.db.activity_display import describe_activity


def test_activity_details_are_readable():
    assert describe_activity('INCIDENT_UPDATED', '{"owner_from":null,"owner_to":"alice"}') == 'Assigned to alice'
    assert 'Investigating' in describe_activity('INCIDENT_UPDATED', '{"from":"Open","to":"Investigating"}')
    assert 'brute-force' in describe_activity('PLAYBOOK_SELECTED', '{"playbook":"brute_force"}').lower()
    assert describe_activity('INCIDENT_NOTE_ADDED', '{"note":"Reviewed evidence"}') == 'Reviewed evidence'


def test_activity_output_does_not_trust_malformed_or_unknown_json():
    assert 'unavailable' in describe_activity('INCIDENT_CREATED', '{')
    assert describe_activity('SOMETHING_ELSE', '{"token":"secret"}') == 'Activity recorded'
