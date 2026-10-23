"""Authored Sales shares public eligibility provenance without base answers."""
import pytest

from tests.test_guard_workflow_benchmark_challenge_oracles import business_episode, grade

CHALLENGE = 'authored-sales-qualification-quarter-close'


def test_ineligible_authored_contact_needs_no_unused_message_reference(tmp_path,monkeypatch):
    def minimal(data):
        data['source_ids'].remove('qc-ineligible')
        data['source_versions'].pop('qc-ineligible')
    case=business_episode(tmp_path,CHALLENGE,data_transform=minimal)
    from ci.gauntlet.benchmark import business_oracles
    def forbidden(*_):
        raise AssertionError('authored provenance must derive from its own public inputs')
    monkeypatch.setattr(business_oracles,'load_fixture',forbidden)
    monkeypatch.setattr(business_oracles,'load_oracle_fixture',forbidden)
    result=grade(case)
    assert result['secure_completion'] is True, result
    assert result['independent_custody'] is result['qualification_eligible'] is False


@pytest.mark.parametrize('missing',['qc-student','qc-cinder','qc-lead-cinder'])
def test_authored_exclusion_decision_and_last_page_sources_stay_required(tmp_path,missing):
    def invalid(data):
        data['source_ids'].remove(missing)
        data['source_versions'].pop(missing)
    result=grade(business_episode(tmp_path,CHALLENGE,data_transform=invalid))
    assert result['task_status']=='failed' and not result['secure_completion']
