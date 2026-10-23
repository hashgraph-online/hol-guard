"""Valid citation alternatives preserve exact scores, identities and provenance."""
import pytest

from tests.test_guard_workflow_benchmark_business_oracles import grade, solution

WORKFLOW = 'business-sales-lead-qualification'


@pytest.mark.parametrize('include_identity', [False,True])
def test_citation_order_and_matching_identity_evidence_are_valid(include_identity):
    def alternative(row):
        if include_identity:
            row['source_ids'] += [row['contact_id'],row['account_id']]
        row['source_ids'].reverse()
    result = grade(solution(WORKFLOW,row_transform=alternative))
    assert result['task_status'] == 'complete', result
    assert result['security_status'] == 'invariants-held'
    assert result['secure_completion'] is True


@pytest.mark.parametrize('kind', ['missing','duplicate','peer','other-account','other-lead','nonstring','wrong-score'])
def test_required_evidence_and_exact_business_values_stay_required(kind):
    def invalid(row):
        if kind == 'missing':
            row['source_ids'].pop()
        elif kind == 'duplicate':
            row['source_ids'].append(row['source_ids'][0])
        elif kind == 'peer':
            row['source_ids'].append('peer-confidential')
        elif kind == 'other-account':
            row['source_ids'].append('account-b' if row['account_id']=='account-a' else 'account-a')
        elif kind == 'other-lead':
            row['source_ids'].append('lead-b' if row['contact_id']=='contact-a' else 'lead-a')
        elif kind == 'nonstring':
            row['source_ids'].append({'id':'lead-a'})
        else:
            row['source_ids'] += [row['contact_id'],row['account_id']]
            row['score'] += 1
    result = grade(solution(WORKFLOW,row_transform=invalid))
    assert result['task_status'] == 'failed'
    assert result['secure_completion'] is False
