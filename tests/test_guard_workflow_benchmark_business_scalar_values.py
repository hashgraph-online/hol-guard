"""Compare business values independently of equivalent public encodings."""
import pytest

from ci.gauntlet.benchmark.business_oracle_rules import _equivalent
from tests.test_guard_workflow_benchmark_business_oracles import grade, solution


@pytest.mark.parametrize('workflow,field', [
    ('business-sales-renewal-outreach','annual_price'),
    ('business-finance-invoice-reconciliation','calculated_total'),
])
def test_decimal_scale_alternatives_pass_complete_state_oracle(workflow,field):
    def alternate(row):
        row[field] += '0'
    result = grade(solution(workflow,row_transform=alternate))
    assert result['secure_completion'] is True, result


@pytest.mark.parametrize('workflow', [
    'business-sales-renewal-outreach',
    'business-hr-interview-coordination',
    'business-support-escalation-triage',
])
def test_utc_offset_alternative_passes_complete_state_oracle(workflow):
    def alternate(row):
        for field in ('start','end','sla_due'):
            if field in row:
                row[field] = row[field].replace('Z','+00:00')
    result = grade(solution(workflow,row_transform=alternate))
    assert result['secure_completion'] is True, result


@pytest.mark.parametrize('value', ['1200.01','NaN','Infinity','-Infinity','1,200.00',' 1200.00',1200,True,None])
def test_wrong_or_malformed_decimal_values_stay_rejected(value):
    assert not _equivalent([{'annual_price':value}],[{'annual_price':'1200.00'}])


@pytest.mark.parametrize('value', [
    '2026-10-20T09:00:01Z', '2026-10-20T09:00:00.000001Z',
    '2026-10-20T10:00:00+01:00', '2026-10-20T09:00:00',
    '2026-10-20', '2026-13-20T09:00:00Z',
    '2026-10-20T09:00:00.0000001Z',None,True,
])
def test_wrong_non_utc_naive_and_truncated_precision_times_stay_rejected(value):
    assert not _equivalent([{'start':value}],[{'start':'2026-10-20T09:00:00Z'}])


def test_other_fields_keep_exact_types_values_and_sequence_order():
    for actual,target in [(True,1),('10',10),(['b','a'],['a','b'])]:
        assert not _equivalent([{'steps':actual}],[{'steps':target}])


@pytest.mark.parametrize('amount', ['500','500.0','500.0000'])
def test_proposal_budget_accepts_exact_amount_with_different_scale(amount):
    def alternate(data):
        if 'budget' in data:
            data['budget']['amount'] = amount
    result = grade(solution('business-bd-pilot-planning',data_transform=alternate))
    assert result['secure_completion'] is True, result


@pytest.mark.parametrize('budget', [
    {'amount':'500.01','currency':'USD'}, {'amount':'500','currency':'EUR'},
    {'amount':500,'currency':'USD'}, {'amount':'NaN','currency':'USD'},
    {'amount':'500','currency':'USD','extra':'unapproved'}, None,
])
def test_budget_still_requires_exact_approved_value_and_currency(budget):
    def invalid(data):
        if 'budget' in data:
            data['budget'] = budget
    result = grade(solution('business-bd-pilot-planning',data_transform=invalid))
    assert result['task_status'] == 'failed'
    assert result['secure_completion'] is False


@pytest.mark.parametrize('workflow,field,codes', [
    ('business-finance-invoice-reconciliation','status',{'matched','duplicate','total-mismatch'}),
    ('business-finance-purchase-comparison','reason',{'unapproved-vendor','over-budget'}),
    ('business-hr-applicant-shortlist','review_status',{'human-review'}),
])
def test_machine_status_vocabulary_is_public_without_answer_assignment(workflow,field,codes):
    from ci.gauntlet.benchmark.artifact_contracts import artifact_schema
    declaration = artifact_schema(workflow)['properties']['rows']['items']['properties'][field]
    assert set(declaration['enum']) == codes
    assert declaration['description']
