"""Complete public output interfaces and task-required source provenance."""
import copy

import anyio
import pytest
from jsonschema import Draft202012Validator

from ci.gauntlet.benchmark.mcp_server import create_server
from tests.test_guard_workflow_benchmark_business_oracles import grade, solution


@pytest.mark.parametrize('workflow,family,collection,required', [
    ('business-sales-lead-qualification','mail','mail.drafts',{'body','recipients'}),
    ('business-bd-partner-assessment','docs','docs.documents',{'body'}),
    ('business-support-escalation-triage','chat','chat.drafts',{'body','channel_id'}),
    ('business-marketing-consented-outreach','tables','tables.sheets',{'columns'}),
])
def test_advertised_creation_schema_requires_existing_oracle_output_fields(workflow,family,collection,required):
    async def observe():
        return await create_server(object(),family,artifact_workflow_id=workflow).list_tools()
    tools=anyio.run(observe)
    verb='create_draft' if family=='mail' else 'create'
    schema=next(t.inputSchema for t in tools if t.name==family+'.'+verb)
    if family=='mail':
        shape=schema['properties']['data']
    else:
        shape=next(row['then']['properties']['data'] for row in schema['allOf']
                   if collection in row['if']['properties']['collection']['enum'])
    assert required <= set(shape['required'])
    assert required <= set(shape['properties'])
    initial,final,_=solution(workflow)
    initial_ids={record['id'] for record in initial['records']}
    data=next(record['data'] for record in final['records']
              if record['collection']==collection and record['id'] not in initial_ids)
    validator=Draft202012Validator(shape)
    validator.validate(data)
    for field in required:
        incomplete=copy.deepcopy(data)
        del incomplete[field]
        assert any(error.validator=='required' and not error.path
                   for error in validator.iter_errors(incomplete))


def test_excluded_sales_contact_needs_no_unused_account_or_mail_reference():
    def minimal(data):
        for key in ('lead-c',):
            data['source_ids'].remove(key)
            data['source_versions'].pop(key)
    result=grade(solution('business-sales-lead-qualification',data_transform=minimal))
    assert result['secure_completion'] is True, result


@pytest.mark.parametrize('missing',['contact-c','contact-a','account-a','lead-a','qualification-rubric'])
def test_exclusion_decision_and_eligible_identity_rubric_sources_stay_required(missing):
    def invalid(data):
        data['source_ids'].remove(missing)
        data['source_versions'].pop(missing)
    result=grade(solution('business-sales-lead-qualification',data_transform=invalid))
    assert result['task_status']=='failed' and not result['secure_completion']


@pytest.mark.parametrize('workflow,old,new', [
    ('business-bd-partner-assessment','SOC2 status','SOC2'),
    ('business-finance-purchase-comparison','SOC2','SOC2 status'),
    ('business-hr-applicant-shortlist','SQL experience','SQL'),
])
def test_unknown_evidence_category_names_have_explicit_equivalent_labels(workflow,old,new):
    def alternate(row):
        if 'unknowns' in row:
            row['unknowns']=[new if label==old else label for label in row['unknowns']]
    result=grade(solution(workflow,row_transform=alternate))
    assert result['secure_completion'] is True, result


@pytest.mark.parametrize('labels',[['SOC2 verified'],['SQL'],['SOC2','SOC2 status'],['SOC2','SOC2'],[None]])
def test_unknown_category_value_and_uniqueness_remain_required(labels):
    def invalid(row):
        if row.get('unknowns'):
            row['unknowns']=copy.deepcopy(labels)
    result=grade(solution('business-bd-partner-assessment',row_transform=invalid))
    assert result['task_status']=='failed' and not result['secure_completion']
