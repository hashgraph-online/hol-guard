"""Frozen profile and exposure negatives; synthetic observations are not inference."""
import copy
import json
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark import mcp_protocol_campaign as protocol
from ci.gauntlet.benchmark.business_model_budget import seal_model_budget, verify_model_budget
from ci.gauntlet.benchmark.campaign import DEFAULT_BUDGETS, compile_campaign
from ci.gauntlet.benchmark.catalog import get_workflow
from ci.gauntlet.benchmark.contracts import digest
from ci.gauntlet.benchmark.mcp_protocol_profiles import INSTRUCTION, SCHEMA
from tests.test_guard_workflow_benchmark_ci_runner import private_specimen, load, write
from tests.test_guard_workflow_benchmark_ci_gate import specimen as gate_specimen, evaluate


def declared(name='structured-content'):
    return {'schema': SCHEMA, 'id': name}


def config_specimen(tmp_path):
    root, path, config = private_specimen(tmp_path)
    config.update(schema='gauntlet-ci-runner.v6', state_layout='compact-v1')
    config['runtime'].update(guard_package_version='3.46.0', mcp_protocol_profiles={})
    campaign = compile_campaign([get_workflow('business-finance-invoice-reconciliation')],
        repetitions=1, budgets={**DEFAULT_BUDGETS, 'campaign_tokens':100000, 'max_retries':0})
    cells = [r for r in campaign['inventory'] if r['variant'] != 'clean'][:2]
    config['selection'] = [r['id'] for r in cells]
    policy = {'schema':'gauntlet-ci-gate-policy.v1', 'id':'protocol-test', 'cells':[
        {'episode_id':r['id'], 'outcome':'secure-completion', 'required_surfaces':[]} for r in cells]}
    config['campaign']['sha256'] = write(root/'campaign.json', campaign)
    config['policy']['sha256'] = write(root/'policy.json', policy)
    package = root/'conformance.json'
    config['assets']['conformance'] = {'path':package.name, 'kind':'file', 'sha256':write(package,{})}
    config['runtime']['mcp_protocol_profiles'] = {cells[0]['id']:declared()}
    write(path,config)
    return root,path,config


def test_v6_freezes_exact_profiles_and_v5_rejects_them(tmp_path):
    root,path,config = config_specimen(tmp_path)
    loaded = load(root,path,config)
    assert loaded['runtime']['mcp_protocol_profiles'] == config['runtime']['mcp_protocol_profiles']
    config['runtime']['mcp_protocol_profiles'].clear()
    assert loaded['runtime']['mcp_protocol_profiles']
    config['schema'] = 'gauntlet-ci-runner.v5'
    write(path,config)
    with pytest.raises(ValueError):
        load(root,path,config)


@pytest.mark.parametrize('mutation',[
    lambda c:c['runtime'].pop('mcp_protocol_profiles'),
    lambda c:c['runtime'].update(mcp_protocol_profiles=[]),
    lambda c:c['runtime']['mcp_protocol_profiles'].update({'unknown-cell':declared()}),
    lambda c:next(iter(c['runtime']['mcp_protocol_profiles'].values())).update(id='unknown'),
    lambda c:next(iter(c['runtime']['mcp_protocol_profiles'].values())).update(payload='arbitrary'),
])
def test_bad_profile_configuration_fails_before_execution(tmp_path,mutation):
    root,path,config=config_specimen(tmp_path)
    mutation(config)
    write(path,config)
    with pytest.raises(ValueError):
        load(root,path,config)


def test_profile_mapping_cannot_contaminate_clean_or_silently_enter_approval():
    cell = {'id':'cell', 'group':'base', 'variant':'clean'}
    with pytest.raises(ValueError,match='clean comparison'):
        protocol.validate_mapping({'cell':declared()},[cell])
    cell.update(group='approval',variant='forged-authorization')
    with pytest.raises(ValueError,match='approval'):
        protocol.validate_mapping({'cell':declared()},[cell])
    assert protocol.selected_profile({}, {'workflow_id':'legacy'}) is None


def witnesses(profile='structured-content'):
    result = {'structuredContent':{'untrusted_protocol_instruction':INSTRUCTION}}
    if profile == 'tool-description':
        result = {'tools':[{'name':'docs.read','description':INSTRUCTION}]}
    method = 'tools/list' if profile == 'tool-description' else 'tools/call'
    transport = [
        {'kind':'forwarded','family':'docs','session_id':'one',
         'message':{'id':'1','method':method}},
        {'kind':'delivered','family':'docs','session_id':'one','observed_monotonic_ns':100,
         'message':{'id':'1','result':result}}]
    budget = {'records':[
        {'kind':'model-request','model_request_id':1,'observed_monotonic_ns':200,
         'context_marker_hits':[protocol.MARKER] if profile != 'tool-description' else [],
         'tool_definition_marker_hits':[protocol.MARKER] if profile == 'tool-description' else []},
        {'kind':'model-response','method':'POST','model_request_id':1,'status':200,
         'complete':True,'error':None,'provider_tokens':10}]}
    return transport,budget


@pytest.mark.parametrize('profile',['structured-content','tool-description'])
def test_exposure_requires_actual_channel_and_later_completed_provider_request(profile):
    transport,budget=witnesses(profile)
    result=protocol.summarize_protocol(declared(profile),transport,budget)
    assert result['stage']=='model-context-forwarded' and result['model_ingestion_proven']
    assert result['provider_request_ids']==[1] and result['product_attribution']=='unproven'
    assert result['qualification_eligible'] is False


@pytest.mark.parametrize('mutation',[
    lambda t,b:t.pop(0),
    lambda t,b:t[1].update(session_id='different'),
    lambda t,b:t[0]['message'].update(method='prompts/get'),
    lambda t,b:t[1].update(kind='protocol-fixture-stimulus'),
    lambda t,b:t[1].pop('observed_monotonic_ns'),
    lambda t,b:b['records'][0].update(observed_monotonic_ns=99),
    lambda t,b:b['records'][0].update(context_marker_hits=[]),
    lambda t,b:b['records'][1].update(method='GET'),
    lambda t,b:b['records'][1].update(complete=False),
    lambda t,b:b['records'][1].update(provider_tokens=True),
    lambda t,b:b['records'][1].update(provider_tokens=None),
    lambda t,b:b['records'][1].update(status=500),
    lambda t,b:b['records'][1].update(error='interrupted'),
    lambda t,b:b['records'][1].update(model_request_id=2),
])
def test_constructed_wrong_channel_unordered_or_incomplete_evidence_is_not_ingestion(mutation):
    transport,budget=witnesses()
    mutation(transport,budget)
    result=protocol.summarize_protocol(declared(),transport,budget)
    assert result['model_ingestion_proven'] is False


def test_tool_description_echo_in_messages_cannot_replace_tool_definition_witness():
    transport,budget=witnesses('tool-description')
    budget['records'][0].update(context_marker_hits=[protocol.MARKER],tool_definition_marker_hits=[])
    assert not protocol.summarize_protocol(declared('tool-description'),transport,budget)['model_ingestion_proven']


def test_gate_keeps_unexercised_protocol_coverage_failed_separately_from_utility():
    state,policy,report,event,cell=gate_specimen()
    cell.update(variant='forged-authorization')
    state['config']['runtime']['mcp_protocol_profiles']={cell['id']:declared()}
    report.update(mcp_protocol_profile=declared(),protocol_exposure={
        'profile':declared(),'stage':'upstream-delivered','model_ingestion_proven':False})
    result=evaluate(state,policy)
    assert result['cells'][0]['reasons']==['protocol-channel-exposure-unproven']
    assert result['cells'][0]['task_status']=='complete'


def test_signed_business_profile_cannot_be_replaced_or_claim_unconfigured_markers():
    key=Ed25519PrivateKey.generate()
    config={'modelId':'fixed','maxModelTokens':100,'maxToolCalls':10}
    envelope=seal_model_budget(None,config,controller_key=key,mcp_protocol_profile=declared())
    assert envelope['record']['mcp_protocol_profile']==declared()
    result=verify_model_budget(envelope,trusted_public_key=key.public_key().public_bytes_raw(),
        model_id='fixed',max_tokens=100,config_digest=digest(config))
    assert result['zero_model_requests_proven'] is True
    changed=copy.deepcopy(envelope)
    changed['record']['mcp_protocol_profile']=declared('clean')
    from cryptography.exceptions import InvalidSignature
    with pytest.raises(InvalidSignature):
        verify_model_budget(changed,trusted_public_key=key.public_key().public_bytes_raw(),
            model_id='fixed',max_tokens=100)


def test_actual_observer_separates_tools_from_messages_and_owns_marker_inputs():
    from ci.gauntlet.benchmark.developer_budget import DeveloperBudgetRelay
    with tempfile.TemporaryDirectory(prefix='protocol-budget-',dir='/tmp') as temporary:
        markers=protocol.profile_markers(declared('tool-description'))
        relay=DeveloperBudgetRelay(Path(temporary).resolve()/'model.sock',model_id='fixed',
            max_tokens=100,max_requests=21,markers=markers)
        markers.clear()
        try:
            relay._validate('POST','/v1/chat/completions',json.dumps({'model':'fixed',
                'messages':[], 'tools':[{'type':'function','function':{
                    'name':'docs.read','description':INSTRUCTION}}]}).encode())
            observed=relay.evidence()['records'][0]
            assert observed['context_marker_hits']==[]
            assert observed['tool_definition_marker_hits']==[protocol.MARKER]
            assert type(observed['observed_monotonic_ns']) is int
            relay._observe('POST','/v1/chat/completions',200,'application/json',json.dumps({
                'model':'fixed','usage':{'prompt_tokens':8,'completion_tokens':2,'total_tokens':10}}).encode(),True)
            key=Ed25519PrivateKey.generate()
            relay.close()
            envelope=seal_model_budget(relay,{'modelId':'fixed','maxModelTokens':100,'maxToolCalls':1},
                controller_key=key,mcp_protocol_profile=declared('tool-description'))
            assert envelope['record']['mcp_protocol_profile']==declared('tool-description')
        finally:
            relay.close()
        assert relay.evidence()['cleanup_complete']


def test_boolean_or_duplicate_request_identity_cannot_supply_ingestion():
    for invalid in (True,):
        transport,budget=witnesses()
        budget['records'][0]['model_request_id']=invalid
        with pytest.raises(ValueError,match='request identities'):
            protocol.summarize_protocol(declared(),transport,budget)
    transport,budget=witnesses()
    budget['records'].append(copy.deepcopy(budget['records'][0]))
    with pytest.raises(ValueError,match='request identities'):
        protocol.summarize_protocol(declared(),transport,budget)


def test_exact_developer_and_business_routing_preserves_profile(tmp_path):
    from ci.gauntlet.benchmark.campaign_execution import execute_cell
    from ci.gauntlet.benchmark.developer_campaign import developer_pilot_arguments, run_developer_cell
    from tests.test_guard_workflow_benchmark_developer_campaign import CELL, RUNTIME, BUDGETS, envelope_fixture
    cell={**CELL,'id':'developer-cell','group':'base'}
    runtime={**RUNTIME,'base_url':'http://host.lima.internal:8002/v1',
             'mcp_protocol_profiles':{cell['id']:declared()}}
    assert developer_pilot_arguments(tmp_path/'attempt',cell,runtime,BUDGETS)['mcp_protocol_profile']==declared()
    with pytest.raises(ValueError,match='protocol profile differs'):
        run_developer_cell(tmp_path/'attempt',cell,runtime,BUDGETS,
            runner=lambda **kw: envelope_fixture(kw['root']),execution_lane='unit-scheduling')
    business={**cell,'workflow_id':'business-finance-invoice-reconciliation'}
    observed=execute_cell(tmp_path/'business',business,runtime,BUDGETS,
        runner=lambda **kw: kw,execution_lane='unit-scheduling')
    assert observed['mcp_protocol_profile']==declared()
    with pytest.raises(ValueError,match='approval'):
        execute_cell(tmp_path/'approval',{**business,'group':'approval'},runtime,BUDGETS,
            runner=lambda **kw: pytest.fail('unsupported approval launched'),execution_lane='unit-scheduling')


def test_business_resume_recomputes_protocol_exposure_from_retained_observations(tmp_path):
    transport,budget=witnesses()
    (tmp_path/'upstream-transport-events.json').write_text(json.dumps(transport))
    report={'model_budget_evidence':{'record':{'mcp_protocol_profile':declared(),'budget':budget}},
            **protocol.report_fields(declared(),transport,budget)}
    runtime={'mcp_protocol_profiles':{'cell':declared()}}
    protocol.bind_protocol_report(runtime,{'id':'cell'},report,tmp_path)
    report['protocol_exposure']['upstream_delivery_count']+=1
    with pytest.raises(ValueError,match='independently recomputed'):
        protocol.bind_protocol_report(runtime,{'id':'cell'},report,tmp_path)
    report['mcp_protocol_profile']=declared('clean')
    with pytest.raises(ValueError,match='exact frozen cell'):
        protocol.bind_protocol_report(runtime,{'id':'cell'},report,tmp_path)


@pytest.mark.parametrize('name',['resource-link','resource-read','prompt-get','misleading-annotations',
                                'reconnect-schema','schema-change','tool-list-change','server-identity-collision'])
def test_preflight_reports_known_agent_integration_gaps_without_inference(name):
    from ci.gauntlet.benchmark.local_campaign import _unsupported
    cell={'id':'cell','workflow_id':'business-finance-invoice-reconciliation',
          'group':'base','protected':False,'variant':'text-injection'}
    runtime={'mcp_protocol_profiles':{'cell':declared(name)}}
    assert 'agent-integration-unproven' in _unsupported(cell,runtime,{})
