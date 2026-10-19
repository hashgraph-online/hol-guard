"""Frozen harness selection and independent observer contracts; no model credit."""
import json
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark import mcp_agent_profile as profile
from ci.gauntlet.benchmark.business_agent_container import mapped_config
from ci.gauntlet.benchmark.business_model_budget import seal_model_budget, verify_model_budget
from ci.gauntlet.benchmark.contracts import canonical_json, digest
from ci.gauntlet.benchmark.developer_agent_launcher import stage_public_episode
from ci.gauntlet.benchmark.developer_budget import DeveloperBudgetRelay
from ci.gauntlet.benchmark.mcp_protocol_campaign import summarize_protocol, support_reason
from tests.test_guard_workflow_benchmark_business_agent_container import public_config
from tests.test_guard_workflow_benchmark_protocol_campaign import config_specimen, declared, witnesses
from tests.test_guard_workflow_benchmark_ci_runner import load, write


def test_v7_freezes_common_profile_and_v6_rejects_it(tmp_path):
    root,path,config=config_specimen(tmp_path)
    config['schema']='gauntlet-ci-runner.v7'
    config['runtime']['mcp_agent_surfaces']=profile.PROFILE
    write(path,config)
    loaded=load(root,path,config)
    assert loaded['runtime']['mcp_agent_surfaces']==profile.PROFILE
    config['schema']='gauntlet-ci-runner.v6'
    write(path,config)
    with pytest.raises(ValueError):
        load(root,path,config)


@pytest.mark.parametrize('value',[True,{},'unknown','mcp-agent-surfaces.v2',0])
def test_unknown_profile_cannot_select_a_harness(value):
    with pytest.raises(ValueError):
        profile.validate(value)


def test_episode_version_and_literal_profile_must_agree():
    for key in profile.EPISODES:
        value=profile.apply_episode({'schema':key},profile.PROFILE)
        assert profile.config_profile(value)==profile.PROFILE
        value.pop('mcpAgentSurfaces')
        with pytest.raises(ValueError):
            profile.config_profile(value)
        with pytest.raises(ValueError):
            profile.config_profile({'schema':key,'mcpAgentSurfaces':profile.PROFILE})


def test_v2_business_mapping_keeps_profile_and_discards_host_launch_fields():
    config=profile.apply_episode(public_config(),profile.PROFILE)
    config['endpoints']['docs']={'command':'/secret/private/python','env':{'PRIVATE':'not-public'}}
    mapped=mapped_config(config)
    assert mapped['schema']=='gauntlet-omp-episode.v2' and mapped['mcpAgentSurfaces']==profile.PROFILE
    assert '/secret' not in canonical_json(mapped) and 'not-public' not in canonical_json(mapped)


def test_developer_stages_profile_dependency_only_for_v2(tmp_path):
    legacy=tmp_path/'legacy'; legacy.mkdir()
    modern=tmp_path/'modern'; modern.mkdir()
    stage_public_episode(legacy,{'schema':'developer-omp-episode.v1'},copy_helpers=True)
    assert not (legacy/'mcp_agent_surfaces.ts').exists()
    config=profile.apply_episode({'schema':'developer-omp-episode.v1'},profile.PROFILE)
    stage_public_episode(modern,config,copy_helpers=True)
    assert (modern/'mcp_agent_surfaces.ts').is_file()
    assert (modern/'mcp_agent_surfaces.ts').stat().st_mode & 0o022==0


def test_identity_observer_reads_tool_data_without_role_escalation_or_ambiguous_json():
    value={'configuredServer':'docs','serverInfo':{'name':'benchmark-collision'}}
    assert profile.identity_hits([{'role':'tool','content':json.dumps(value)}])==['docs']
    assert profile.identity_hits([{'role':'user','content':json.dumps(value)}])==[]
    assert profile.identity_hits([{'role':'tool','content':'{"configuredServer":"docs","configuredServer":"mail","serverInfo":{"name":"benchmark-collision"}}'}])==[]
    assert profile.identity_hits([{'role':'tool','content':{'configuredServer':[], 'serverInfo':{}}}])==[]


def test_observer_binds_harness_and_separates_identity_evidence_from_claimed_authority():
    with tempfile.TemporaryDirectory(prefix='agent-profile-',dir='/tmp') as directory:
        relay=DeveloperBudgetRelay(Path(directory).resolve()/'model.sock',model_id='fixed',
            max_tokens=100,max_requests=30,mcp_agent_surfaces=profile.PROFILE)
        try:
            body={'model':'fixed','messages':[{'role':'tool','content':json.dumps({
                'configuredServer':'docs','serverInfo':{'name':'benchmark-collision'}})}],
                'tools':[{'type':'function','function':{'name':'mcp_read_resource'}}]}
            relay._validate('POST','/v1/chat/completions',json.dumps(body).encode())
            relay._observe('POST','/v1/chat/completions',200,'application/json',json.dumps({
                'model':'fixed','usage':{'prompt_tokens':8,'completion_tokens':2,'total_tokens':10}}).encode(),True)
            relay.close()
            observed=relay.evidence()
            assert observed['mcp_agent_surfaces']==profile.PROFILE
            assert observed['records'][0]['mcp_server_identity_hits']==['docs']
            assert observed['records'][0]['tool_names']==['mcp_read_resource']
            key=Ed25519PrivateKey.generate()
            config=profile.apply_episode({'schema':'gauntlet-omp-episode.v1','modelId':'fixed',
                'maxModelTokens':100,'maxToolCalls':10},profile.PROFILE)
            sealed=seal_model_budget(relay,config,controller_key=key)
            assert sealed['record']['mcp_agent_surfaces']==profile.PROFILE
            assert 'mcp_agent_profile.py' in sealed['record']['sources']
            assert verify_model_budget(sealed,trusted_public_key=key.public_key().public_bytes_raw(),
                model_id='fixed',max_tokens=100)['observed_model_tokens']==10
        finally:
            relay.close()


def test_v7_metadata_context_does_not_upgrade_v6_tool_definition_witness():
    transport,budget=witnesses('tool-description')
    budget['records'][0].update(context_marker_hits=['mcp-protocol-instruction.v1'],tool_definition_marker_hits=[])
    assert not summarize_protocol(declared('tool-description'),transport,budget)['model_ingestion_proven']
    modern=summarize_protocol(declared('tool-description'),transport,budget,agent_surfaces=profile.PROFILE)
    assert modern['model_ingestion_proven'] and modern['schema']=='gauntlet-mcp-protocol-exposure.v2'


def test_identity_collision_requires_two_actual_configured_servers_before_completed_request():
    transport=[]
    for index,family in enumerate(('docs','mail')):
        transport.extend([{'kind':'forwarded','family':family,'session_id':family,
            'message':{'id':str(index),'method':'initialize'}},
            {'kind':'delivered','family':family,'session_id':family,'observed_monotonic_ns':100+index,
             'message':{'id':str(index),'result':{'serverInfo':{'name':'benchmark-collision'}}}}])
    _,budget=witnesses()
    budget['records'][0]['mcp_server_identity_hits']=['docs','mail']
    args={'agent_surfaces':profile.PROFILE}
    assert summarize_protocol(declared('server-identity-collision'),transport,budget,**args)['model_ingestion_proven']
    budget['records'][0]['mcp_server_identity_hits']=['docs','docs']
    assert not summarize_protocol(declared('server-identity-collision'),transport,budget,**args)['model_ingestion_proven']
    budget['records'][0]['mcp_server_identity_hits']=['docs','mail']
    transport[-1]['observed_monotonic_ns']=999
    assert not summarize_protocol(declared('server-identity-collision'),transport,budget,**args)['model_ingestion_proven']


def test_report_binding_cannot_hide_harness_substitution():
    runtime={'mcp_agent_surfaces':profile.PROFILE}
    with pytest.raises(ValueError,match='harness profile'):
        profile.bind_report(runtime,{})
    with pytest.raises(ValueError,match='provider observer'):
        profile.bind_report(runtime,{'mcp_agent_surfaces':profile.PROFILE})


def test_all_surface_profiles_remain_explicitly_unsupported_without_declared_harness():
    cell={'id':'cell'}
    runtime={'mcp_protocol_profiles':{'cell':declared('prompt-get')}}
    assert support_reason(runtime,cell)
    assert support_reason({**runtime,'mcp_agent_surfaces':profile.PROFILE},cell) is None


@pytest.mark.parametrize('protected',[False,True])
def test_business_and_developer_handoffs_keep_the_same_harness(protected,tmp_path):
    from ci.gauntlet.benchmark.campaign_execution import execute_cell
    from ci.gauntlet.benchmark.developer_campaign import developer_pilot_arguments
    runtime={'bun':'/public/bun','sdk_root':'/public/node_modules/@oh-my-pi/pi-coding-agent',
        'base_url':'http://host.lima.internal:8002/v1','model_id':'fixed','protected_adapter':'hol-guard',
        'isolated':True,'product_isolated':True,'guard_python':'/public/guard/bin/python',
        'guard_source_sha':'1'*40,'guard_prefix_digest':'2'*64,'guard_bwrap_sha256':'3'*64,
        'guard_executor_image_id':'sha256:'+'4'*64,'mcp_agent_surfaces':profile.PROFILE}
    cell={'id':'cell','group':'base','workflow_id':'business-finance-invoice-reconciliation',
          'variant':'clean','protected':protected}
    budgets={'episode_seconds':900,'tool_operations':200,'model_tokens':100000}
    args=execute_cell(tmp_path/'business',cell,runtime,budgets,runner=lambda **kw:kw,
                      execution_lane='unit-scheduling')
    assert args['mcp_agent_surfaces']==profile.PROFILE
    assert args['adapter_id']==('hol-guard' if protected else 'unprotected')
    developer={**cell,'workflow_id':'python-cli-with-tests'}
    assert developer_pilot_arguments(tmp_path/'developer',developer,runtime,budgets)[
        'mcp_agent_surfaces']==profile.PROFILE


def test_approval_handoff_keeps_the_profile_without_adding_protocol_attack_mediation(tmp_path):
    from ci.gauntlet.benchmark.approval_campaign import run_approval_cell
    from tests.test_guard_workflow_benchmark_approval_campaign import CELL,RUNTIME,BUDGETS
    def capture(**kwargs):
        assert kwargs['mcp_agent_surfaces']==profile.PROFILE
        assert 'mcp_protocol_profile' not in kwargs
        raise RuntimeError('unit-only handoff captured')
    with pytest.raises(RuntimeError,match='handoff captured'):
        run_approval_cell(tmp_path/'approval',CELL,{**RUNTIME,'mcp_agent_surfaces':profile.PROFILE},
            BUDGETS,runner=capture,execution_lane='unit-scheduling')


def test_signed_observer_refuses_a_silent_profile_drop():
    with tempfile.TemporaryDirectory(prefix='agent-drop-',dir='/tmp') as directory:
        relay=DeveloperBudgetRelay(Path(directory).resolve()/'model.sock',model_id='fixed',
            max_tokens=100,max_requests=30)
        try:
            cfg=profile.apply_episode({'schema':'gauntlet-omp-episode.v1','modelId':'fixed',
                'maxModelTokens':100,'maxToolCalls':10},profile.PROFILE)
            with pytest.raises(ValueError,match='selected harness binding'):
                seal_model_budget(relay,cfg,controller_key=Ed25519PrivateKey.generate())
        finally:
            relay.close()


@pytest.mark.parametrize('developer',[False,True])
def test_provider_inventory_requires_exact_tools_and_completed_observation(developer):
    names=sorted(profile.TOOLS | ({'read','write','edit','bash'} if developer else set()))
    budget={'records':[{'kind':'model-request','model_request_id':1,'tool_names':names},
        {'kind':'model-response','method':'POST','model_request_id':1,'complete':True,
         'status':200,'error':None,'provider_tokens':2}]}
    profile.verify_inventory(budget,developer=developer)
    budget['records'][0]['tool_names']=names+['undeclared-tool']
    with pytest.raises(ValueError,match='differs'):
        profile.verify_inventory(budget,developer=developer)
    budget['records'][0]['tool_names']=names
    budget['records'][1]['complete']=False
    with pytest.raises(ValueError,match='completed provider'):
        profile.verify_inventory(budget,developer=developer)
