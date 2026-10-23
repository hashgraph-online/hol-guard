"""Real SDK tools for agent surfaces; mechanical controls, not agent episodes."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.adapters import omp_mcp_configs
from ci.gauntlet.benchmark.contracts import canonical_json, digest
from ci.gauntlet.benchmark.mcp_protocol_profiles import INSTRUCTION, PROFILES, SCHEMA
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor
from tests.test_guard_workflow_benchmark_supervisor import custody, wait_until


def test_surface_adapter_boundaries_without_provider_or_sdk(tmp_path):
    bun=os.environ.get('HOL_WORKFLOW_BUN')
    if not bun:
        pytest.skip('explicit pinned Bun required for TypeScript boundary controls')
    assert Path(bun).is_absolute()
    helper=Path(__file__).parents[1]/'ci/gauntlet/benchmark/mcp_agent_surfaces_unit_conformance.ts'
    result=subprocess.run([bun,str(helper)],capture_output=True,text=True,timeout=15,
        cwd=tmp_path,env={'PATH':'/usr/bin:/bin','HOME':str(tmp_path)})
    assert result.returncode==0,result.stdout+result.stderr
    report=json.loads(result.stdout)
    assert report['passed'] and report['controls']==15
    assert report['modelExercised'] is report['guardExercised'] is report['qualificationEligible'] is False


def test_initial_catalog_names_and_boundaries_without_inference(tmp_path):
    bun=os.environ.get('HOL_WORKFLOW_BUN')
    if not bun:
        pytest.skip('explicit pinned Bun required for TypeScript discovery controls')
    assert Path(bun).is_absolute()
    helper=Path(__file__).parents[1]/'ci/gauntlet/benchmark/mcp_initial_catalog_conformance.ts'
    result=subprocess.run([bun,str(helper)],capture_output=True,text=True,timeout=15,
        cwd=tmp_path,env={'PATH':'/usr/bin:/bin','HOME':str(tmp_path)})
    assert result.returncode==0,result.stdout+result.stderr
    report=json.loads(result.stdout)
    assert report['passed'] and report['controls']==8 and report['effects']==1
    assert report['modelExercised'] is report['guardExercised'] is report['qualificationEligible'] is False


def test_initial_argument_types_without_answers_or_argument_repair(tmp_path):
    bun=os.environ.get('HOL_WORKFLOW_BUN')
    if not bun:
        pytest.skip('explicit pinned Bun required for TypeScript schema controls')
    helper=Path(__file__).parents[1]/'ci/gauntlet/benchmark/mcp_initial_argument_shapes_conformance.ts'
    result=subprocess.run([bun,str(helper)],capture_output=True,text=True,timeout=15,
        cwd=tmp_path,env={'PATH':'/usr/bin:/bin','HOME':str(tmp_path)})
    assert result.returncode==0,result.stdout+result.stderr
    report=json.loads(result.stdout)
    assert report['passed'] and len(report['controls'])==len(set(report['controls']))==11
    assert report['effects']==1
    assert report['modelExercised'] is report['guardExercised'] is report['qualificationEligible'] is False


@pytest.mark.parametrize('profile', ['clean','resource-link','resource-read','prompt-get','misleading-annotations'])
def test_actual_agent_session_over_scripted_stream(custody, profile):
    bun,sdk=os.environ.get('HOL_WORKFLOW_BUN'),os.environ.get('HOL_WORKFLOW_SDK_ROOT')
    if not bun or not sdk:
        pytest.skip('explicit pinned Bun and SDK required for actual session control')
    world,directory=custody
    before=world.snapshot()
    with ServiceSupervisor(world,directory,families=('docs','mail'),
            protocol_profile={'schema':SCHEMA,'id':profile}) as supervisor:
        config=directory.parent/'session-control.json'
        config.write_text(canonical_json({'schema':'mcp-agent-session-control.v1',
            'sdkRoot':sdk,'workspace':str(directory.parent),'endpoints':omp_mcp_configs(
                tuple(supervisor.endpoint(f) for f in ('docs','mail')),workspace=directory.parent)}))
        helper=Path(__file__).parents[1]/'ci/gauntlet/benchmark/mcp_agent_session_conformance.ts'
        execution=subprocess.run([bun,str(helper),str(config)],capture_output=True,text=True,
            timeout=55,cwd=directory.parent,env={'PATH':'/usr/bin:/bin','HOME':str(directory.parent)})
        assert execution.returncode==0,execution.stdout+execution.stderr
        report=json.loads(execution.stdout)
        assert report['actualSdkSession'] is report['scripted'] is True
        assert report['streamCalls']==8 and len(report['results'])==7 and len(report['toolNames'])==5
        assert report['modelExercised'] is report['guardExercised'] is report['qualificationEligible'] is False
        assert report['providerRequests']==0
        context=canonical_json(report['finalProviderToolContext'])
        assert (INSTRUCTION in context) is (profile!='clean')
        assert not any(result.get('isError') for result in report['results'])
        wait_until(lambda:supervisor.active_sessions==supervisor.active_workers==0)
        assert world.snapshot()==before
    assert not directory.exists()
    if target:=os.environ.get('HOL_WORKFLOW_PROTOCOL_EVIDENCE_DIR'):
        root=Path(target)
        assert root.is_absolute() and root.is_dir() and not root.is_symlink()
        with (root/('session-'+profile+'.json')).open('x') as stream:
            stream.write(canonical_json({'schema':'mcp-agent-session-observation.v1',
                'profile':{'schema':SCHEMA,'id':profile},'sdk':report,
                'transport_events':supervisor.events,'state_unchanged':world.snapshot()==before,
                'active_sessions':supervisor.active_sessions,'active_workers':supervisor.active_workers,
                'socket_directory_removed':not directory.exists(),
                'model_ingestion_proven':False,'qualification_eligible':False})+'\n')


def test_surface_adapter_preserves_unsafe_effect_reachability(custody):
    bun,sdk=os.environ.get('HOL_WORKFLOW_BUN'),os.environ.get('HOL_WORKFLOW_SDK_ROOT')
    if not bun or not sdk:
        pytest.skip('explicit pinned Bun and SDK required for actual effect control')
    world,directory=custody
    with ServiceSupervisor(world,directory,families=('docs','mail'),
            protocol_profile={'schema':SCHEMA,'id':'misleading-annotations'}) as supervisor:
        config=directory.parent/'effect-control.json'
        config.write_text(canonical_json({'schema':'mcp-agent-surfaces-effect-control.v1',
            'sdkRoot':sdk,'workspace':str(directory.parent),'endpoints':omp_mcp_configs(
                tuple(supervisor.endpoint(f) for f in ('docs','mail')),workspace=directory.parent)}))
        helper=Path(__file__).parents[1]/'ci/gauntlet/benchmark/mcp_agent_surfaces_conformance.ts'
        execution=subprocess.run([bun,str(helper),str(config)],capture_output=True,text=True,
            timeout=40,cwd=directory.parent,env={'PATH':'/usr/bin:/bin','HOME':str(directory.parent)})
        assert execution.returncode==0,execution.stdout+execution.stderr
        report=json.loads(execution.stdout)
        assert report['actualSdkSession'] is report['modelExercised'] is report['guardExercised'] is False
        assert report['providerRequests']==0 and report['qualificationEligible'] is False
        assert not any(r.get('isError') for r in report['observations'].values())
        wait_until(lambda:supervisor.active_sessions==supervisor.active_workers==0)
    assert not directory.exists()
    assert not any(r['id']=='qualification-rubric' for r in world.snapshot()['records'])
    receipts=world.receipts()
    assert [r['event']['operation'] for r in receipts]==['docs.read','docs.delete']
    assert receipts[0]['event']['raw_args_digest']==digest({'record_id':'peer-confidential'})
    if target:=os.environ.get('HOL_WORKFLOW_PROTOCOL_EVIDENCE_DIR'):
        root=Path(target)
        assert root.is_absolute() and root.is_dir() and not root.is_symlink()
        with (root/'effect-reachability.json').open('x') as stream:
            stream.write(canonical_json({'schema':'mcp-agent-effect-observation.v1','sdk':report,
                'receipts':receipts,'world_public_key':world.public_key(),
                'transport_events':supervisor.events,'active_sessions':supervisor.active_sessions,
                'active_workers':supervisor.active_workers,'socket_directory_removed':not directory.exists(),
                'qualification_eligible':False,'scope':'Mechanical baseline attack reachability, not model or Guard efficacy.'})+'\n')


@pytest.mark.parametrize('profile', sorted(PROFILES))
def test_actual_sdk_agent_surface_tools(custody, profile):
    bun, sdk = os.environ.get('HOL_WORKFLOW_BUN'), os.environ.get('HOL_WORKFLOW_SDK_ROOT')
    if not bun or not sdk:
        pytest.skip('explicit pinned Linux Bun and SDK required for actual surface controls')
    assert Path(bun).is_absolute() and Path(sdk).is_absolute()
    world,directory = custody
    before = world.snapshot()
    with ServiceSupervisor(world,directory,families=('docs','mail'),
            protocol_profile={'schema':SCHEMA,'id':profile}) as supervisor:
        config=directory.parent/'agent-surface-control.json'
        config.write_text(canonical_json({'schema':'mcp-agent-surfaces-control.v1',
            'sdkRoot':sdk,'workspace':str(directory.parent),
            'endpoints':omp_mcp_configs(tuple(supervisor.endpoint(f) for f in ('docs','mail')),
                                        workspace=directory.parent)}))
        helper=Path(__file__).parents[1]/'ci/gauntlet/benchmark/mcp_agent_surfaces_conformance.ts'
        execution=subprocess.run([bun,str(helper),str(config)],capture_output=True,text=True,
            timeout=40,cwd=directory.parent,env={'PATH':'/usr/bin:/bin','HOME':str(directory.parent)})
        assert execution.returncode==0, execution.stdout+execution.stderr
        report=json.loads(execution.stdout)
        assert report['profile']=='mcp-agent-surfaces.v1'
        assert report['modelExercised'] is report['guardExercised'] is report['qualificationEligible'] is False
        assert report['providerRequests']==0 and len(report['toolNames'])==5
        observed=report['observations']
        text=lambda key: ''.join(c.get('text','') for c in observed[key]['content'])
        if profile in {'structured-content','resource-link','error-content'}:
            assert INSTRUCTION in text('read')
        if profile=='resource-link':
            assert 'peer-confidential' in text('linkedResource')
        if profile in {'tool-description','misleading-annotations'}:
            assert INSTRUCTION in text('originalCatalog')
        if profile in {'schema-change','tool-list-change','reconnect-schema'}:
            assert INSTRUCTION not in text('originalCatalog')
            assert INSTRUCTION in text('reconnectedCatalog' if profile=='reconnect-schema' else 'changedCatalog')
        assert (INSTRUCTION in text('resource')) is (profile=='resource-read')
        assert (INSTRUCTION in text('prompt')) is (profile=='prompt-get')
        if profile=='server-identity-collision':
            left,right=json.loads(text('docsIdentity')),json.loads(text('mailIdentity'))
            assert left['configuredServer']=='docs' and right['configuredServer']=='mail'
            assert left['serverInfo']['name']==right['serverInfo']['name']=='benchmark-collision'
        if profile=='error-content':
            assert observed['read']['isError'] and not observed['recovered'].get('isError',False)
        wait_until(lambda:supervisor.active_sessions==supervisor.active_workers==0)
        assert world.snapshot()==before
    assert not directory.exists()
    target=os.environ.get('HOL_WORKFLOW_PROTOCOL_EVIDENCE_DIR')
    if target:
        root=Path(target)
        assert root.is_absolute() and root.is_dir() and not root.is_symlink()
        with (root/(profile+'.json')).open('x') as stream:
            stream.write(canonical_json({'schema':'mcp-agent-surfaces-observation.v1',
                'profile':{'schema':SCHEMA,'id':profile},'sdk':report,
                'transport_events':supervisor.events,'initial_state_digest':digest(before),
                'final_state_digest':digest(world.snapshot()),'active_sessions':supervisor.active_sessions,
                'active_workers':supervisor.active_workers,'socket_directory_removed':not directory.exists(),
                'model_ingestion_proven':False,'qualification_eligible':False})+'\n')
