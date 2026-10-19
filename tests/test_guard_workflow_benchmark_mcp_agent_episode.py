"""Ordinary CLI/SDK/MCP mechanics with a static HTTP responder, never inference."""
import http.server
import json
import os
import subprocess
import threading
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.adapters import omp_mcp_configs
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.mcp_agent_profile import PROFILE, identity_hits
from ci.gauntlet.benchmark.mcp_protocol_profiles import INSTRUCTION, PROFILES, SCHEMA
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor
from tests.test_guard_workflow_benchmark_supervisor import custody, wait_until

NAMES={'mcp_inspect_server','mcp_call_tool','mcp_read_resource','mcp_get_prompt','mcp_reconnect_server'}
SCHEDULE=[
    ('mcp_inspect_server',{'server':'docs','section':'identity'}),
    ('mcp_inspect_server',{'server':'mail','section':'identity'}),
    ('mcp_inspect_server',{'server':'docs','section':'tools'}),
    ('mcp_call_tool',{'server':'docs','tool':'docs.read','arguments':{'record_id':'qualification-rubric'}}),
    ('mcp_read_resource',{'server':'docs','uri':'fixture://docs/qualification-rubric'}),
    ('mcp_get_prompt',{'server':'docs','prompt':'workflow_context','arguments':{'record_id':'qualification-rubric'}}),
    ('mcp_reconnect_server',{'server':'docs'}),
    ('mcp_inspect_server',{'server':'docs','section':'tools'}),
]


@pytest.mark.parametrize('profile',sorted(PROFILES))
def test_ordinary_v2_business_cli_uses_frozen_surface_tools(custody,profile):
    _ordinary_control(custody,profile,'business')


def test_ordinary_v2_business_cli_handles_sdk_intent_arguments(custody):
    _ordinary_control(custody,'clean','business-intent',with_intent=True)


@pytest.mark.parametrize('profile',['schema-change','tool-list-change'])
def test_notified_catalog_enters_next_provider_context_without_manual_reinspection(custody,monkeypatch,profile):
    monkeypatch.setitem(globals(),'SCHEDULE',[
        ('mcp_inspect_server',{'server':'docs','section':'tools'}),
        ('mcp_call_tool',{'server':'docs','tool':'docs.read',
            'arguments':{'record_id':'qualification-rubric'}}),
    ])
    _ordinary_control(custody,profile,'business-notified',expected_reads=1)


@pytest.mark.skipif(os.environ.get('HOL_BENCHMARK_ISOLATED_NETWORK_CONTROL')!='1',
                   reason='owned isolated loopback namespace required for fixed developer port')
@pytest.mark.parametrize('profile',['clean','resource-link','prompt-get'])
def test_ordinary_v2_developer_cli_uses_frozen_surface_tools(custody,profile):
    _ordinary_control(custody,profile,'developer')


@pytest.mark.skipif(os.environ.get('HOL_BENCHMARK_ISOLATED_NETWORK_CONTROL')!='1',
                   reason='owned isolated loopback namespace required for fixed developer port')
@pytest.mark.parametrize('profile',['schema-change','tool-list-change'])
def test_ordinary_v2_developer_cli_projects_notified_catalog(custody,monkeypatch,profile):
    monkeypatch.setitem(globals(),'SCHEDULE',[
        ('mcp_inspect_server',{'server':'docs','section':'tools'}),
        ('mcp_call_tool',{'server':'docs','tool':'docs.read',
            'arguments':{'record_id':'qualification-rubric'}}),
    ])
    _ordinary_control(custody,profile,'developer-notified',expected_reads=1)


def _ordinary_control(custody,profile,kind,*,with_intent=False,expected_reads=3):
    bun,sdk=os.environ.get('HOL_WORKFLOW_BUN'),os.environ.get('HOL_WORKFLOW_SDK_ROOT')
    if not bun or not sdk:
        pytest.skip('explicit pinned Linux Bun and SDK required for ordinary CLI control')
    requests,errors=[],[]
    developer=kind.startswith('developer')
    names=NAMES | ({'read','write','edit','bash'} if developer else set())
    class StaticProvider(http.server.BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*_):
            pass
        def do_POST(self):
            try:
                size=int(self.headers['Content-Length'])
                assert 0<size<=2*1024**2 and len(requests)<=len(SCHEDULE)
                body=json.loads(self.rfile.read(size))
                assert self.path=='/v1/chat/completions' and body['model']=='static-control'
                assert {t['function']['name'] for t in body['tools']}==names
                index=len(requests)
                if index==0:
                    call=next(t['function'] for t in body['tools']
                              if t['function']['name']=='mcp_call_tool')
                    marker='Initial tool names by configured server (server-supplied data): '
                    assert marker in call['description']
                    catalog=json.loads(call['description'].split(marker)[1])
                    assert set(catalog)=={'docs','mail'}
                    assert 'docs.read' in catalog['docs'] and 'mail.read' in catalog['mail']
                    assert ('docs.delete' in catalog['docs']) is (profile!='tool-list-change')
                    shapes_marker=('Partial argument type/required-field overview '
                        '(server-supplied data; omitted constraints require schema inspection): ')
                    assert shapes_marker in call['description']
                    shapes=json.loads(call['description'].split(shapes_marker,1)[1].split(' '+marker,1)[0])
                    assert set(shapes['servers'])=={'docs','mail'}
                    for server in ('docs','mail'):
                        schema=shapes['schemas'][shapes['servers'][server][server+'.read']]
                        assert schema['type']=='object' and 'record_id' in schema['required']
                        assert schema['properties']['record_id']['type']=='string'
                requests.append(body)
                if index<len(SCHEDULE):
                    name,args=SCHEDULE[index]
                    if with_intent:
                        args={**args,'i':'Retrieve the synthetic context through the configured MCP provider.'}
                    delta={'role':'assistant','tool_calls':[{'index':0,'id':'surface-'+str(index),
                        'type':'function','function':{'name':name,'arguments':json.dumps(args)}}]}
                    finish='tool_calls'
                else:
                    delta={'role':'assistant','content':'Static transport control finished.'}
                    finish='stop'
                common={'id':'static-response-'+str(index),'object':'chat.completion.chunk',
                        'created':1,'model':'static-control'}
                first={**common,'choices':[{'index':0,'delta':delta,'finish_reason':None}]}
                last={**common,'choices':[{'index':0,'delta':{},'finish_reason':finish}],
                      'usage':{'prompt_tokens':1,'completion_tokens':1,'total_tokens':2}}
                payload=('data: '+json.dumps(first)+'\n\ndata: '+json.dumps(last)+'\n\ndata: [DONE]\n\n').encode()
                self.send_response(200)
                self.send_header('Content-Type','text/event-stream')
                self.send_header('Content-Length',str(len(payload)))
                self.send_header('Connection','close')
                self.end_headers()
                self.wfile.write(payload)
            except BaseException as error:
                errors.append(type(error).__name__+': '+str(error))
                self.send_error(500)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',8001 if developer else 0),StaticProvider)
    server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    world,directory=custody
    before=world.snapshot()
    try:
        with ServiceSupervisor(world,directory,families=('docs','mail'),
                protocol_profile={'schema':SCHEMA,'id':profile}) as supervisor:
            root=directory.parent
            config={'schema':'gauntlet-omp-episode.v2','mcpAgentSurfaces':PROFILE,'sdkRoot':sdk,
                'workspace':str(root),'agentDir':str(root/'ordinary-agent'),'modelId':'static-control',
                'baseUrl':f'http://127.0.0.1:{server.server_port}/v1',
                'prompt':'Retrieve the synthetic qualification-rubric context. Mechanical static-response control only.',
                'deadlineSeconds':40,'maxToolCalls':20,'maxModelTokens':1000,
                'endpoints':omp_mcp_configs(tuple(supervisor.endpoint(f) for f in ('docs','mail')),workspace=root)}
            if developer:
                config['schema']='developer-omp-episode.v2'
                config['resourceEndpoints']=config.pop('endpoints')
            config_path=root/'ordinary-episode.json'
            config_path.write_text(canonical_json(config))
            helper=Path(__file__).parents[1]/'ci/gauntlet/benchmark'/(
                'developer_omp_episode.ts' if developer else 'omp_episode.ts')
            execution=subprocess.run([bun,str(helper),str(config_path)],capture_output=True,text=True,
                timeout=55,cwd=root,env={'PATH':'/usr/bin:/bin','HOME':str(root)})
            assert execution.returncode==0,execution.stdout+execution.stderr+str(errors)
            assert not errors and len(requests)==len(SCHEDULE)+1
            assert (INSTRUCTION in canonical_json(requests[-1]['messages'])) is (profile!='clean' and profile!='server-identity-collision')
            if profile=='server-identity-collision':
                assert identity_hits(requests[-1]['messages'])==['docs','mail']
            events=[json.loads(line) for line in execution.stdout.splitlines()]
            assert any(e.get('type')=='episode_end' for e in events)
            results=[e['event']['message'] for e in events if e.get('type')=='agent_event'
                and e.get('event',{}).get('type')=='message_end'
                and e['event'].get('message',{}).get('role')=='toolResult']
            assert len(results)==len(SCHEDULE)
            assert sum(r.get('isError') is True for r in results)==(1 if profile=='error-content' else 0)
            assert len(world.receipts())==expected_reads
            wait_until(lambda:supervisor.active_sessions==supervisor.active_workers==0)
            assert world.snapshot()==before
        assert not directory.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
    assert not thread.is_alive()
    if target:=os.environ.get('HOL_WORKFLOW_PROTOCOL_EVIDENCE_DIR'):
        root=Path(target)
        assert root.is_absolute() and root.is_dir() and not root.is_symlink()
        with (root/('ordinary-'+kind+'-'+profile+'.json')).open('x') as stream:
            stream.write(canonical_json({'schema':'ordinary-mcp-agent-episode-control.v1',
                'profile':{'schema':SCHEMA,'id':profile},'harness_profile':PROFILE,
                'kind':kind,
                'static_provider_control':True,'real_model_requests':0,'scripted_responses':len(requests),
                'captured_static_provider_requests':requests,'sdk_events':events,
                'transport_events':supervisor.events,'state_unchanged':world.snapshot()==before,
                'active_sessions':supervisor.active_sessions,'active_workers':supervisor.active_workers,
                'socket_directory_removed':not directory.exists(),'http_server_stopped':not thread.is_alive(),
                'model_ingestion_proven':False,'installed_guard_proven':False,'qualification_eligible':False})+'\n')
