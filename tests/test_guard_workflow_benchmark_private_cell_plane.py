"""Routing/custody contracts only; fake transports establish no product efficacy."""
import hashlib
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import builtin_hook_supervisor as supervisor
from ci.gauntlet.benchmark import private_cell_hook_plane as module
from ci.gauntlet.benchmark.contracts import canonical_json, digest
from ci.gauntlet.benchmark.product_cell_supervisor import ProductCell


def plane():
    value=module.PrivateCellHookPlane.__new__(module.PrivateCellHookPlane)
    value.started,value.closed,value.cleanup_complete=True,False,False
    value.python=Path('/runtime/guard/bin/python')
    value.workspace_path='/runtime/home/project'
    value.hook_observations,value.executions,value.cleanup_errors=[],[],[]
    value.observations=[]
    value.observation_bytes=0
    value._lock=threading.RLock()
    value.cell=SimpleNamespace(stage=Path('/owned'),closed=False)
    return value


def test_normal_negative_hook_keeps_exact_request_response_and_status():
    value=plane()
    payload={'config_path':value.config_path,'hook_event_name':'PreToolUse',
             'tool_name':'bash','tool_input':{'command':'opaque $(untrusted)'}}
    response={'decision':'deny','reason_code':'fixture-native-refusal'}
    calls=[]
    def capture(argv,raw,**kwargs):
        calls.append((argv,raw))
        return subprocess.CompletedProcess(argv,1,canonical_json(response).encode(),b'diagnostic'),[]
    value._capture=capture
    assert value.invoke_hook(payload)==response
    assert calls[0][1]==(canonical_json(payload)+'\n').encode()
    assert 'opaque $(untrusted)' not in calls[0][0]
    observed=value.hook_observations[0]
    assert observed['payload_digest']==digest(payload) and observed['returncode']==1
    assert observed['response_digest']==digest(response)
    assert value.observations[0]['stderr']=='diagnostic'
    assert value.observations[0]['tool_input']==payload['tool_input']


def test_daemon_early_exit_retains_actual_channels_without_another_status_poll():
    import base64
    value=plane()
    value.observations=[]
    value.cell._call=lambda *args: {'stdout':'','stderr':base64.b64encode(b'actual startup failure').decode(),
                                   'returncode':1}
    with pytest.raises(RuntimeError,match='exited before readiness'):
        value._poll_daemon('owned-daemon',100)
    assert value.observations==[{'kind':'daemon-channel','returncode':1,
                                'stdout':'','stderr':'actual startup failure'}]


def test_cold_status_query_uses_remaining_setup_budget_and_never_outlives_it(monkeypatch):
    value=plane()
    value.home_path='/runtime/home'
    monkeypatch.setattr(module.time,'monotonic',lambda:100.0)
    calls=[]
    def capture(argv,**options):
        calls.append(options['timeout'])
        return subprocess.CompletedProcess(argv,0,b'{"running":true}',b'')
    value.cell.capture=capture
    value._daemon_status(160.0)
    value._daemon_status(120.8)
    assert calls==[30,20]
    with pytest.raises(TimeoutError,match='readiness deadline'):
        value._daemon_status(100.8)
    assert calls==[30,20]


@pytest.mark.parametrize('payload',[None,{}, {'config_path':'/other','hook_event_name':'PreToolUse'},
                                    {'config_path':module.PrivateCellHookPlane.config_path,'hook_event_name':'unknown'}])
def test_bad_hook_scope_has_no_product_effect(payload):
    value=plane()
    value._capture=lambda *args,**kwargs:pytest.fail('invalid scope reached product')
    with pytest.raises(ValueError,match='context'):
        value.invoke_hook(payload)


def test_contained_snapshot_uses_descriptor_helper_and_preserves_cancel_callback(monkeypatch):
    value=plane()
    payload={'hook_event_name':'PreToolUse','tool_name':'bash','tool_input':{'command':'python3 -m unittest'}}
    snapshots=[]
    @contextmanager
    def request(directory,raw,**kwargs):
        snapshots.append(raw)
        assert directory==Path('/owned/state/home')
        yield 'owned-request'
    monkeypatch.setattr(module,'contained_request_file',request)
    def cancelled():
        return False
    def capture(argv,raw,**kwargs):
        assert kwargs=={'timeout':330,'cancelled':cancelled} and raw==b''
        assert argv[argv.index('--request-file')+1]=='/product/home/owned-request/request.json'
        assert argv[argv.index('--request-sha256')+1]==hashlib.sha256(snapshots[0]).hexdigest()
        return subprocess.CompletedProcess(argv,0,b'exact output',b''),[]
    value._capture=capture
    result=value.execute_contained(payload,cancelled=cancelled)
    assert result['stdout']=='exact output' and result['payload_digest']==digest(payload)
    assert result['containment_conformance_established'] is False


@pytest.mark.parametrize('where',['cell','image',None])
def test_cleanup_never_releases_image_while_cell_may_survive(where):
    value=plane()
    effects=[]
    def cell_close():
        effects.append('cell')
        if where=='cell':
            raise RuntimeError('cell survived')
        value.cell.closed=True
    def image_close():
        effects.append('image')
        if where=='image':
            raise RuntimeError('image survived')
        value.image_lease.owned=False
    value.cell.close=cell_close
    value.image_lease=SimpleNamespace(owned=True,close=image_close)
    if where:
        with pytest.raises(RuntimeError,match='cleanup incomplete'):
            value.close()
        assert not value.cleanup_complete
    else:
        value.close()
        value.close()
        assert value.cleanup_complete
    assert effects==(['cell'] if where=='cell' else ['cell','image'])


def test_extended_capture_cancellation_retains_partial_evidence_and_closes_cell():
    cell=ProductCell.__new__(ProductCell)
    cell.wall_seconds=600
    cell.observations=[]
    cell.spawn=lambda *args,**kwargs:pytest.fail('cancelled call must not spawn')
    cell.release=lambda *args,**kwargs:None
    effects=[]
    cell.close=lambda:effects.append('closed')
    with pytest.raises(InterruptedError,match='cancelled'):
        cell.capture_execution(['/usr/bin/false'],cancelled=lambda:True)
    assert effects==['closed'] and cell.observations[0]['kind']=='capture-failure'
    assert cell.observations[0]['stdout']==''
    with pytest.raises(ValueError,match='bounded'):
        cell.capture(['/usr/bin/false'],timeout=61)


def test_sdk_binding_dispatches_explicit_cell_schema_without_container_records(monkeypatch):
    actual={'effective_uid':10001,'effective_capabilities':'0000000000000000','no_new_privileges':1}
    controller=supervisor.BuiltinHookSupervisor.__new__(supervisor.BuiltinHookSupervisor)
    controller.sdk_pid=None
    calls=[]
    controller.plane=SimpleNamespace(boundary_schema='private-cell-boundary.v1',
                                    verify_sdk_boundary=lambda identity:calls.append(identity))
    monkeypatch.setattr(supervisor,'process_identity',lambda pid:actual)
    controller.bind_sdk(42,expected_identity=actual)
    assert calls==[actual] and controller.sdk_pid==42


@pytest.mark.parametrize('failure',[InterruptedError,TimeoutError])
def test_failed_actual_capture_keeps_samples_and_disables_closed_plane(failure):
    value=plane()
    value.observations=[]
    value.cell._pids=lambda:set()
    def capture(*args,observer,**kwargs):
        observer()
        value.cell.closed=True
        raise failure('actual capture interrupted')
    value.cell.capture_execution=capture
    with pytest.raises(failure,match='actual capture interrupted'):
        value._capture(['/installed/python','normal-native-command'],b'',timeout=5)
    assert value.started is False and value.executions==[]
    assert value.observations==[{'kind':'actual-native-capture-failure','exception_type':failure.__name__,
        'command':['/installed/python','normal-native-command'],'timeout_seconds':5,
        'kernel_process_samples':[],'cell_closed':True,'product_claims_authenticated':False}]
    with pytest.raises(ValueError,match='live private'):
        value.execute_contained({'hook_event_name':'PreToolUse','tool_name':'bash'})
