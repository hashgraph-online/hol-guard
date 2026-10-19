"""Controller race contracts with fake processes, never Native execution proof."""
import errno
import io
import itertools
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import native_builtin_plane as module

COMMAND=['/installed/python','--unit-hook']


@pytest.fixture
def sampling(monkeypatch):
    process=SimpleNamespace(pid=900,returncode=None,stdin=io.BytesIO(),stdout=io.BytesIO(),stderr=io.BytesIO())
    process.poll=lambda:process.returncode
    process.kill=lambda:setattr(process,'returncode',-9)
    process.wait=lambda **_:process.returncode
    observed={'exchanges':0,'removals':[]}
    monkeypatch.setattr(module.subprocess,'Popen',lambda *args,**kwargs:process)
    monkeypatch.setattr(module,'_podman',lambda *args,**kwargs:observed['removals'].append(args))
    clock=itertools.count(step=.05)
    monkeypatch.setattr(module.time,'monotonic',lambda:next(clock))
    monkeypatch.setattr(module.time,'sleep',lambda _:None)
    def exchange(actual,raw,*,timeout):
        assert actual is process and raw==b'unit payload\n'
        observed['exchanges']+=1
        process.returncode=0
        return b'{"decision":"allow"}',b''
    monkeypatch.setattr(module,'_exchange',exchange)
    controller={key:key+':controller' for key in ('mount_namespace','pid_namespace','network_namespace')}
    identity={**{key:key+':product' for key in controller},'effective_uid':10004,
        'effective_gid':10004,'effective_capabilities':'0000000000000000','no_new_privileges':1}
    subject=SimpleNamespace(name='unit-owned-product',controller_identity=controller,
        hook_observations=[],started=True)
    return subject,process,observed,identity


def proc_bytes(monkeypatch,stale=None):
    original=Path.read_bytes
    def read(path):
        if str(path).startswith('/proc/') and path.name=='cmdline':
            if path.parent.name=='11' and stale:
                raise stale
            return b'\0'.join(part.encode() for part in COMMAND)+b'\0'
        return original(path)
    monkeypatch.setattr(Path,'read_bytes',read)


@pytest.mark.parametrize('phase',['cmdline','identity'])
def test_departed_candidate_does_not_hide_later_measured_hook(sampling,monkeypatch,phase):
    subject,process,observed,identity=sampling
    samples=iter([{10},{10,11},{10,12},{10}])
    subject.pids=lambda:next(samples)
    proc_bytes(monkeypatch,ProcessLookupError(errno.ESRCH,'departed') if phase=='cmdline' else None)
    measured=[]
    def inspect(pid):
        measured.append(pid)
        if pid==11:raise ProcessLookupError(errno.ESRCH,'departed')
        return identity
    monkeypatch.setattr(module,'process_identity',inspect)
    result=module.NativeBuiltinHookPlane._invoke(subject,COMMAND,b'unit payload\n',{},.5)
    assert result=={'decision':'allow'} and measured[-1]==12
    assert observed['exchanges']==1 and observed['removals']==[]
    assert subject.hook_observations[0]['product_pid']==12
    assert subject.hook_observations[0]['identity']==identity
    assert all(getattr(process,name).closed for name in ('stdin','stdout','stderr'))


def test_only_departed_candidates_still_refuse_without_reading_a_decision(sampling,monkeypatch):
    subject,process,observed,_=sampling
    samples=itertools.chain([{10}],itertools.repeat({10,11}))
    subject.pids=lambda:next(samples)
    proc_bytes(monkeypatch,ProcessLookupError(errno.ESRCH,'departed'))
    monkeypatch.setattr(module,'process_identity',lambda _:pytest.fail('departed process measured'))
    with pytest.raises(ValueError,match='could not be independently measured'):
        module.NativeBuiltinHookPlane._invoke(subject,COMMAND,b'unit payload\n',{},.2)
    assert observed['exchanges']==0 and subject.hook_observations==[]
    assert observed['removals']==[('rm','--force','--time=0','unit-owned-product')]
    assert process.returncode==-9 and subject.started is False


def test_permission_denial_remains_fatal_and_cannot_be_ignored_as_churn(sampling,monkeypatch):
    subject,_,observed,_=sampling
    samples=iter([{10},{10,11}]);subject.pids=lambda:next(samples)
    proc_bytes(monkeypatch,PermissionError(errno.EACCES,'denied'))
    with pytest.raises(PermissionError):
        module.NativeBuiltinHookPlane._invoke(subject,COMMAND,b'unit payload\n',{},.5)
    assert observed['exchanges']==0 and subject.hook_observations==[]
    assert len(observed['removals'])==1 and subject.started is False


def test_stable_privileged_candidate_still_fails_real_boundary_validation(sampling,monkeypatch):
    subject,_,observed,identity=sampling
    samples=iter([{10},{10,12}]);subject.pids=lambda:next(samples)
    proc_bytes(monkeypatch)
    monkeypatch.setattr(module,'process_identity',lambda _:{**identity,'effective_uid':0})
    with pytest.raises(ValueError,match='UID/capability/namespace boundary'):
        module.NativeBuiltinHookPlane._invoke(subject,COMMAND,b'unit payload\n',{},.5)
    assert observed['exchanges']==0 and subject.hook_observations==[]
    assert len(observed['removals'])==1 and subject.started is False
