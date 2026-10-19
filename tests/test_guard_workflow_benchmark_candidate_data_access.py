"""Trusted inert reads preserve private modes and always restore oracle identity."""
import os

import pytest

from ci.gauntlet.benchmark import developer_worker_probe as module


@pytest.fixture
def reader(tmp_path,monkeypatch):
    state={'uid':0,'transitions':[]}
    monkeypatch.setattr(module,'_WORKER_VERIFIED',True)
    monkeypatch.setattr(module.sys,'platform','linux')
    monkeypatch.setattr(module.os,'geteuid',lambda:state['uid'])
    def switch(uid):
        state['transitions'].append(uid)
        state['uid']=uid
    monkeypatch.setattr(module.os,'seteuid',switch)
    monkeypatch.setattr(module,'CANDIDATE',tmp_path.resolve())
    return state,tmp_path.resolve()


def test_inert_reads_restore_root_even_when_candidate_data_is_broken(reader):
    state,root=reader
    path=root/'private.txt';path.write_text('candidate data');path.chmod(0o600)
    assert module.candidate_text(path)=='candidate data'
    assert state['uid']==0 and os.stat(path).st_mode&0o777==0o600
    with pytest.raises(RuntimeError,match='synthetic read error'):
        with module.candidate_data_access():
            assert state['uid']==10003
            raise RuntimeError('synthetic read error')
    assert state['uid']==0 and state['transitions'][-2:]==[10003,0]


def test_candidate_execution_cannot_be_entered_during_inert_read(reader):
    state,_=reader
    with module.candidate_data_access():
        with pytest.raises(RuntimeError,match='authenticated isolated worker'):
            module.run(['/must-never-launch'])
    assert state['uid']==0


@pytest.mark.parametrize('kind',['oversize','nonutf8','missing'])
def test_unusable_text_is_a_failed_artifact_and_identity_is_restored(reader,kind):
    state,root=reader
    path=root/'artifact.txt'
    if kind!='missing':path.write_bytes(b'x'*65_537 if kind=='oversize' else b'\xff')
    assert module.candidate_text(path) is None
    assert state['uid']==0


def test_reader_rejects_paths_outside_candidate_and_symlinks(reader):
    state,root=reader
    with pytest.raises(ValueError,match='artifact root'):
        module.candidate_text(root.parent/'outside')
    path=root/'link';path.symlink_to(root.parent/'outside')
    with pytest.raises(ValueError,match='symlink'):
        module.candidate_text(path)
    assert state['uid']==0


@pytest.mark.parametrize('verified,uid',[(False,0),(True,10003)])
def test_unverified_or_nonroot_reader_cannot_change_identity(reader,monkeypatch,verified,uid):
    state,_=reader
    state['uid']=uid
    monkeypatch.setattr(module,'_WORKER_VERIFIED',verified)
    with pytest.raises(RuntimeError,match='authenticated Root'):
        with module.candidate_data_access():
            pytest.fail('reader entered')
    assert state['transitions']==[]
