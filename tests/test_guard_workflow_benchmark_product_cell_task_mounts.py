"""Mount declarations cannot turn public task inputs into controller mounts."""
import hashlib
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import product_cell_task_mounts as module


@pytest.fixture
def declared(tmp_path,monkeypatch):
    stage=tmp_path/'cell'
    stage.mkdir()
    custody='/opt/campaign/tasks'
    pinned={'device':7,'inode':13,'mode':0o755}
    workspace={'source':custody+'/checkout','destination':'/runtime/home/project',
               'custody_root':custody,**pinned}
    provider={'source':custody+'/remote','destination':custody+'/remote','custody_root':custody,
              **{**pinned,'inode':14,'mode':0o700}}
    value={'schema':'product-cell-task-mounts.v1','workspace':workspace,'providers':[provider]}
    original=Path.stat
    monkeypatch.setattr(Path,'stat',lambda path,*args,**kwargs:
        SimpleNamespace(st_mode=stat.S_IFDIR|0o700) if str(path)==custody
        else original(path,*args,**kwargs))
    monkeypatch.setattr(module,'metadata',lambda path: dict(pinned) if path.name=='checkout'
                        else {'device':7,'inode':14,'mode':0o700})
    seen=[]
    def trust(path,**kwargs):
        seen.append((path,kwargs))
    def read():
        raw=json.dumps(value).encode()
        (stage/'task-mounts.json').write_bytes(raw)
        return module.read_mounts(stage,hashlib.sha256(raw).hexdigest(),workspace='/runtime/home/project',
                                  trusted=trust,runtime_mountpoint='/home/guard/.venv')
    return value,read,seen,stage


def test_declared_checkout_and_provider_preserve_distinct_modes_and_all_parent_custody(declared):
    _,read,seen,_=declared
    rows=read()
    assert [(row['destination'],row['mode']) for row in rows]==[
        ('/runtime/home/project',0o755),('/opt/campaign/tasks/remote',0o700)]
    assert (Path('/opt/campaign/tasks'),{'directory':True}) in seen
    assert (Path('/'),{'directory':True}) in seen


@pytest.mark.parametrize('field,value',[
    ('source','/opt/campaign/tasks/../escape'),('source','/opt//campaign/tasks/checkout'),
    ('source','relative'),('source','/opt/campaign/tasks'),('destination','/product/home'),
    ('destination','/runtime/home/project/nested'),('device',True),('inode',99),('mode',0o777),
    ('extra','/bin/sh')])
def test_bad_workspace_declaration_rejected(declared,field,value):
    config,read,_,_=declared
    config['workspace'][field]=value
    with pytest.raises(ValueError):
        read()


@pytest.mark.parametrize('path',['/usr/override','/opt/node/bin','/home/guard/.venv/subdir',
    '/home/guard','/opt/campaign/tasks/checkout','/opt/campaign/tasks/checkout/nested'])
def test_provider_cannot_shadow_runtime_system_or_other_task(declared,path):
    config,read,_,_=declared
    config['providers'][0].update(source=path,destination=path,custody_root='/')
    with pytest.raises(ValueError):
        read()


def test_provider_count_and_duplicate_mounts_fail_before_use(declared):
    config,read,_,_=declared
    config['providers']*=9
    with pytest.raises(ValueError,match='bounded'):
        read()
    config['providers']=config['providers'][:2]
    with pytest.raises(ValueError,match='disjoint'):
        read()


def test_undeclared_and_modified_mount_file_fail_closed(declared):
    _,read,_,stage=declared
    read()
    with pytest.raises(ValueError,match='external declaration'):
        module.read_mounts(stage,None,workspace='/runtime/home/project',trusted=lambda *a,**k:None)
    with pytest.raises(ValueError,match='digest'):
        module.read_mounts(stage,'0'*64,workspace='/runtime/home/project',trusted=lambda *a,**k:None)


def test_untrusted_parent_aborts_before_mount_or_inode_read(declared,monkeypatch):
    _,read,_,stage=declared
    read()
    raw=(stage/'task-mounts.json').read_bytes()
    def reject(path,**kwargs):
        if path==Path('/opt/campaign'):
            raise ValueError('agent-controlled ancestor')
    monkeypatch.setattr(module,'metadata',lambda path:pytest.fail('must reject ancestry first'))
    with pytest.raises(ValueError,match='ancestor'):
        module.read_mounts(stage,hashlib.sha256(raw).hexdigest(),workspace='/runtime/home/project',trusted=reject)


@pytest.mark.parametrize('uid,gid,mode',[(0,10001,0o700),(10001,0,0o700),
    (10001,10001,0o777),(10001,10001,0o2775),(10001,10001,0o600)])
def test_actual_leaf_metadata_rejects_wrong_owner_and_unsafe_modes(tmp_path,monkeypatch,uid,gid,mode):
    leaf=tmp_path/'task'
    monkeypatch.setattr(Path,'lstat',lambda path:SimpleNamespace(
        st_uid=uid,st_gid=gid,st_mode=stat.S_IFDIR|mode,st_dev=7,st_ino=13))
    with pytest.raises(ValueError,match='agent directory'):
        module.metadata(leaf)


def test_source_substitution_rejected_before_mount(declared,monkeypatch,tmp_path):
    _,read,_,_=declared
    rows=read()
    monkeypatch.setattr(module,'metadata',lambda path:{'device':7,'inode':999,'mode':0o755})
    with pytest.raises(ValueError,match='changed before'):
        module.bind_mounts(rows,tmp_path/'new',mount=lambda *a,**k:pytest.fail('no mount'),
                           run=lambda *a,**k:pytest.fail('no helper'))
