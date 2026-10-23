"""Factory failure paths and budgets; planning doubles are not VM proof."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import private_cell_factory as module
from ci.gauntlet.benchmark.developer_product_runtime import OperationBudget


def config(path):
    return {'schema':'developer-private-cell-config.v1','artifacts':str(path),
        **{key:'a'*64 for key in ('artifact_manifest_sha256','initializer_sha256',
                                 'native_sha256','runtime_tree_digest')},
        'idmap_runtime':'ubuntu2404-controller-v1','cpu_profile':'single-core-v1'}


@pytest.mark.parametrize('field,value',[('schema','v0'),('extra',True),('native_sha256',None),
    ('runtime_tree_digest','A'*64),('artifacts','../outside'),('idmap_runtime',[]),
    ('cpu_profile','all-cpus'),('cpu_profile',True)])
def test_config_is_exact_and_cannot_select_arbitrary_profiles(tmp_path,field,value):
    row=config(tmp_path)
    row[field]=value
    with pytest.raises(ValueError):
        module.PrivateCellConfig.parse(row)


def test_config_roundtrip_detaches_caller_data(tmp_path):
    row=config(tmp_path)
    parsed=module.PrivateCellConfig.parse(row)
    row['native_sha256']='b'*64
    assert parsed.declaration()['native_sha256']=='a'*64


def test_public_bootstrap_traverses_under_private_umask(factory):
    import os
    import stat
    options,_,_,_=factory
    artifacts=Path(options['config'].artifacts)
    nested=artifacts/'public/ci/nested/module.py'
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b'# inert bootstrap fixture\n')
    manifest=json.loads((artifacts/'manifest.json').read_text())
    manifest['files']['public/ci/nested/module.py']=hashlib.sha256(nested.read_bytes()).hexdigest()
    raw=json.dumps(manifest).encode()
    (artifacts/'manifest.json').write_bytes(raw)
    stage=options['root'];stage.mkdir(mode=0o700)
    old=os.umask(0o077)
    try:
        module._stage_public(artifacts,stage,hashlib.sha256(raw).hexdigest())
        assert os.umask(0o077)==0o077
    finally:
        os.umask(old)
    for p in (stage/'public',stage/'public/ci',stage/'public/ci/nested'):
        assert stat.S_IMODE(p.stat().st_mode)==0o755
    assert stat.S_IMODE((stage/'public/ci/nested/module.py').stat().st_mode)==0o444
    assert stat.S_IMODE(stage.stat().st_mode)==0o700


@pytest.fixture
def factory(tmp_path,monkeypatch):
    artifacts=tmp_path/'artifacts'
    (artifacts/'public').mkdir(parents=True)
    (artifacts/'public/initializer').write_bytes(b'not-an-executed-initializer')
    files={'public/initializer':hashlib.sha256((artifacts/'public/initializer').read_bytes()).hexdigest()}
    raw=json.dumps({'schema':'product-cell-artifacts.v1','files':files}).encode()
    (artifacts/'manifest.json').write_bytes(raw)
    cfg=config(artifacts)
    cfg['artifact_manifest_sha256']=hashlib.sha256(raw).hexdigest()
    cfg=module.PrivateCellConfig.parse(cfg)
    effects=[]
    class Lease:
        def __init__(self,image_id):
            self.owned=False
        def acquire(self):
            effects.append('acquire')
            self.owned=True
        def declare(self,root):
            effects.append('declare')
            return 'c'*64
        def close(self):
            effects.append('release')
            self.owned=False
    class Cell:
        def __init__(self,*args,**kwargs):
            self.options=kwargs
            self.closed=False
            effects.append('cell')
        def close(self):
            effects.append('cell-close')
            self.closed=True
    monkeypatch.setattr(module,'ImageLease',Lease)
    monkeypatch.setattr(module,'ProductCell',Cell)
    monkeypatch.setattr(module,'_BudgetPrivatePlane',lambda **kwargs:SimpleNamespace(**kwargs))
    monkeypatch.setattr(module.os,'geteuid',lambda:0)
    monkeypatch.setattr(module.os,'chown',lambda *args:effects.append(('initial-state-owner',*args)))
    monkeypatch.setattr(module,'_trusted',lambda *args,**kwargs:None)
    monkeypatch.setattr(module,'metadata',lambda path:{'device':7,'inode':13,'mode':0o755})
    monkeypatch.setattr(module,'read_mounts',lambda *args,**kwargs:effects.append('validate-mounts'))
    monkeypatch.setattr(module,'root_prefix_digest',lambda *args:'a'*64)
    options=dict(root=tmp_path/'cell',config=cfg,python=Path('/opt/pinned/bin/python'),
        source_sha='a'*40,prefix_digest='a'*64,bwrap_sha256='b'*64,image_id='sha256:'+'c'*64,
        workspace_source=tmp_path/'checkout',workspace_custody_root=tmp_path,
        provider_mounts=(tmp_path/'remote',),provider_custody_root=tmp_path,wall_seconds=180,
        operation_budget=OperationBudget(2))
    return options,effects,Lease,Cell


def test_factory_passes_external_pins_preserves_task_and_uses_private_new_state(factory):
    options,effects,_,_=factory
    plane=module.build_private_cell(**options)
    assert effects.index('validate-mounts')<effects.index('acquire')<effects.index('cell')
    assert [e for e in effects if isinstance(e,tuple)]==[
        ('initial-state-owner',options['root']/'state',10004,10004),
        ('initial-state-owner',options['root']/'state/home',10004,10004),
        ('initial-state-owner',options['root']/'state/guard',10004,10004),
        ('initial-state-owner',options['root']/'state/guard/config.toml',10004,10004)]
    assert (options['root']/'state/guard/config.toml').read_text()==(
        'mode="enforce"\nsync=false\ntelemetry=false\ndesktop_notifications=false\n'
        'approval_wait_timeout_seconds=1\n')
    assert plane.cell.options['expected_task_digest']==hashlib.sha256(
        (options['root']/'task-mounts.json').read_bytes()).hexdigest()
    assert plane.expected_native_sha256=='a'*64
    assert plane.expected_prefix_digest=='a'*64
    assert plane.cell.options['network_profile']=='private-loopback-v1'
    assert plane.operation_budget is options['operation_budget']
    assert not (options['root']/'task').exists()


def test_dirty_prefix_aborts_before_state_or_image(factory,monkeypatch):
    options,effects,_,_=factory
    monkeypatch.setattr(module,'root_prefix_digest',lambda *args:'f'*64)
    with pytest.raises(ValueError,match='prefix differs'):
        module.build_private_cell(**options)
    assert effects==[] and not options['root'].exists()


def test_modified_bootstrap_aborts_before_image_acquisition(factory):
    options,effects,_,_=factory
    (Path(options['config'].artifacts)/'public/initializer').write_bytes(b'modified')
    with pytest.raises(ValueError,match='bytes differ'):
        module.build_private_cell(**options)
    assert 'acquire' not in effects


def test_partial_image_acquisition_failure_releases_owned_lease(factory,monkeypatch):
    options,effects,lease_class,_=factory
    def fail(self):
        self.owned=True
        effects.append('acquire')
        raise RuntimeError('partial image failure')
    monkeypatch.setattr(lease_class,'acquire',fail)
    with pytest.raises(RuntimeError,match='partial image'):
        module.build_private_cell(**options)
    assert effects[-1]=='release' and 'cell' not in effects


def test_failed_plane_construction_closes_cell_before_image(factory,monkeypatch):
    options,effects,_,_=factory
    def fail(**kwargs):
        raise RuntimeError('plane failed')
    monkeypatch.setattr(module,'_BudgetPrivatePlane',fail)
    with pytest.raises(RuntimeError,match='plane failed'):
        module.build_private_cell(**options)
    assert effects[-2:]==['cell-close','release']


def test_cleanup_failure_does_not_release_potentially_live_cell_image(factory,monkeypatch):
    options,effects,_,cell_class=factory
    def fail_close(self):
        effects.append('cell-close')
        raise RuntimeError('cell survives')
    monkeypatch.setattr(cell_class,'close',fail_close)
    monkeypatch.setattr(module,'_BudgetPrivatePlane',lambda **kwargs:(_ for _ in ()).throw(ValueError('plane failed')))
    with pytest.raises(RuntimeError,match='cell survives'):
        module.build_private_cell(**options)
    assert effects[-1]=='cell-close' and 'release' not in effects


def test_private_pre_uses_shared_budget_before_product_forwarding(monkeypatch):
    from ci.gauntlet.benchmark.private_cell_hook_plane import PrivateCellHookPlane
    plane=module._BudgetPrivatePlane.__new__(module._BudgetPrivatePlane)
    plane.operation_budget=OperationBudget(1)
    forwarded=[]
    monkeypatch.setattr(PrivateCellHookPlane,'invoke_hook',lambda self,payload,**kwargs:forwarded.append(payload))
    plane.invoke_hook({'hook_event_name':'PreToolUse','command':'one'})
    with pytest.raises(ValueError,match='before product'):
        plane.invoke_hook({'hook_event_name':'PreToolUse','command':'two'})
    assert len(forwarded)==1
