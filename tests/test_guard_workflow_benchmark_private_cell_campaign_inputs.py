"""Inert bootstrap/freeze negatives, not native conformance or live episodes."""
import hashlib

import pytest

from ci.gauntlet.benchmark import private_cell_campaign_inputs as module
from ci.gauntlet.benchmark.campaign_identity import validate_product_pins
from ci.gauntlet.benchmark.contracts import canonical_json


def manifest(root,files):
    value={'schema':'product-cell-artifacts.v1','files':{
        name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    for name,data in files.items():
        path=root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
    raw=(canonical_json(value)+'\n').encode()
    (root/'manifest.json').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def bootstrap(tmp_path,monkeypatch):
    root=tmp_path/'cell'
    root.mkdir()
    files=module._sources()
    files.update({'public/actor.py':b'raise RuntimeError("inert, never execute")',
                  'public/initializer':b'inert ELF placeholder'})
    pin=manifest(root,files)
    cfg={'schema':'developer-private-cell-config.v1','artifacts':str(root),
        'artifact_manifest_sha256':pin,'initializer_sha256':hashlib.sha256(files['public/initializer']).hexdigest(),
        'native_sha256':'a'*64,'runtime_tree_digest':'b'*64,'idmap_runtime':'ubuntu2404-controller-v1',
        'cpu_profile':'single-core-v1'}
    monkeypatch.setattr(module,'_trusted',lambda *args,**kwargs:None)
    return root,files,cfg


def test_only_exact_pinned_bootstrap_is_read_as_inert_data(bootstrap):
    _,files,cfg=bootstrap
    result=module.verify_artifacts(cfg)
    assert result['candidate_code_executed'] is False
    assert len(result['files'])==len(files)==38
    assert result['manifest_sha256']==cfg['artifact_manifest_sha256']


@pytest.mark.parametrize('mutation',['bytes','source','extra','missing','traversal','initializer','manifest'])
def test_bootstrap_substitution_rejected_even_with_recomputed_manifest(bootstrap,mutation):
    root,files,cfg=bootstrap
    if mutation=='bytes':
        (root/'public/actor.py').write_bytes(b'changed')
    elif mutation=='source':
        files['code/ci/gauntlet/benchmark/product_vm_rootfs.py']=b'raise RuntimeError("candidate Root code")'
        cfg['artifact_manifest_sha256']=manifest(root,files)
    elif mutation=='extra':
        (root/'code/os.py').write_bytes(b'raise RuntimeError("shadow stdlib")')
    elif mutation=='missing':
        del files['code/ci/__init__.py']
        cfg['artifact_manifest_sha256']=manifest(root,files)
    elif mutation=='traversal':
        files['public/../escape']=b'bad'
        cfg['artifact_manifest_sha256']=manifest(root,files)
    elif mutation=='initializer':
        cfg['initializer_sha256']='0'*64
    else:
        cfg['artifact_manifest_sha256']='0'*64
    with pytest.raises(ValueError):
        module.verify_artifacts(cfg)


def test_private_cell_config_requires_all_isolated_product_pins(bootstrap):
    _,_,cfg=bootstrap
    runtime={'guard_private_cell':cfg}
    with pytest.raises(ValueError,match='requires all'):
        validate_product_pins(runtime)
    runtime.update(guard_prefix_digest='a'*64,guard_bwrap_sha256='b'*64,
        guard_executor_image_id='sha256:'+'c'*64,isolated=True,product_isolated=True,protected_adapter='hol-guard')
    assert validate_product_pins(runtime)['guard_prefix_digest']=='a'*64
    runtime['isolated']=False
    with pytest.raises(ValueError,match='explicit isolated'):
        validate_product_pins(runtime)


def test_freeze_pins_inert_runtime_helpers_and_never_claims_conformance(bootstrap,monkeypatch):
    from ci.gauntlet.benchmark import product_cell_idmap, product_cell_supervisor, runtime_bundle
    _,_,cfg=bootstrap
    calls=[]
    entries={module.COMPLETION_MODULE:{'kind':'file','sha256':'c'*64}}
    monkeypatch.setattr(runtime_bundle,'inventory',lambda p:(entries,{},'b'*64,42))
    monkeypatch.setattr(product_cell_idmap,'verify',lambda profile,**_:calls.append(profile))
    monkeypatch.setattr(product_cell_supervisor,'cpu_configuration',lambda profile:(3,['frozen CPU']))
    result=module.freeze_private_cell({'guard_private_cell':cfg,'guard_python':'/opt/pinned/bin/python'})
    assert calls==['ubuntu2404-controller-v1']
    assert result['runtime_entries']==1 and result['runtime_bytes']==42 and result['allowed_cpu']==3
    assert (result['agent_uid'],result['builtin_uid'],result['mcp_uid'])==(10001,10004,10005)
    assert result['conformance_verified'] is result['qualification_eligible'] is False
    assert result['completion_module_sha256']=='c'*64
    assert result['contained_completion_profile']=='guard-contained-completion.v1'
    entries.clear()
    with pytest.raises(ValueError,match='lacks the declared completion module'):
        module.freeze_private_cell({'guard_private_cell':cfg,'guard_python':'/opt/pinned/bin/python'})
    cfg['runtime_tree_digest']='0'*64
    with pytest.raises(ValueError,match='runtime tree differs'):
        module.freeze_private_cell({'guard_private_cell':cfg,'guard_python':'/opt/pinned/bin/python'})


def test_pilot_arguments_preserve_adapter_identity_but_do_not_admit_protected_cells(bootstrap,tmp_path):
    from ci.gauntlet.benchmark.developer_campaign import (
        developer_pilot_arguments,
        developer_support,
        run_developer_cell,
    )
    _,_,cfg=bootstrap
    runtime={'guard_private_cell':cfg,'guard_python':'/opt/pinned/bin/python','guard_source_sha':'a'*40,
        'guard_prefix_digest':'a'*64,'guard_bwrap_sha256':'b'*64,'guard_executor_image_id':'sha256:'+'c'*64,
        'isolated':True,'product_isolated':True,'protected_adapter':'hol-guard','bun':'/public/bun',
        'sdk_root':'/public/node_modules/@oh-my-pi/pi-coding-agent','model_id':'inert-model'}
    budgets={'episode_seconds':240,'tool_operations':20,'model_tokens':10000}
    cell={'workflow_id':'fix-failing-node-test','variant':'clean','protected':True}
    kwargs=developer_pilot_arguments(tmp_path/'attempt',cell,runtime,budgets)
    assert kwargs['adapter_id']=='hol-guard' and str(kwargs['guard_python'])==runtime['guard_python']
    assert kwargs['guard_private_cell']==cfg and kwargs['guard_private_cell'] is not cfg
    assert 'conformance not established' in developer_support(cell,runtime,budgets)
    with pytest.raises(ValueError,match='conformance not established'):
        run_developer_cell(tmp_path/'attempt',cell,runtime,budgets)
    assert not (tmp_path/'attempt').exists()
    baseline=developer_pilot_arguments(tmp_path/'baseline',{**cell,'protected':False},runtime,budgets)
    assert baseline['adapter_id']=='unprotected' and 'guard_private_cell' not in baseline
