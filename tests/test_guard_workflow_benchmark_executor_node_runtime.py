"""Inert image-path mutations must not claim usable sandbox dependencies."""
import hashlib
import json
import os

import pytest

from ci.gauntlet.benchmark import executor_node_runtime as module


def image(tmp_path,monkeypatch):
    # Unit data owned by the test user; actual mounted images require UID0.
    monkeypatch.setattr(module,'ROOT_UID',os.getuid())
    root=tmp_path/'image';(root/'usr/bin').mkdir(parents=True)
    npm=root/'usr/lib/node_modules/npm';(npm/'bin').mkdir(parents=True)
    (root/'usr/bin/node').write_bytes(b'\x7fELF-inert-fixture-never-executed')
    (root/'usr/bin/node').chmod(0o755)
    (npm/'bin/npm-cli.js').write_text('inert fixture; never execute')
    (npm/'package.json').write_text(json.dumps({'name':'npm','version':'10.9.4'}))
    (root/'usr/bin/npm').symlink_to('../lib/node_modules/npm/bin/npm-cli.js')
    # The normal Linux checkout can have umask0002. Fixture inputs must satisfy
    # the readonly custody contract explicitly, independent of the test host.
    root.chmod(0o755)
    for path in root.rglob('*'):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path.name=='node' else 0o644)
    return root


def test_regular_usr_runtime_is_measured_as_inert_input(tmp_path,monkeypatch):
    root=image(tmp_path,monkeypatch);result=module.image_node_runtime_identity(root)
    assert result['available'] is True and result['candidate_code_executed'] is False
    assert result['node']['sha256']==hashlib.sha256((root/'usr/bin/node').read_bytes()).hexdigest()
    assert result['npm_version']=='10.9.4'


@pytest.mark.parametrize('mutation',[
    'node-missing','node-opt-link','node-directory','node-fifo','node-not-executable','node-writable',
    'npm-foreign-link','npm-missing','package-duplicate-fields','package-wrong-name',
    'indirect-library-parent','writable-library-parent','wrong-owner',
])
def test_missing_escaping_or_unsafe_dependencies_fail_capability_before_inference(tmp_path,monkeypatch,mutation):
    root=image(tmp_path,monkeypatch);node=root/'usr/bin/node';npm=root/'usr/bin/npm'
    package=root/'usr/lib/node_modules/npm/package.json'
    if mutation=='node-missing':node.unlink()
    elif mutation=='node-opt-link':node.unlink();node.symlink_to('/opt/node/bin/node')
    elif mutation=='node-directory':node.unlink();node.mkdir()
    elif mutation=='node-fifo':node.unlink();os.mkfifo(node)
    elif mutation=='node-not-executable':node.chmod(0o644)
    elif mutation=='node-writable':node.chmod(0o777)
    elif mutation=='npm-foreign-link':npm.unlink();npm.symlink_to('/opt/node/bin/npm')
    elif mutation=='npm-missing':npm.unlink()
    elif mutation=='package-duplicate-fields':package.write_text('{"name":"npm","name":"other","version":"1"}')
    elif mutation=='package-wrong-name':package.write_text('{"name":"other","version":"1"}')
    elif mutation=='indirect-library-parent':
        library=root/'usr/lib';library.rename(root/'moved-lib');library.symlink_to('../moved-lib',target_is_directory=True)
    elif mutation=='writable-library-parent':(root/'usr/lib').chmod(0o777)
    else:monkeypatch.setattr(module,'ROOT_UID',os.getuid()+1)
    result=module.image_node_runtime_identity(root)
    assert result['available'] is False and result['candidate_code_executed'] is False
    assert result['reason'] and 'node' not in result


@pytest.mark.parametrize('workflow,protected,capability,expected',[
    ('fix-failing-node-test',True,'valid',True),
    ('fix-failing-node-test',True,'missing',False),
    ('fix-failing-node-test',True,'wrong-digest',False),
    ('fix-failing-node-test',True,'integer-available',False),
    ('python-cli-with-tests',True,'missing',True),
    ('fix-failing-node-test',False,'missing',True),
    ('business-bd-pilot-planning',True,'missing',True),
])
def test_preflight_requires_node_closure_only_for_relevant_protected_workflows(monkeypatch,workflow,protected,capability,expected):
    from ci.gauntlet.benchmark import ci_runner_preflight as preflight,local_campaign_custody,local_campaign
    monkeypatch.setattr(preflight.sys,'platform','linux')
    monkeypatch.setattr(preflight.os,'geteuid',lambda:0)
    monkeypatch.setattr(preflight,'verify_assets',lambda _: {})
    monkeypatch.setattr(local_campaign,'_unsupported',lambda *_:None)
    node={'available':capability!='missing','node':{'sha256':'a'*64}}
    if capability=='wrong-digest':node['node']['sha256']='b'*64
    if capability=='integer-available':node['available']=1
    isolation={'developer_product':{'node_runtime':node},
        'local_executor_admission':{'local_execution_supported':True,'public_inputs_verified':True}}
    monkeypatch.setattr(local_campaign_custody,'freeze_isolation',lambda _:isolation)
    monkeypatch.setattr(preflight,'observe_provider',lambda _:{'status':{'quota':{
        'remaining_tokens':1000,'requests':0,'maximum_requests':100}}})
    cell={'id':'fixture','group':'base','workflow_id':workflow,'protected':protected}
    loaded={'config_digest':'fixture','config':{'selection':['fixture'],'assets':{'node':{'sha256':'a'*64}}},
        'selection_reservations':{},'shards':[['fixture']],'runtime':{},
        'policy':{'cells':[{'episode_id':'fixture','required_surfaces':[]}]},
        'campaign':{'inventory':[cell],'budgets':{}}}
    result=preflight.preflight(loaded)
    assert result['passed'] is expected
    if not expected:
        assert result['unsupported_cells'][0]['reason']=='executor-node-runtime-closure-unavailable'
