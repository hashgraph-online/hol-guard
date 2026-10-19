"""Campaign binder contracts using re-signed, path-adjusted inert control data.

These derivatives are unit inputs, never new execution or model evidence.
"""
import base64
import json
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.developer_campaign_product import bind_developer_product

ROOT=Path('/opt/hol-private-cell-plane-control-20261014-111')


def sign(value,key):
    if isinstance(value,list):
        return [sign(item,key) for item in value]
    if isinstance(value,dict):
        result={name:sign(item,key) for name,item in value.items()}
        if set(result)=={'record','signature'}:
            result['signature']=base64.b64encode(key.sign(canonical_json(result['record']).encode())).decode()
        return result
    return value


@pytest.fixture
def case(request):
    number=getattr(request,'param','111')
    root=ROOT.with_name(ROOT.name.removesuffix('111')+number)
    path=Path(__file__).parent/f'fixtures/workflow_benchmark/private_cell_runtime_{number}.json'
    # Campaign provider homes use runtime/home, unlike the standalone control.
    value=json.loads(path.read_text().replace(str(root/'tasks/home'),str(root/'runtime/home')))
    key=Ed25519PrivateKey.generate()
    evidence=sign(value['evidence'],key)
    settings=evidence['record']['settings']
    plane=evidence['record']['native_builtin_audit']['record']['product_plane']
    outside=value['outside_observations']
    runtime={'guard_private_cell':settings['private_cell'],'guard_source_sha':settings['source_sha'],
        'guard_prefix_digest':settings['prefix_digest'],'guard_bwrap_sha256':settings['bwrap_sha256'],
        'guard_executor_image_id':settings['executor_image_id'],'guard_python':plane['runtime_prefix']+'/bin/python'}
    config={'runtime':runtime,'isolation_tuple':{'image_id':settings['mcp_image_id'],
        'controller':deepcopy(plane['controller_identity']),'developer_product':{'private_cell':{
        'config':deepcopy(settings['private_cell']),
        'artifacts':{'manifest_sha256':settings['private_cell']['artifact_manifest_sha256']},
        'runtime_tree_digest':settings['private_cell']['runtime_tree_digest'],
        'mcp_identity_profile':'private-cell-mcp-v2','contained_output_binding':'controller-contained-output.v1',
        'contained_completion_profile':'guard-contained-completion.v1'}}}}
    if number!='111':
        runtime['guard_package_version']=settings['package_version']
        config['isolation_tuple']['developer_product']['private_cell'].update(
            schema='private-cell-campaign-inputs.v2',package_version=settings['package_version'])
    raw={'developer_product_evidence':evidence,'public_key':base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        'public_prompt_digest':evidence['record']['public_prompt_digest'],
        'resource_profile':{'deadline_seconds':settings['deadline_seconds'],'max_tool_calls':settings['max_tool_calls']},
        'baseline':{'checkout_path':str(root/'tasks/checkout'),'remote_path':str(root/'tasks/remote')},
        'execution_measurements':{'agent':outside['agent_identity'],'sdk_binding':{'error':None,'cleanup_complete':True,
            'observation':{'pid':outside['sdk_pid'],'identity':outside['sdk_identity'],
                'kernel_peer_authenticated':True,'bound_before_sdk_import':True}}}}
    return config,raw


def test_actual_v4_custody_reader_binds_captured_output_without_model_credit(case):
    config,raw=case
    result=bind_developer_product(config,raw,attempt_path=ROOT)
    assert result['custody_verified'] and result['builtin_pre_count']==result['builtin_post_count']==1
    assert result['mcp_tool_call_count']==1 and result['qualification_eligible'] is False
    assert 'utility_passed' not in result


def test_actual_freeze_namespace_projection_accepts_full_outside_identity(case):
    config,raw=case
    controller=config['isolation_tuple']['controller']
    config['isolation_tuple']['controller']={k:controller[k] for k in
        ('boot_id','mount_namespace','pid_namespace','network_namespace')}
    assert bind_developer_product(config,raw,attempt_path=ROOT)['custody_verified'] is True
    config['isolation_tuple']['controller']['network_namespace']='net:[foreign]'
    with pytest.raises(ValueError,match='runtime/controller'):
        bind_developer_product(config,raw,attempt_path=ROOT)


@pytest.mark.parametrize('field',['boot_id','mount_namespace','pid_namespace','network_namespace'])
def test_namespace_projection_cannot_omit_frozen_authority(case,field):
    config,raw=case
    del config['isolation_tuple']['controller'][field]
    with pytest.raises(ValueError,match='runtime/controller'):
        bind_developer_product(config,raw,attempt_path=ROOT)


def test_old_unbound_output_custody_cannot_enter_current_campaign(case):
    config,raw=case
    raw['developer_product_evidence']['record']['schema_version']='2.0'
    key=Ed25519PrivateKey.generate()
    raw['public_key']=base64.b64encode(key.public_key().public_bytes_raw()).decode()
    raw['developer_product_evidence']=sign(raw['developer_product_evidence'],key)
    with pytest.raises(ValueError):
        bind_developer_product(config,raw,attempt_path=ROOT)


@pytest.mark.parametrize('mutation',['manifest','prefix','controller','provider','key','sdk','old-profile'])
def test_campaign_context_cannot_be_substituted_by_signed_episode_claims(case,mutation):
    config,raw=case
    if mutation=='manifest':
        config['isolation_tuple']['developer_product']['private_cell']['artifacts']['manifest_sha256']='0'*64
    elif mutation=='prefix':
        config['runtime']['guard_python']='/opt/substituted/bin/python'
    elif mutation=='controller':
        config['isolation_tuple']['controller']['boot_id']='other-boot'
    elif mutation=='provider':
        raw['baseline']['remote_path']='/opt/other-provider'
    elif mutation=='key':
        raw['public_key']=base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    elif mutation=='sdk':
        raw['execution_measurements']['sdk_binding']['observation']['bound_before_sdk_import']=False
    else:
        config['isolation_tuple']['developer_product']['private_cell']['mcp_identity_profile']='native-product-v1'
    with pytest.raises(ValueError):
        bind_developer_product(config,raw,attempt_path=ROOT)


@pytest.mark.parametrize('case',['190'],indirect=True)
def test_historical_local_conformance_cannot_credit_changed_execution_sources(case,monkeypatch):
    from ci.gauntlet.benchmark import ci_gate, developer_campaign, local_executor_conformance
    from ci.gauntlet.benchmark.contracts import strict_json_loads
    config,raw=case
    root=ROOT.with_name(ROOT.name.removesuffix('111')+'190')
    path=Path(__file__).parent/'fixtures/workflow_benchmark/local_executor_conformance_013.json'
    value=strict_json_loads(path.read_bytes())
    config['runtime']['guard_conformance']={'path':str(path),
        'sha256':'529413f50d7ae74da0b86127fa78dd472e3af6cba34acd95a6cb217dc414d54e'}
    assets=value['public_assets']
    config['isolation_tuple'].update(assets)
    monkeypatch.setattr(local_executor_conformance,'platform_identity',lambda:value['platform'])
    with pytest.raises(ValueError,match='exact exercised execution-source inventory required'):
        local_executor_conformance.verify_local_conformance(config['runtime'],public_assets=assets)
    monkeypatch.setattr(developer_campaign,'_verified_raw',lambda _:raw)
    cell={'workflow_id':'python-cli-with-tests','group':'base'}
    report={'adapter':'hol-guard','execution_valid':True}
    assert ci_gate._surfaces(config,cell,report,root)=={'native-builtin-review','native-mcp'}
    config['isolation_tuple']['local_executor_admission']={
        'local_execution_supported':True,'public_inputs_verified':True,'package_sha256':'0'*64}
    with pytest.raises(ValueError,match='exact exercised execution-source inventory required'):
        ci_gate._surfaces(config,cell,report,root)


def test_diagnostic_support_is_recomputed_and_cannot_be_asserted_by_raw_boolean(case):
    from ci.gauntlet.benchmark.developer_campaign_product import private_runtime_custody
    _,raw=case
    raw['protected_product_custody_supported']=False
    assert private_runtime_custody(raw,attempt_path=ROOT)['custody_verified'] is True
    raw['protected_product_custody_supported']=True
    raw['developer_product_evidence']=None
    assert private_runtime_custody(raw,attempt_path=ROOT) is None
