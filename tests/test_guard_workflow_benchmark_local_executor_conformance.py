"""Actual retained conformance and adversarial local-admission contracts."""
import hashlib
import json
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from ci.gauntlet.benchmark import local_executor_conformance as module
from ci.gauntlet.benchmark.contracts import canonical_json, digest

PACKAGES={
    '013':'529413f50d7ae74da0b86127fa78dd472e3af6cba34acd95a6cb217dc414d54e',
    '014':'adc7f0aebe005aa17345b202a442f7ff60caa4169bf3577a927a57afc46cab79',
    '015':'647a82fd353d386c23d2c4eaf7b682e9d27d1c91d1af6c7fa00cab8f3af968de',
    '016':'7a2ba1f7f2abecc6398317045aaf6257ee1ed49ca61c1516a88952a2dad05e2a',
}


def retained_package(identifier):
    package=Path(__file__).parent/f'fixtures/workflow_benchmark/local_executor_conformance_{identifier}.json'
    pin=PACKAGES[identifier]
    raw=package.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==pin
    value=json.loads(raw)
    settings=value['controls']['success']['record']['developer_runtime']['record']['settings']
    runtime={'guard_package_version':settings['package_version'],
        'guard_conformance':{'path':str(package),'sha256':pin},
        'guard_private_cell':settings['private_cell'],'guard_source_sha':settings['source_sha'],
        'guard_prefix_digest':settings['prefix_digest'],'guard_bwrap_sha256':settings['bwrap_sha256'],
        'guard_executor_image_id':settings['executor_image_id']}
    return runtime,value


@pytest.fixture(params=['015','016'])
def specimen(request,monkeypatch,tmp_path):
    runtime,value=retained_package(request.param)
    # Interpret historical proof against its actual, separately retained source
    # bytes. Never relabel the old controls as having exercised the new runner.
    archive=Path(__file__).parent/'fixtures/workflow_benchmark/historical_execution_sources_016.zip'
    assert hashlib.sha256(archive.read_bytes()).hexdigest()=='3e9a068a7ef9502afc219672db026fe277cf6b9f05dd4acefcc28030451bcda2'
    source=tmp_path/'retained-source';source.mkdir()
    with zipfile.ZipFile(archive) as bundle:
        assert set(bundle.namelist())==set(value['execution_sources'])
        for name,pin in value['execution_sources'].items():
            raw=bundle.read(name)
            assert hashlib.sha256(raw).hexdigest()==pin
            (source/name).write_bytes(raw)
    monkeypatch.setattr(module,'SOURCE',source)
    monkeypatch.setattr(module,'EXECUTION_SOURCES',tuple(value['execution_sources']))
    return runtime,value


def test_updated_runner_requires_fresh_proof_instead_of_borrowing_historical_controls():
    runtime,value=retained_package('016')
    with pytest.raises(ValueError,match='execution[- ]source'):
        module.verify_local_conformance(runtime,observed_platform=value['platform'])


def test_real_five_control_package_admits_only_matching_local_execution(specimen):
    runtime,value=specimen
    summary=module.verify_local_conformance(runtime,observed_platform=value['platform'],
                                            public_assets=value['public_assets'])
    assert summary['local_execution_supported'] is summary['public_inputs_verified'] is True
    assert summary['product_claims_authenticated'] is summary['qualification_eligible'] is False
    assert summary['review_scope']=='implementation-author-local-only'
    assert {row['role'] for row in summary['controls']}==module.ROLES
    assert all(row['model_tokens']==0 and row['synthetic'] for row in summary['controls'])


def test_no_implicit_platform_portability_or_public_input_verification(specimen):
    runtime,value=specimen
    other={**value['platform'],'kernel_release':'different'}
    with pytest.raises(ValueError,match='platform'):
        module.verify_local_conformance(runtime,observed_platform=other)
    result=module.verify_local_conformance(runtime,observed_platform=value['platform'])
    assert result['public_inputs_verified'] is False


@pytest.mark.parametrize('mutation',[
    lambda v:v.update(qualification_eligible=True),
    lambda v:v.update(scope='qualification'),
    lambda v:v['controls'].pop('cancel'),
    lambda v:v['review'].update(reviewer_role='independent-reviewer'),
    lambda v:v['review']['requirements'].pop('network'),
    lambda v:v['review'].update(document='altered review'),
    lambda v:v['execution_sources'].update({'../escape.py':'0'*64}),
    lambda v:v['execution_sources'].update({'builtin_hook_supervisor.py':'0'*64}),
    lambda v:v['runtime'].update(prefix_digest='0'*64),
    lambda v:v['controls']['timeout']['record'].update(detached_child_alive_before_cell_teardown=True),
    lambda v:v['controls']['timeout']['record'].update(cell_closed_before_explicit_teardown=True),
    lambda v:v['controls']['cancel']['record'].update(detached_child_samples=[]),
    lambda v:v['controls']['input-binding']['record']['request_binding_negatives'].pop(),
    lambda v:v['controls']['boundary']['record']['native_contained_boundary_negatives']['rows'][0].update(denied=False),
    lambda v:v['controls']['success']['record']['sdk_result']['results'][1].update(isError=True),
    lambda v:v['controls']['success']['record']['sdk_result'].pop('modelContextProjection'),
    lambda v:v['controls']['success']['record']['sdk_result']['modelContextProjection'].update(originalCommandVisible=False),
    lambda v:v['controls']['success']['record']['sdk_result']['modelContextProjection'].update(executionTransportRetained=False),
    lambda v:v['controls']['success']['record']['sdk_result']['modelContextProjection'].update(originalCommandVisible=1),
    lambda v:v['controls']['success']['record']['sdk_result']['modelContextProjection'].update(executionTransportRetained=1),
    lambda v:v['controls']['success']['record']['sdk_result']['modelContextProjection'].update(extra=True),
    lambda v:v['controls']['success']['record']['developer_runtime']['record'].update(prompt_allowed=False),
])
def test_recomputed_package_hash_cannot_hide_semantically_invalid_controls(specimen, tmp_path,mutation):
    runtime,value=specimen
    mutation(value)
    for row in value['controls'].values():
        row['record_digest']=digest(row['record'])
    raw=(canonical_json(value)+'\n').encode()
    path=tmp_path/'changed.json'
    path.write_bytes(raw)
    runtime['guard_conformance']={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
    with pytest.raises((ValueError,InvalidSignature)):
        module.verify_local_conformance(runtime,observed_platform=value['platform'])


@pytest.mark.parametrize('asset',['sdk','bun'])
def test_actual_public_input_substitution_refused(specimen, asset):
    runtime,value=specimen
    actual=deepcopy(value['public_assets'])
    actual[asset]['tree_digest' if asset=='sdk' else 'sha256']='0'*64
    with pytest.raises(ValueError,match='SDK/Bun'):
        module.verify_local_conformance(runtime,observed_platform=value['platform'],public_assets=actual)


def test_external_hash_precedes_parsing_and_no_package_cannot_admit(specimen):
    runtime,value=specimen
    runtime['guard_conformance']['sha256']='0'*64
    with pytest.raises(ValueError,match='outside pin'):
        module.verify_local_conformance(runtime,observed_platform=value['platform'])
    del runtime['guard_conformance']
    with pytest.raises(ValueError,match='not established'):
        module.verify_local_conformance(runtime,observed_platform=value['platform'])


@pytest.mark.parametrize('historical',['001','002','003','004','005','006','007','008','009','010','011','012','013','014'])
def test_historical_conformance_cannot_admit_changed_execution_sources(specimen, historical):
    runtime,_=specimen
    path=Path(runtime['guard_conformance']['path']).with_name('local_executor_conformance_'+historical+'.json')
    raw=path.read_bytes()
    value=json.loads(raw)
    runtime['guard_conformance']={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
    settings=value['controls']['success']['record']['developer_runtime']['record']['settings']
    if 'package_version' in value['runtime']:
        runtime['guard_package_version']=value['runtime']['package_version']
    else:
        runtime.pop('guard_package_version',None)
    runtime['guard_private_cell']=settings['private_cell']
    # Match the historical tuple so this case isolates the source-inventory
    # rejection, rather than stopping first on its now different runtime.
    for name in ('source_sha','prefix_digest','bwrap_sha256','executor_image_id'):
        runtime['guard_'+name]=settings[name]
    with pytest.raises(ValueError,match='execution[- ]source'):
        module.verify_local_conformance(runtime,observed_platform=value['platform'])


def test_a_different_native_runtime_cannot_borrow_the_other_builds_conformance(specimen):
    runtime,value=specimen
    current=Path(runtime['guard_conformance']['path'])
    other='016' if current.name.endswith('_015.json') else '015'
    path=current.with_name('local_executor_conformance_'+other+'.json')
    runtime['guard_conformance']={'path':str(path),'sha256':PACKAGES[other]}
    with pytest.raises(ValueError,match='frozen runtime differs'):
        module.verify_local_conformance(runtime,observed_platform=value['platform'])


@pytest.mark.parametrize('stderr,accepted',[
    ('contained_test_authorization_failed: rejected\n',True),
    ('contained_run_authorization_failed: rejected\n',True),
    ('native_hook_worker_unavailable: unavailable',False),
    ('not_contained_run_authorization_failed: rejected',False),
    ('traceback: contained_run_authorization_failed',False),
    ('contained_run_authorization_failed',False),
    ('',False),(None,False),
])
def test_request_binding_refusal_requires_an_exact_known_public_code(stderr,accepted):
    from ci.gauntlet.benchmark.local_executor_controls import request_rejection
    assert request_rejection(stderr) is accepted
