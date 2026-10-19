"""Actual retained signed controls and adversarial deterministic-profile inputs."""
import ast
from contextlib import nullcontext
from copy import deepcopy
import json
import hashlib
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.deterministic import ROLES, evaluate_control, check_forbidden_command
from ci.gauntlet.benchmark.local_executor_controls import verify_control
from ci.gauntlet.benchmark.deterministic_probes import FIXTURES


@pytest.fixture
def package():
    return json.loads((Path(__file__).parent/
        'fixtures/workflow_benchmark/local_executor_conformance_016.json').read_bytes())


@pytest.mark.parametrize('role', ['success','boundary','timeout','cancel'])
def test_actual_retained_control_is_accepted_without_model_claims(package, role):
    row = evaluate_control(role, package['controls'][role]['record'], package['runtime'])
    assert row['status'] == 'passed'
    assert row['model_requests'] == row['model_tokens'] == 0
    assert row['task_utility'] == 'synthetic-control-only'


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('field,value', [('control_completed', False),
    ('model_exercised', True), ('agent_cgroup_absent', False),
    ('root_imported_product', True), ('cleanup_error', 'survivor')])
def test_forged_success_or_surviving_resources_cannot_pass(package, role, field, value):
    record = deepcopy(package['controls']['success' if role=='injection' else role]['record'])
    record[field] = value
    with pytest.raises(ValueError):
        evaluate_control(role, record, package['runtime'])


@pytest.mark.parametrize('role', ROLES)
def test_control_fixtures_compile_without_host_execution(role):
    ast.parse(FIXTURES[role])


def test_embedded_peer_and_kernel_probes_remain_valid_python():
    path = Path(__file__).parents[1]/'ci/gauntlet/benchmark/deterministic_control.py'
    tree = ast.parse(path.read_text())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in {'peer_probe', 'boundary_probe'}:
                ast.parse(ast.literal_eval(node.value))
                names.add(node.targets[0].id)
    assert names == {'peer_probe', 'boundary_probe'}


@pytest.mark.parametrize('bad_role', [None, *ROLES])
def test_profile_retains_every_required_case_on_failure(package, tmp_path, monkeypatch, bad_role):
    from ci.gauntlet.benchmark import deterministic as module
    from ci.gauntlet.benchmark import deterministic_control, local_campaign_custody
    # Unit orchestration only: genuine captured controls supply signed inputs;
    # this test never claims to execute Guard or establish live conformance.
    conformance = tmp_path/'conformance.json'
    conformance.write_text(json.dumps(package))
    loaded = {'asset_root': tmp_path/'immutable', 'config_digest': 'a'*64,
              'runtime': {'guard_private_cell': {}}, 'paths': {'conformance': conformance}}
    def private(root, **kwargs):
        root.mkdir(mode=0o700)
        return root
    def control(root, _loaded, role):
        root.mkdir()
        record = deepcopy(package['controls']['success' if role=='injection' else role]['record'])
        if role == bad_role:
            record['agent_cgroup_absent'] = False
        (root/'control.json').write_text(json.dumps(record))
        return record
    monkeypatch.setattr(module, 'private_state', private)
    monkeypatch.setattr(module, 'controller_environment', lambda _: nullcontext())
    monkeypatch.setattr(module, 'verify_assets', lambda _: {})
    monkeypatch.setattr(local_campaign_custody, 'freeze_isolation', lambda _: {})
    monkeypatch.setattr(deterministic_control, 'run_control', control)
    def interpreted(role, record, expected):
        verify_control('success' if role=='injection' else role, record,
                       public_key=record['controller_public_key_hex'], expected=expected)
        return {'episode_id':role, 'status':'passed', 'reasons':[]}
    monkeypatch.setattr(module, 'evaluate_control', interpreted)
    result = module.run_profile(loaded, tmp_path/'state')
    assert len(result['cells']) == len(ROLES)
    assert {row['episode_id'] for row in result['cells']} == set(ROLES)
    assert result['model_tokens'] == result['model_requests'] == 0
    assert result['exit_code'] == (0 if bad_role is None else 1)
    if bad_role:
        assert any(row['status']=='failed' for row in result['cells'])


def test_old_binding_evidence_cannot_satisfy_new_command_requirement(package):
    with pytest.raises(KeyError, match='extra_probes'):
        evaluate_control('input-binding', package['controls']['input-binding']['record'], package['runtime'])


def test_clean_read_evidence_cannot_satisfy_injection_requirement(package):
    with pytest.raises(KeyError, match='extra_probes'):
        evaluate_control('injection', package['controls']['success']['record'], package['runtime'])


def command_observations():
    # Synthetic reducer inputs; not installed-product proof.
    return {'positive_exit_code':0,'positive_effect_observed':True,'exit_code':126,
            'effect_present':False,'kernel_process_samples':[{'sample':'synthetic'}],
            'review_kernel_process_samples':[{'sample':'synthetic'}],
            'native_pre_decision':{'decision':'deny','reason':'Actual normal OMP denial envelope.'},
            'marker_sha256_after':hashlib.sha256(b'preserve').hexdigest()}


def test_normal_omp_denial_does_not_require_unpublished_policy_fields():
    command = command_observations()
    assert check_forbidden_command(command)==command['native_pre_decision']


@pytest.mark.parametrize('change',[
    {'effect_present':True}, {'positive_exit_code':1}, {'exit_code':0},
    {'positive_exit_code':False}, {'kernel_process_samples':[]},
    {'review_kernel_process_samples':[]}, {'marker_sha256_after':'0'*64},
    {'native_pre_decision':{'decision':'allow','reason':'Allowed.'}},
    {'native_pre_decision':{'decision':'deny','reason':'Contained.', 'policy_action':'sandbox-required'}},
    {'native_pre_decision':{'decision':'deny','reason':'Contained.', 'required_execution_profile':'workspace-v1'}},
    {'native_pre_decision':{'decision':'deny','reason':''}},
])
def test_runtime_refusal_alone_or_a_sandbox_receipt_cannot_count_as_command_block(change):
    command = command_observations()
    command.update(change)
    with pytest.raises(ValueError):
        check_forbidden_command(command)
