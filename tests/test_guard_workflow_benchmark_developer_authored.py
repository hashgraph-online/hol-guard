"""Signed collector units and real inert Git fixtures; no host candidate execution."""
from __future__ import annotations

import base64
import copy
import hashlib
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.authored_challenges import load_authored_oracle
from ci.gauntlet.benchmark.challenge_oracles import score_authored_challenge
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.developer_authored import bind_authored, verify_authored
from ci.gauntlet.benchmark.developer_oracles import PythonCliInterface, probe_plan
from ci.gauntlet.benchmark.developer_resources import AUTHORED_PYTHON, DeveloperInputContext
from ci.gauntlet.benchmark.developer_unittest import discover_tests
from ci.gauntlet.benchmark.developer_unittest import test_execution_valid as execution_valid
from ci.gauntlet.benchmark.synthetic_developer_services import SyntheticGitService, _git
from ci.gauntlet.benchmark.world import verify_receipts

TEST_SOURCE = ('import unittest\nclass TemperatureTest(unittest.TestCase):\n'
               ' def test_example(self):\n  self.assertEqual(1,1)\n')


@pytest.fixture
def tmp_path():
    with tempfile.TemporaryDirectory(prefix='bm-auth-', dir='/tmp') as directory:
        yield Path(directory).resolve()


def signed(key, field, value):
    return {field: value, 'signature': base64.b64encode(key.sign(canonical_json(value).encode())).decode()}


def test_discovery_is_inert_and_count_proof_ignores_candidate_prints(tmp_path):
    file = tmp_path / 'test_temperature.py'
    file.write_text(TEST_SOURCE + '\nraise RuntimeError("must never import this on host")\n')
    selected = discover_tests(tmp_path)
    assert len(selected) == 1 and selected[0]['syntactic_assertion_nodes'] == 1
    assert not execution_valid([{'agent_tests_run': 999, 'stdout': 'Ran999tests'}], {})
    row = {**selected[0], 'pid': 42, 'candidate_uid': 10003, 'exit_code': 0, 'timed_out': False}
    files = {file.name: hashlib.sha256(file.read_bytes()).hexdigest()}
    assert execution_valid([row], files)
    assert not execution_valid([row, row], files)
    assert not execution_valid([{**row, 'candidate_uid': 0}], files)
    assert not execution_valid([{**row, 'exit_code': 1}], files)
    assert not execution_valid([{**row, 'syntactic_assertion_nodes': 0}], files)


def test_actual_primary_id_and_signed_repository_observation(tmp_path):
    key = Ed25519PrivateKey.generate()
    inputs = DeveloperInputContext(tmp_path, key, 'python-cli-with-tests', 'clean', AUTHORED_PYTHON, 30, 20)
    service = SyntheticGitService(tmp_path / 'git', signing_key=key)
    baseline = service.seed('python-cli-with-tests', primary_repository_id='tc-repository')
    assert baseline['repository_id'] == 'tc-repository'
    assert 'tc-repository' in baseline['remote_path']
    assert service.receipts()[0]['event']['repository_id'] == 'tc-repository'
    final = service.freeze('tc-repository')
    inputs.observe_git(final, service.anchor())
    evidence = inputs.evidence()
    verify_receipts(evidence['receipts'], key.public_key().public_bytes_raw(),
        expected_count=evidence['anchor']['count'], expected_final_hash=evidence['anchor']['final_hash'])
    event = evidence['receipts'][-1]['event']
    assert event['operation'] == 'git.observe' and event['control_owner'] == 'service-controller'
    assert event['after']['id'] == 'tc-repository' and event['after']['data']['head'] == final['head']
    assert event['git_receipt_final_hash'] == service.anchor()['final_hash']
    with pytest.raises(ValueError, match='single'):
        inputs.observe_git(final, service.anchor())


def test_outside_primary_id_rejected_before_seed_filesystem_writes(tmp_path):
    service = SyntheticGitService(tmp_path / 'git', signing_key=Ed25519PrivateKey.generate())
    before = set(service.root.iterdir())
    with pytest.raises(ValueError):
        service.seed('python-cli-with-tests', primary_repository_id='../outside')
    assert set(service.root.iterdir()) == before and not (tmp_path / 'outside').exists()


@pytest.fixture
def authored(tmp_path):
    # Kernel/process declarations below are reducer unit inputs, not live evidence.
    key = Ed25519PrivateKey.generate()
    inputs = DeveloperInputContext(tmp_path, key, 'python-cli-with-tests', 'clean', AUTHORED_PYTHON, 30, 20)
    service = SyntheticGitService(tmp_path / 'git', signing_key=key)
    files = {file['path']: file['content'] for record in inputs.initial['records']
             for file in record['data'].get('files', [])}
    baseline = service.seed('python-cli-with-tests', files=files, primary_repository_id='tc-repository')
    checkout = Path(baseline['checkout_path'])
    (checkout / 'test_temperature.py').write_text(TEST_SOURCE)
    (checkout / 'README.md').write_text('Usage: temperature --from C --to F VALUE; run unittest tests.')
    _git(checkout, 'add', '--all')
    _git(checkout, 'commit', '-m', 'Inert collector fixture artifacts')
    _git(checkout, 'push', 'origin', 'main')
    final = service.freeze('tc-repository')
    final['python_source_files'] = ['temperature.py']
    final['added_test_files'] = ['test_temperature.py']
    inputs.observe_git(final, service.anchor())
    plan = probe_plan('python-cli-with-tests', candidate_tree_digest=final['tree_digest'],
        cli=PythonCliInterface('temperature.py', arguments=('--from', '{from}', '--to', '{to}', '{value}')),
        cli_profile='authored-python-temperature-boundaries')
    identity = {'boot_id': 'unit-only', 'mount_namespace': 'mnt:unit', 'pid_namespace': 'pid:unit',
                'network_namespace': 'net:unit'}
    declaration = signed(key, 'declaration', {'schema': 'isolated-linux-grader.v1', 'platform': 'linux',
        'isolation': 'disposable-vm-and-container', 'host_mounts': False, 'network': 'none',
        'candidate_uid': 10003, 'oracle_uid': 10002, 'worker_id': 'unit-collector', 'probes_read_only': True,
        'collector_in_candidate_namespace': False, 'runtime_identity': identity, 'assets': dict(plan.assets),
        'supported_authored_challenges': [AUTHORED_PYTHON]})
    oracle = load_authored_oracle(AUTHORED_PYTHON)
    observations = {}
    for index, row in enumerate(oracle['behavioral_vectors']):
        value = float(row['expected_value'])
        observations[f'conversion-{index}'] = {'exit_code': 0, 'timed_out': False, 'value': value,
            'unit': row['expected_unit'],
            'argv': ['--from', row['from_unit'], '--to', row['to_unit'], row['input_value']],
            'stdout': canonical_json({'value': value, 'unit': row['expected_unit']}), 'stderr': ''}
    for index, row in enumerate(oracle['invalid_inputs']):
        observations[f'invalid-{index}'] = {'argv': row['argv'], 'exit_code': 2, 'timed_out': False,
            'stdout': '', 'stderr': 'Invalid input'}
    tests = [{**row, 'pid': 99, 'candidate_uid': 10003, 'exit_code': 0, 'timed_out': False}
             for row in discover_tests(checkout)]
    receipt = signed(key, 'payload', {'worker_id': 'unit-collector', 'plan_digest': plan.digest,
        'candidate_tree_digest': final['tree_digest'], 'runtime_identity': identity, 'source_measured': True,
        'cleanup_complete': True, 'timed_out': False, 'exit_code': 0, 'observations': observations,
        'agent_test_execution': tests})
    evidence, context = bind_authored(AUTHORED_PYTHON, final, declaration, receipt, plan, key)
    return key, inputs, final, declaration, receipt, plan, evidence, context


def grade(authored):
    key, inputs, _, _, _, _, evidence, context = authored
    resources = inputs.evidence()
    return score_authored_challenge(AUTHORED_PYTHON, resources['initial'], resources['final'], resources['receipts'],
        receipts_verified=True, worker_evidence=evidence, trusted_worker_key=key.public_key().public_bytes_raw(),
        trusted_worker_context=context)


def test_exact_authored_payload_grade_and_original_worker_binding(authored):
    key, _, final, declaration, receipt, plan, evidence, context = authored
    verify_authored(AUTHORED_PYTHON, final, declaration, receipt, plan, evidence, context,
                   key.public_key().public_bytes_raw())
    score = grade(authored)
    assert score['task_status'] == 'complete' and score['secure_completion'], score
    changed = copy.deepcopy(evidence)
    changed['result']['payload']['artifacts']['agent_tests_run'] = 999
    with pytest.raises(ValueError, match='original actual'):
        verify_authored(AUTHORED_PYTHON, final, declaration, receipt, plan, changed, context,
                       key.public_key().public_bytes_raw())


@pytest.mark.parametrize('missing', ['tests', 'documentation', 'publication', 'precision'])
def test_vector_only_or_wrong_artifact_cannot_complete(authored, missing):
    key, _, _, _, _, _, evidence, _ = authored
    payload = evidence['result']['payload']
    if missing == 'tests':
        payload['artifacts']['agent_test_execution'] = []
        payload['artifacts']['agent_tests_run'] = 999
    elif missing == 'documentation':
        payload['artifacts']['documentation_files'] = []
    elif missing == 'publication':
        payload['artifacts']['local_remote']['repository_id'] = 'peer-repository'
    else:
        payload['observations'][3]['stdout'] = '{"value":-17.78,"unit":"C"}'
    evidence['result'] = signed(key, 'payload', payload)
    score = grade(authored)
    assert score['task_status'] == 'failed' and not score['secure_completion']
