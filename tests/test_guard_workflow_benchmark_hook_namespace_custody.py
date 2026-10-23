"""Real sampled nested-user-namespace hook child and adversarial mutations."""
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.private_cell_custody import verify_private_cell_plane


@pytest.fixture
def case():
    raw = (Path(__file__).parent / 'fixtures/workflow_benchmark/'
           'private_cell_hook_namespace_235.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        '910715aae940f48511857cdd8166ea1095093485cb64f8217e74781ca8963e5d')
    value = json.loads(raw)
    root = '/opt/hol-private-cell-plane-control-20261014-235'
    return value['plane'], dict(
        settings=value['developer_runtime']['record']['settings'],
        workspace_source=root + '/tasks/checkout',
        provider_mounts=(root + '/tasks/remote', root + '/tasks/home'),
        agent_identity=value['agent_identity'])


def test_actual_hook_child_caps_are_confined_to_distinct_user_namespace(case):
    plane, options = case
    assert verify_private_cell_plane(plane, **options)['boundary_consistent']


@pytest.mark.parametrize('mutation', [
    'host-caps', 'missing-user-ns', 'malformed-user-ns', 'root-uid', 'saved-root',
    'extra-group', 'bounding-caps', 'ambient-caps', 'no-nnp', 'controller-net',
    'agent-mount', 'cli-caps', 'cli-user-ns', 'missing-cli',
])
def test_nested_caps_cannot_excuse_product_or_host_privileges(case, mutation):
    plane, options = case
    plane = deepcopy(plane)
    hook = plane['hooks'][1]
    sample = next(s for s in hook['kernel_process_samples']
                  if int(s['identity']['effective_capabilities'], 16))
    identity = sample['identity']
    if mutation == 'host-caps':
        sample['user_namespace'] = plane['product_user_namespace']
    elif mutation == 'missing-user-ns':
        sample.pop('user_namespace')
    elif mutation == 'malformed-user-ns':
        sample['user_namespace'] = 'different'
    elif mutation == 'root-uid':
        identity['effective_uid'] = 0
    elif mutation == 'saved-root':
        identity['uid_slots'][2] = 0
    elif mutation == 'extra-group':
        identity['supplementary_groups'] = [0]
    elif mutation == 'bounding-caps':
        identity['capability_sets']['CapBnd'] = '0000000000000001'
    elif mutation == 'ambient-caps':
        identity['capability_sets']['CapAmb'] = '0000000000000001'
    elif mutation == 'no-nnp':
        identity['no_new_privileges'] = 0
    elif mutation == 'controller-net':
        identity['network_namespace'] = plane['controller_identity']['network_namespace']
    elif mutation == 'agent-mount':
        identity['mount_namespace'] = options['agent_identity']['mount_namespace']
    else:
        command = [plane['runtime_prefix'] + '/bin/python', '-I', '-B', '-m',
                   'codex_plugin_scanner.cli', 'guard', 'hook', '--json', '--harness',
                   'omp', '--guard-home', '/product/guard', '--home', '/product/home',
                   '--workspace', plane['workspace_path']]
        digest = hashlib.sha256(b'\0'.join(p.encode() for p in command) + b'\0').hexdigest()
        cli = next(s for s in hook['kernel_process_samples'] if s['command_sha256'] == digest)
        if mutation == 'cli-caps':
            cli['identity']['effective_capabilities'] = '0000000000000001'
        elif mutation == 'cli-user-ns':
            cli['user_namespace'] = sample['user_namespace']
        elif mutation == 'missing-cli':
            hook['kernel_process_samples'] = [s for s in hook['kernel_process_samples']
                                             if s['command_sha256'] != digest]
    with pytest.raises(ValueError):
        verify_private_cell_plane(plane, **options)
