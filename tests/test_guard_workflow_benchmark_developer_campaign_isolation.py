"""Typed binding predicate units; these declarations are not actual VM evidence."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.developer_campaign_isolation import bind_developer_isolation
from ci.gauntlet.benchmark.model_endpoint import model_endpoint


def fixture(path):
    path.mkdir()
    source = Path(__file__).parents[1] / 'ci/gauntlet/benchmark'
    runtime = {'isolated': True, 'bun': '/public/bun',
               'sdk_root': '/public/node_modules/@oh-my-pi/pi-coding-agent'}
    controller = {'boot_id': 'unit-boot', 'mount_namespace': 'mnt:[unit-controller]',
                  'pid_namespace': 'pid:[unit-controller]', 'network_namespace': 'net:[unit-controller]'}
    assets = {'sdk': {'unit': 'sdk'}, 'bun': {'unit': 'bun'}}
    helpers = ('developer_omp_episode.ts', 'developer_model_relay.py',
               'developer_provider_relay.py', 'service_relay.py')
    identities = {str(source / name): hashlib.sha256((source / name).read_bytes()).hexdigest() for name in helpers}
    public = {name: identities[str(source / name)] for name in helpers} | {'episode.json': 'unit-config-sha'}
    root = path / 'runtime'
    mounts = [('/owned/checkout', '/runtime/home/project', True), ('/owned/bare', '/owned/bare', True),
        ('/public/node_modules', '/sdk/node_modules', False), ('/public/bun', '/runtime/bun', False),
        (str(root / 'public'), '/runtime/public', False), (str(root / 'home'), '/runtime/home', True),
        (str(root / 'agent'), '/runtime/agent', True), (str(root / 'model.sock'), '/runtime/model.sock', False),
        (str(path / 'rs'), '/runtime/resources', False)]
    agent = {'boot_id': 'unit-boot', 'mount_namespace': 'mnt:[unit-agent]', 'pid_namespace': 'pid:[unit-agent]',
        'network_namespace': 'net:[unit-agent]', 'effective_uid': 10001, 'effective_gid': 10001,
        'effective_capabilities': '0000000000000000', 'no_new_privileges': 1}
    key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    raw = {'public_key': public_key, 'base_workflow_id': 'fix-failing-node-test',
        'model_budget_evidence': {'provider': model_endpoint()},
        'baseline': {'checkout_path': '/owned/checkout', 'remote_path': '/owned/bare'},
        'execution_measurements': {'controller': controller, 'frozen_assets': assets, 'post_assets': assets,
            'public_assets': public, 'public_assets_unchanged': True, 'agent': agent,
            'container': {'image': 'sha256:unit-image', 'user': '10001:10001', 'network': 'none', 'readonly_root': True,
                'mounts': [{'Type': 'bind', 'Source': origin, 'Destination': target, 'RW': writable}
                           for origin, target, writable in mounts]}}}
    config = {'runtime': runtime, 'identities': identities,
        'isolation_tuple': {'controller': controller, **assets, 'image_id': 'sha256:unit-image'}}
    report = {'producer_public_key': public_key, 'execution_lane': 'isolated-linux', 'execution_valid': True}
    return key, raw, config, report


def write(path, key, raw):
    (path / 'diagnostic-report.json').write_text(canonical_json({'report': raw,
        'signature': base64.b64encode(key.sign(canonical_json(raw).encode())).decode()}))


def test_binding_accepts_only_exact_declared_process_and_mount_predicate(tmp_path):
    path = tmp_path / 'attempt'
    key, raw, config, report = fixture(path)
    write(path, key, raw)
    bind_developer_isolation(config, report, attempt_path=path)


def test_frozen_endpoint_binding_rejects_port_or_alias_substitution_even_on_invalid_episode(tmp_path):
    path = tmp_path / 'attempt'
    key, raw, config, report = fixture(path)
    write(path, key, raw)
    report['execution_valid'] = False
    for url in ['http://host.lima.internal:8002/v1', 'http://localhost:8001/v1']:
        config['runtime']['base_url'] = url
        with pytest.raises(ValueError, match='exact frozen controller declaration'):
            bind_developer_isolation(config, report, attempt_path=path)


@pytest.mark.parametrize('failure', ['key', 'assets', 'uid', 'namespace', 'private-mount', 'writable-sdk'])
def test_signed_but_wrong_measurement_cannot_match_frozen_boundary(tmp_path, failure):
    path = tmp_path / 'attempt'
    key, raw, config, report = fixture(path)
    measurement = raw['execution_measurements']
    if failure == 'key':
        report['producer_public_key'] = 'different-authority'
    elif failure == 'assets':
        measurement['post_assets'] = {'sdk': {'changed': True}, 'bun': measurement['frozen_assets']['bun']}
    elif failure == 'uid':
        measurement['agent']['effective_uid'] = 0
    elif failure == 'namespace':
        measurement['agent']['mount_namespace'] = config['isolation_tuple']['controller']['mount_namespace']
    elif failure == 'private-mount':
        measurement['container']['mounts'].append({'Type': 'bind', 'Source': '/private/world.db',
            'Destination': '/model-readable-world.db', 'RW': False})
    else:
        mount = next(row for row in measurement['container']['mounts'] if row['Destination'] == '/sdk/node_modules')
        mount['RW'] = True
    write(path, key, raw)
    with pytest.raises(ValueError):
        bind_developer_isolation(config, report, attempt_path=path)


@pytest.mark.parametrize('failure', ['direct-upstream', 'private-prefix', 'missing-gate'])
def test_protected_agent_cannot_mount_private_product_or_direct_world(tmp_path, failure):
    path = tmp_path / 'attempt'
    key, raw, config, report = fixture(path)
    raw['adapter_id'] = 'hol-guard'
    measurement = raw['execution_measurements']
    source = Path(__file__).parents[1] / 'ci/gauntlet/benchmark'
    for name in ('builtin_guard_bridge.ts', 'contained_exec_relay.py'):
        sha = hashlib.sha256((source / name).read_bytes()).hexdigest()
        measurement['public_assets'][name] = sha
        config['identities'][str(source / name)] = sha
    mounts = measurement['container']['mounts']
    mounts[:] = [row for row in mounts if row['Destination'] != '/runtime/resources']
    mounts += [{'Type': 'bind', 'Source': str(path / origin), 'Destination': target, 'RW': False}
               for origin, target in (('front', '/runtime/resources'), ('hooks', '/runtime/guard-hook'),
                                      ('sdk-gate', '/runtime/sdk-gate'))]
    if failure == 'direct-upstream':
        next(row for row in mounts if row['Destination'] == '/runtime/resources')['Source'] = str(path / 'rs')
    elif failure == 'private-prefix':
        mounts.append({'Type': 'bind', 'Source': '/private/native-prefix',
                       'Destination': '/agent/native-prefix', 'RW': False})
    else:
        mounts[:] = [row for row in mounts if row['Destination'] != '/runtime/sdk-gate']
    write(path, key, raw)
    with pytest.raises(ValueError, match='undeclared controller/oracle/product'):
        bind_developer_isolation(config, report, attempt_path=path)
