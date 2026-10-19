"""Signed measurement reducer conformance, not genuine isolated inference proof."""
import base64
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.local_campaign_custody import (
    CLEANUP_FIELDS,
    bind_isolation,
    cleanup_complete,
    freeze_isolation,
    verify_isolation_freeze,
)
from ci.gauntlet.benchmark.model_endpoint import model_endpoint


@pytest.fixture
def inert_freeze_runtime(monkeypatch):
    from ci.gauntlet.benchmark import business_agent_container, linux_executor, local_campaign_custody

    observed = []
    monkeypatch.setattr(local_campaign_custody.sys, 'platform', 'linux')
    monkeypatch.setattr(local_campaign_custody.os, 'geteuid', lambda: 0)

    def inspect(*arguments):
        observed.append(arguments)
        return SimpleNamespace(stdout=json.dumps([{'Id': business_agent_container.BASE_IMAGE}]))

    monkeypatch.setattr(business_agent_container, '_podman', inspect)
    monkeypatch.setattr(business_agent_container, 'freeze_public_tree', lambda _: {'unit-only-tree': True})
    monkeypatch.setattr(business_agent_container, '_file_identity', lambda _: {'unit-only-binary': True})
    monkeypatch.setattr(linux_executor, '_identity', lambda _: {'unit-only-controller': True})
    original = Path.read_bytes
    binaries = {'/usr/bin/podman', '/usr/sbin/apparmor_parser'}
    monkeypatch.setattr(Path, 'read_bytes', lambda path: b'unit binary identity, never executed'
                        if str(path) in binaries else original(path))
    return {'isolated': True, 'sdk_root': '/unit/node_modules/@oh-my-pi/pi-coding-agent',
            'bun': '/unit/bun', 'base_url': 'http://host.lima.internal:8001/v1'}, observed


@pytest.mark.parametrize('host', ['host.lima.internal', '127.0.0.1'])
@pytest.mark.parametrize('port', [8001, 8002])
def test_isolation_freeze_accepts_only_declared_endpoint_and_keeps_exact_url(inert_freeze_runtime, host, port):
    runtime, observed = inert_freeze_runtime
    runtime['base_url'] = f'http://{host}:{port}/v1'
    frozen = freeze_isolation(runtime)
    assert frozen['model_endpoint'] == model_endpoint(runtime['base_url'])
    assert frozen['qualification_eligible'] is False
    assert len(observed) == 1
    verify_isolation_freeze({'runtime': runtime, 'isolation_tuple': frozen})


@pytest.mark.parametrize('url', ['http://remote.test:8002/v1', 'http://host.lima.internal:8003/v1',
                               'http://user@host.lima.internal:8002/v1', 'http://host.lima.internal:8002/v1/'])
def test_isolation_freeze_rejects_bad_upstream_before_image_inspection(inert_freeze_runtime, url):
    runtime, observed = inert_freeze_runtime
    runtime['base_url'] = url
    with pytest.raises(ValueError, match='local model endpoints'):
        freeze_isolation(runtime)
    assert observed == []


@pytest.mark.parametrize('changed', ['http://host.lima.internal:8002/v1', 'http://127.0.0.1:8001/v1'])
def test_isolation_resume_rejects_changed_endpoint_port_or_alias(inert_freeze_runtime, changed):
    runtime, _observed = inert_freeze_runtime
    frozen = freeze_isolation(runtime)
    runtime['base_url'] = changed
    with pytest.raises(ValueError, match='frozen Linux image, namespaces or public assets changed'):
        verify_isolation_freeze({'runtime': runtime, 'isolation_tuple': frozen})


def test_old_isolation_tuple_cannot_acquire_endpoint_declaration(inert_freeze_runtime):
    runtime, _observed = inert_freeze_runtime
    frozen = freeze_isolation(runtime)
    del frozen['model_endpoint']
    with pytest.raises(ValueError, match='changed'):
        verify_isolation_freeze({'runtime': runtime, 'isolation_tuple': frozen})


def measurements(tmp_path):
    # Deliberately synthetic unit data; no worker/container is launched.
    key = Ed25519PrivateKey.generate()
    sdk = tmp_path / 'node_modules' / '@oh-my-pi' / 'pi-coding-agent'
    bun = tmp_path / 'bun'
    source = Path(__file__).resolve().parents[1] / 'ci' / 'gauntlet' / 'benchmark'
    identities = {str(source / name): hashlib.sha256((source / name).read_bytes()).hexdigest()
                  for name in ('omp_episode.ts', 'business_protocol_recovery.ts',
                               'service_relay.py', 'developer_model_relay.py')}
    identities.update({str(bun): 'b' * 64, str(sdk / 'package.json'): 'c' * 64})
    controller = {'boot_id': 'unit-only-boot', 'mount_namespace': 'mnt:[1]',
                  'pid_namespace': 'pid:[1]', 'network_namespace': 'net:[1]'}
    frozen = {'image_id': 'sha256:' + 'a' * 64, 'controller': controller,
              'sdk': {'tree_digest': 'd' * 64}, 'bun': {'sha256': 'b' * 64}}
    config = {'execution_lane': 'unit-scheduling', 'runtime': {'isolated': True, 'sdk_root': str(sdk),
              'bun': str(bun)}, 'isolation_tuple': frozen, 'identities': identities}
    attempt = tmp_path / 'attempt'
    path = attempt / 'agent-runtime'
    mounts = [(path / 'public', '/runtime/public', 'ro'), (path / 'home', '/runtime/home', 'rw'),
              (path / 'workspace', '/runtime/home/project', 'rw'), (path / 'agent', '/runtime/agent', 'rw'),
              (attempt / 'sockets', '/services', 'ro'), (bun, '/runtime/bun', 'ro'),
              (sdk.parents[1], '/sdk/node_modules', 'ro'), (path / 'model.sock', '/runtime/model.sock', 'ro')]
    assets = {'sdk': frozen['sdk'], 'bun': frozen['bun'], 'public': {'tree_digest': 'e' * 64}}
    record = {'schema_version': '1.0', 'kind': 'isolated-business-agent',
              'image_id': frozen['image_id'], 'observed_image': frozen['image_id'], 'controller': controller,
              'bun_sha256': 'b' * 64, 'sdk_package_sha256': 'c' * 64, 'frozen_assets': assets,
              'post_assets': copy.deepcopy(assets), 'assets_unchanged': True, 'isolation_observed': True,
              'uid': 10001, 'network_mode': 'none', 'cleanup_complete': True, 'cleanup_errors': [],
              'agent': {'boot_id': controller['boot_id'], 'mount_namespace': 'mnt:[2]',
                        'pid_namespace': 'pid:[2]', 'network_namespace': 'net:[2]', 'effective_uid': 10001,
                        'effective_gid': 10001, 'effective_capabilities': '0000000000000000', 'no_new_privileges': 1},
              'public_assets': {name: identities[str(source / name)] for name in
                                ('omp_episode.ts', 'business_protocol_recovery.ts',
                                 'service_relay.py', 'developer_model_relay.py')},
              'mounts': [{'source': str(p), 'destination': d, 'mode': m} for p, d, m in mounts]}
    report = {'execution_valid': True, 'execution_lane': 'isolated-linux', 'adapter': 'unprotected',
              'producer_public_key': base64.b64encode(key.public_key().public_bytes_raw()).decode(),
              'isolation': {'record': record}, **{field: 0 for field in CLEANUP_FIELDS}}
    sign(report, key)
    return config, report, attempt, key


def sign(report, key):
    report['isolation']['signature'] = base64.b64encode(
        key.sign(canonical_json(report['isolation']['record']).encode())).decode()


def test_complete_signed_unit_measurements_match_declared_reducer_schema(tmp_path):
    config, report, attempt, _key = measurements(tmp_path)
    bind_isolation(config, report, attempt_path=attempt)
    assert config['execution_lane'] == 'unit-scheduling'
    assert cleanup_complete(report, isolated=True)


@pytest.mark.parametrize('helper', ['omp_episode.ts', 'business_protocol_recovery.ts',
                                  'service_relay.py', 'developer_model_relay.py'])
@pytest.mark.parametrize('mutation', ['missing', 'changed'])
def test_every_mounted_helper_is_required_and_hash_bound(tmp_path, helper, mutation):
    config, report, attempt, key = measurements(tmp_path)
    assets = report['isolation']['record']['public_assets']
    if mutation == 'missing':
        del assets[helper]
    else:
        assets[helper] = '0'*64
    sign(report, key)
    with pytest.raises(ValueError):
        bind_isolation(config, report, attempt_path=attempt)


@pytest.mark.parametrize('mutation', ['image', 'controller', 'sdk', 'mount-controller', 'shared-namespace',
                                     'missing-namespace', 'assets-changed', 'missing-helper'])
def test_signed_but_wrong_measurement_never_matches_frozen_tuple(tmp_path, mutation):
    config, report, attempt, key = measurements(tmp_path)
    record = report['isolation']['record']
    if mutation == 'image':
        record['image_id'] = 'sha256:' + 'f' * 64
    elif mutation == 'controller':
        record['controller'] = dict(record['controller'], boot_id='other-boot')
    elif mutation == 'sdk':
        record['frozen_assets']['sdk'] = {'tree_digest': 'f' * 64}
    elif mutation == 'mount-controller':
        record['mounts'].append({'source': str(attempt / 'world.db'), 'destination': '/controller.db', 'mode': 'ro'})
    elif mutation == 'shared-namespace':
        record['agent']['mount_namespace'] = record['controller']['mount_namespace']
    elif mutation == 'missing-namespace':
        del record['agent']['mount_namespace']
    elif mutation == 'assets-changed':
        record['assets_unchanged'] = False
    else:
        del record['public_assets']['omp_episode.ts']
    sign(report, key)
    with pytest.raises(ValueError):
        bind_isolation(config, report, attempt_path=attempt)


def test_altered_isolation_signature_cannot_be_treated_as_measurement(tmp_path):
    config, report, attempt, _key = measurements(tmp_path)
    report['isolation']['record']['uid'] = 0
    with pytest.raises(InvalidSignature):
        bind_isolation(config, report, attempt_path=attempt)


@pytest.mark.parametrize('field', CLEANUP_FIELDS)
def test_isolated_cleanup_requires_each_counter_not_missing_or_active(tmp_path, field):
    _config, report, _attempt, _key = measurements(tmp_path)
    del report[field]
    assert not cleanup_complete(report, isolated=True)
    report[field] = 1
    assert not cleanup_complete(report, isolated=True)


def test_shared_historical_report_cannot_be_upgraded_by_requested_flag(tmp_path):
    config, report, attempt, _key = measurements(tmp_path)
    report['execution_lane'] = 'shared-uid-diagnostic'
    with pytest.raises(ValueError, match='lane differs'):
        bind_isolation(config, report, attempt_path=attempt)
