"""Campaign identity and namespace binding; synthetic records are never live evidence."""
import base64
from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet.benchmark import installed_guard, local_campaign, native_product_container
from ci.gauntlet.benchmark.campaign_product_custody import bind_product_report
from ci.gauntlet.benchmark.contracts import canonical_json
from tests.test_guard_workflow_benchmark_local_campaign import freeze
from tests.test_guard_workflow_benchmark_product_custody import fixture, sign


def test_isolated_freeze_hashes_prefix_without_root_candidate_probe(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('candidate execution on controller is forbidden')
    monkeypatch.setattr(installed_guard, 'inspect_installed_guard', forbidden)
    seen = []
    def inert(prefix):
        seen.append(prefix)
        return {'digest': 'a' * 64}
    monkeypatch.setattr(native_product_container, 'root_prefix_inventory', inert)
    monkeypatch.setattr(local_campaign, 'freeze_isolation', lambda runtime: {'unit_only': True})
    prefix = tmp_path / 'installed'
    prefix.mkdir()
    (prefix / 'pyvenv.cfg').write_text('home = /usr/bin\n')
    root, _ = freeze(tmp_path, protected=True, isolated=True, guard={
        'guard_python': str(prefix / 'bin/python'), 'guard_source_sha': 'b' * 40, 'product_isolated': True})
    from ci.gauntlet.benchmark.contracts import strict_json_loads
    config = strict_json_loads((root / 'frozen.json').read_bytes())
    assert seen == [prefix]
    assert config['identities']['isolated-product-prefix-digest'] == 'a' * 64
    assert 'installed-guard-public-identity' not in config['identities']


@pytest.mark.parametrize('flag,isolated', [('true', True), (1, True), (True, False)])
def test_invalid_product_lane_fails_before_probes_or_inference(tmp_path, flag, isolated):
    with pytest.raises(ValueError, match=r'product isolation|product.*explicit'):
        freeze(tmp_path, protected=True, isolated=isolated, guard={
            'guard_python': str(tmp_path / 'prefix/bin/python'),
            'guard_source_sha': 'b' * 40, 'product_isolated': flag})


def bound_fixture(tmp_path):
    key, record = fixture()
    prefix = tmp_path / 'prefix'
    root = tmp_path / 'attempt'
    root.mkdir()
    plane = record['product_plane']
    mounts = plane['observations'][0]['mounts']
    mounts[0].update(source=str(prefix), destination=str(prefix))
    for row in mounts[1:4]:
        row['source'] = str(root / 'product-runtime' / Path(row['destination']).name)
    mounts[-1]['source'] = str(root / 'sockets')
    agent = {'boot_id': 'boot', 'mount_namespace': 'agent-mnt',
             'pid_namespace': 'agent-pid', 'network_namespace': 'agent-net'}
    report = {'product_isolated': True, 'execution_valid': False,
        'producer_public_key': base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        'guard_identity': {'product_self_report': plane['product_identity_claim'], 'authenticated': False},
        'isolation': {'record': {'agent': agent}}, 'native_audit': sign(key, record)}
    (root / 'transport-events.json').write_text(canonical_json(record['transport_observations']))
    config = {'runtime': {'guard_python': str(prefix / 'bin/python'), 'guard_source_sha': 'b' * 40},
        'identities': {'isolated-product-prefix-digest': 'a' * 64},
        'isolation_tuple': {'image_id': 'sha256:' + 'c' * 64,
            'controller': {name: value for name, value in plane['controller_identity'].items()
                           if name in {'boot_id', 'mount_namespace', 'pid_namespace', 'network_namespace'}}}}
    return key, record, report, config, root


def test_attempt_binds_external_prefix_private_mounts_and_agent_namespaces(tmp_path):
    _, _, report, config, root = bound_fixture(tmp_path)
    result = bind_product_report(config, report, attempt_path=root)
    assert result['custody_verified'] is True
    assert result['product_claims_authenticated'] is False
    assert result['qualification_eligible'] is False


def test_signed_mount_for_another_attempt_is_rejected(tmp_path):
    key, record, report, config, root = bound_fixture(tmp_path)
    record['product_plane']['observations'][0]['mounts'][-1]['source'] = '/another-attempt/sockets'
    report['native_audit'] = sign(key, record)
    with pytest.raises(ValueError, match='exact private/public attempt'):
        bind_product_report(config, report, attempt_path=root)


def test_signed_audit_cannot_substitute_a_different_transport_log(tmp_path):
    _, _, report, config, root = bound_fixture(tmp_path)
    (root / 'transport-events.json').write_text('[]')
    with pytest.raises(ValueError, match='retained frontdoor transport'):
        bind_product_report(config, report, attempt_path=root)


def test_both_approval_agent_namespaces_are_checked(tmp_path):
    _, record, report, config, root = bound_fixture(tmp_path)
    second = deepcopy(report['isolation'])
    second['record']['agent']['mount_namespace'] = record['product_plane']['observations'][0]['identity'][
        'mount_namespace']
    report['approval_phase_isolations'] = [report['isolation'], second]
    with pytest.raises(ValueError, match='shares agent namespace'):
        bind_product_report(config, report, attempt_path=root)


def test_failed_startup_cannot_claim_measured_product_custody(tmp_path):
    _, _, report, config, root = bound_fixture(tmp_path)
    report['native_audit'] = None
    assert bind_product_report(config, report, attempt_path=root)['custody_verified'] is False
    report['execution_valid'] = True
    with pytest.raises(ValueError, match='lacks actual product custody'):
        bind_product_report(config, report, attempt_path=root)
