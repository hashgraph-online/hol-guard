"""Explicit package pins must survive transport and inert verification."""
import json
import pytest

from ci.gauntlet.benchmark import campaign_execution, ci_runner_config
from ci.gauntlet.benchmark.contracts import digest
from tests.test_guard_workflow_benchmark_ci_runner import private_specimen, write


def specimen(tmp_path):
    root, path, config = private_specimen(tmp_path)
    config.update(schema='gauntlet-ci-runner.v5', state_layout='compact-v1')
    conformance = root / 'conformance.json'
    conformance.write_text('{}')
    config['assets']['conformance'] = {
        'path': 'conformance.json', 'kind': 'file', 'sha256': write(conformance, {})}
    config['runtime']['guard_package_version'] = '3.46.0'
    write(path, config)
    return root, path, config


def test_explicit_version_is_relocated_and_forwarded_to_business_execution(tmp_path):
    root, path, config = specimen(tmp_path)
    loaded = ci_runner_config.load_config(path, expected_digest=digest(config), asset_root=root)
    assert loaded['runtime']['guard_package_version'] == '3.46.0'
    assert loaded['attempt_layout'] == 'compact-v1'
    cell = next(row for row in loaded['campaign']['inventory'] if row['protected'] and row['variant'] == 'clean')
    calls = []
    campaign_execution.execute_cell(tmp_path / 'attempt', cell, loaded['runtime'],
        loaded['campaign']['budgets'], runner=lambda **options: calls.append(options), execution_lane='unit-scheduling')
    assert len(calls) == 1 and calls[0]['guard_package_version'] == '3.46.0'
    assert calls[0]['guard_source_sha'] == config['runtime']['guard_source_sha']


@pytest.mark.parametrize('version', [None, True, 3.46, '', '3.46', 'latest', '3.46.0\n', '3.46.0;allow'])
def test_new_schema_refuses_missing_or_nonliteral_versions(tmp_path, version):
    root, path, config = specimen(tmp_path)
    if version is None:
        config['runtime'].pop('guard_package_version')
    else:
        config['runtime']['guard_package_version'] = version
    write(path, config)
    with pytest.raises(ValueError):
        ci_runner_config.load_config(path, expected_digest=digest(config), asset_root=root)


def test_version_pin_cannot_enter_an_older_schema_or_change_after_freeze(tmp_path):
    root, path, config = specimen(tmp_path)
    original = digest(config)
    config['schema'] = 'gauntlet-ci-runner.v4'
    write(path, config)
    with pytest.raises(ValueError):
        ci_runner_config.load_config(path, expected_digest=digest(config), asset_root=root)
    config['schema'] = 'gauntlet-ci-runner.v5'
    config['runtime']['guard_package_version'] = '3.46.1'
    write(path, config)
    with pytest.raises(ValueError, match='external pin'):
        ci_runner_config.load_config(path, expected_digest=original, asset_root=root)


def test_manifest_version_check_is_inert_and_rejects_mismatches(tmp_path):
    from ci.gauntlet.benchmark.product_version import verify_installed_version

    path = tmp_path / 'lib/python3.12/site-packages/codex_plugin_scanner/_native/runtime-manifest.json'
    path.parent.mkdir(parents=True)
    manifest = {'package_version': '3.46.0', 'source_sha': 'a' * 40, 'runtime_sha256': 'b' * 64}
    path.write_text(json.dumps(manifest))
    assert verify_installed_version(tmp_path, version='3.46.0', source_sha='a' * 40,
                                    native_sha256='b' * 64) == '3.46.0'
    for mutation in ({'package_version': '3.43.1'}, {'source_sha': 'c' * 40}, {'runtime_sha256': 'd' * 64}):
        path.write_text(json.dumps({**manifest, **mutation}))
        with pytest.raises(ValueError):
            verify_installed_version(tmp_path, version='3.46.0', source_sha='a' * 40,
                                     native_sha256='b' * 64)
    path.write_text('{"package_version":"3.46.0","package_version":"3.43.1"}')
    with pytest.raises(ValueError, match='duplicate'):
        verify_installed_version(tmp_path, version='3.46.0', source_sha='a' * 40, native_sha256='b' * 64)


def test_offline_version_check_never_uses_the_product_claim_as_its_pin():
    from ci.gauntlet.benchmark.product_version import verify_claim_version

    claim = {'package_version': '3.46.0', 'manifest': {'package_version': '3.46.0'},
             'capabilities': {'runtime_version': '3.46.0'}}
    verify_claim_version(claim, '3.46.0')
    with pytest.raises(ValueError):
        verify_claim_version(claim, '3.43.1')
    claim['manifest']['package_version'] = '3.43.1'
    with pytest.raises(ValueError):
        verify_claim_version(claim, '3.46.0')


def test_same_version_pin_reaches_developer_and_approval_drivers(tmp_path):
    from ci.gauntlet.benchmark.approval_campaign import run_approval_cell
    from ci.gauntlet.benchmark.developer_campaign import developer_pilot_arguments

    root, path, config = specimen(tmp_path)
    loaded = ci_runner_config.load_config(path, expected_digest=digest(config), asset_root=root)
    runtime, budgets = loaded['runtime'], loaded['campaign']['budgets']
    cell = {'group': 'developer', 'workflow_id': 'python-cli-with-tests', 'variant': 'clean', 'protected': True}
    options = developer_pilot_arguments(tmp_path / 'developer', cell, runtime, budgets)
    assert options['guard_package_version'] == '3.46.0'
    assert options['guard_private_cell'] == runtime['guard_private_cell']
    calls = []

    class BeforeExecution(Exception):
        pass

    def runner(**options):
        calls.append(options)
        raise BeforeExecution

    cell = {'group': 'approval', 'variant': 'sales-denied',
            'workflow_id': 'business-sales-lead-qualification', 'protected': True}
    with pytest.raises(BeforeExecution):
        run_approval_cell(tmp_path / 'approval', cell, runtime, budgets,
                          runner=runner, execution_lane='unit-scheduling')
    assert len(calls) == 1 and calls[0]['guard_package_version'] == '3.46.0'


def test_signed_custody_still_rejects_wrong_or_missing_package_version():
    from ci.gauntlet.benchmark.product_custody import verify_product_audit
    from tests.test_guard_workflow_benchmark_product_custody import fixture, sign

    key, record = fixture()
    claim = {'package_version': '3.46.0', 'manifest': {'package_version': '3.46.0'},
             'capabilities': {'runtime_version': '3.46.0'}}
    record['product_plane']['product_identity_claim'] = claim
    options = {'trusted_public_key': key.public_key().public_bytes_raw(),
               'expected_prefix_digest': 'a' * 64, 'expected_source_sha': 'b' * 40,
               'expected_image_id': 'sha256:' + 'c' * 64, 'expected_package_version': '3.46.0'}
    summary = verify_product_audit(sign(key, record), **options)
    assert summary['custody_verified'] is True and summary['product_claims_authenticated'] is False
    claim['manifest']['package_version'] = '3.43.1'
    with pytest.raises(ValueError, match='frozen version'):
        verify_product_audit(sign(key, record), **options)
    record['product_plane']['product_identity_claim'] = {}
    with pytest.raises(ValueError, match='version claim'):
        verify_product_audit(sign(key, record), **options)
