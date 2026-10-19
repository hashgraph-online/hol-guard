"""Campaign routing/custody regressions; injected fixtures never claim inference."""
import json

import pytest

from ci.gauntlet.benchmark import campaign_execution, local_campaign
from ci.gauntlet.benchmark.campaign import DEFAULT_BUDGETS, compile_campaign
from ci.gauntlet.benchmark.catalog import get_workflow
from tests.test_guard_workflow_benchmark_developer_campaign import envelope_fixture


@pytest.fixture(autouse=True)
def unit_isolation(monkeypatch):
    # This suite exercises signed scheduling fixtures, never kernel identity.
    monkeypatch.setattr(local_campaign, 'freeze_isolation', lambda runtime: None)
    monkeypatch.setattr(local_campaign, 'verify_isolation_freeze', lambda config: None)


def freeze(tmp_path, *, protected=False, endpoint='http://host.lima.internal:8001/v1', cache=None):
    bun = tmp_path / 'bun'
    bun.write_bytes(b'unit fixture executable')
    sdk = tmp_path / 'sdk'
    (sdk / 'src').mkdir(parents=True)
    (sdk / 'src' / 'index.ts').write_text('// unit public fixture')
    (sdk / 'package.json').write_text('{"version":"18.4.12"}')
    budgets = {**DEFAULT_BUDGETS, 'model_tokens': 100000, 'tool_operations': 200}
    campaign = compile_campaign([get_workflow('fix-failing-node-test')],
                                repetitions=1, budgets=budgets)
    cell = next(row for row in campaign['inventory']
                if row['variant'] == 'text-injection' and row['protected'] == protected)
    runtime = {'bun': str(bun), 'sdk_root': str(sdk), 'model_id': 'unit-provider',
               'base_url': endpoint, 'protected_adapter': 'example-policy',
               'isolated': True, 'artifacts': []}
    if cache is not None:
        runtime['zod_cache'] = str(cache)
    root = tmp_path / 'campaign'
    preview = local_campaign.freeze_local_campaign(root, campaign=campaign,
        episode_ids=[cell['id']], runtime=runtime, max_episodes=1,
        execution_lane='unit-scheduling')
    return root, preview, cell


def test_developer_campaign_preserves_actual_unsafe_history_and_unknown_cost(tmp_path):
    root, preview, _ = freeze(tmp_path)
    assert preview['preview']['runnable_episodes'] == 1
    assert preview['preview']['maximum_controller_seconds'] == 2400
    calls = []

    def runner(**kwargs):
        calls.append(kwargs)
        envelope_fixture(kwargs['root'], unsafe=True)

    result = local_campaign.run_local_campaign(root,
        preview_digest=preview['preview_digest'], runner=runner)
    assert len(calls) == 1 and calls[0]['task'] == 'fix-failing-node-test'
    state = local_campaign.load_local_campaign(root)
    finish = next(row['event'] for row in state['ledger'] if row['event']['type'] == 'finish')
    assert finish['report']['group'] == 'developer'
    assert finish['report']['score']['security_status'] == 'violated'
    assert finish['report']['score']['evidence_validity'] == 'invalid'
    assert finish['charged_tokens'] == 100000
    assert not result['qualification_eligible']
    path = root / 'attempts' / f'{finish["episode_id"]}.attempt-0' / 'model-budget-evidence.json'
    payload = json.loads(path.read_text())
    payload['observed_tokens'] = 1
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match='retained state/usage/transport'):
        local_campaign.load_local_campaign(root)


@pytest.mark.parametrize('protected,endpoint,reason', [
    (True, 'http://host.lima.internal:8001/v1', 'conformance'),
])
def test_unsupported_developer_cell_never_invokes_runner(tmp_path, protected, endpoint, reason):
    root, preview, _ = freeze(tmp_path, protected=protected, endpoint=endpoint)
    assert preview['preview']['runnable_episodes'] == 0
    local_campaign.run_local_campaign(root, preview_digest=preview['preview_digest'],
        runner=lambda **kwargs: pytest.fail('unsupported executor invoked'))
    state = local_campaign.load_local_campaign(root)
    assert reason in state['ledger'][0]['event']['reason']


@pytest.mark.parametrize('endpoint', ['http://127.0.0.1:8003/v1', 'http://remote.test:8002/v1'])
def test_invalid_developer_upstream_rejected_at_freeze_without_runner(tmp_path, monkeypatch, endpoint):
    calls = []
    monkeypatch.setattr('ci.gauntlet.benchmark.developer_campaign.run_developer_pilot',
                        lambda **kwargs: calls.append(kwargs))
    with pytest.raises(ValueError, match='local model endpoints'):
        freeze(tmp_path, endpoint=endpoint)
    assert not calls
    assert not (tmp_path / 'campaign/frozen.json').exists()


@pytest.mark.parametrize('port', [8001, 8002])
def test_declared_loopback_alias_is_runnable_and_exact_url_is_frozen(tmp_path, port):
    endpoint = f'http://127.0.0.1:{port}/v1'
    root, preview, _ = freeze(tmp_path, endpoint=endpoint)
    assert preview['preview']['runnable_episodes'] == 1
    assert local_campaign.load_local_campaign(root)['config']['runtime']['base_url'] == endpoint
    # Preview only: no runner, model or candidate execution supplies a positive outcome.


def test_live_developer_routing_cannot_receive_injected_callback(tmp_path, monkeypatch):
    seen = []

    def entry(path, cell, runtime, budgets, *, runner, execution_lane):
        seen.append((runner, execution_lane))
        return {}

    monkeypatch.setattr('ci.gauntlet.benchmark.developer_campaign.run_developer_cell', entry)
    campaign_execution.execute_cell(tmp_path,
        {'workflow_id': 'python-cli-with-tests', 'group': 'base'}, {}, {},
        runner=lambda: pytest.fail('injected callback'), execution_lane='live')
    assert seen == [(None, 'live')]


def test_developer_cell_cannot_substitute_business_report(tmp_path):
    root, _, cell = freeze(tmp_path)
    config = json.loads((root / 'frozen.json').read_text())
    report = {'workflow_id': cell['workflow_id'], 'variant': cell['variant'],
              'adapter': 'unprotected', 'model_id': 'unit-provider'}
    with pytest.raises(ValueError, match='developer-specific evidence'):
        local_campaign._bind_report(config, cell, report, attempt_path=tmp_path)


def test_explicit_public_dependency_bytes_cannot_change_after_freeze(tmp_path):
    cache = tmp_path / 'public-cache'
    cache.mkdir()
    (cache / 'metadata.json').write_text('{"fixture":"inert scheduling data"}')
    archive = cache / 'zod-3.23.8.tgz'
    archive.write_bytes(b'never installed or executed by unit fixture')
    root, _, _ = freeze(tmp_path, cache=cache)
    config = local_campaign.load_local_campaign(root)['config']
    assert str(archive) in config['identities']
    archive.write_bytes(b'changed after immutable freeze')
    with pytest.raises(ValueError, match='frozen source, fixture, SDK or runtime bytes changed'):
        local_campaign.load_local_campaign(root)
