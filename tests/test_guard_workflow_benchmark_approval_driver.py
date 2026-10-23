"""Unit driver integration only: signed fixture state, no model/namespace claims."""
import base64
import hashlib
import json

import pytest

from ci.gauntlet.benchmark import campaign_execution, local_campaign
from ci.gauntlet.benchmark.approval_campaign import run_approval_cell
from ci.gauntlet.benchmark.approval_oracles import score_approval_variant
from ci.gauntlet.benchmark.campaign import DEFAULT_BUDGETS, compile_campaign
from ci.gauntlet.benchmark.catalog import get_workflow, load_approval_variants
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.world import World
from tests.test_guard_workflow_benchmark_approval_campaign import negative_scheduling_callback

SALES = 'business-sales-lead-qualification'


def freeze_unit(tmp_path, monkeypatch, *, mixed=False, token_cap=1000000):
    # Physical probes are mocked only for this explicitly frozen unit lane.
    # All receipt signatures, oracle checks and driver ledger audits remain real.
    monkeypatch.setattr(local_campaign, 'freeze_isolation', lambda runtime: {'unit-scheduling-only': True})
    monkeypatch.setattr(local_campaign, 'verify_isolation_freeze', lambda config: None)
    bun = tmp_path / 'public-bun'
    bun.write_text('unit scheduling placeholder, never executed')
    sdk = tmp_path / 'public-sdk'
    (sdk / 'src').mkdir(parents=True)
    (sdk / 'src/index.ts').write_text('// unit scheduling placeholder, never executed')
    (sdk / 'package.json').write_text('{"version":"18.4.12"}')
    variant = next(v for v in load_approval_variants() if v['id'] == 'sales-denied')
    budgets = {**DEFAULT_BUDGETS, 'model_tokens': 10000, 'max_retries': 0, 'campaign_tokens': token_cap}
    campaign = compile_campaign([get_workflow(SALES)], approval_variants=[variant], budgets=budgets)
    approval = next(row for row in campaign['inventory'] if row['group'] == 'approval' and not row['protected'])
    cells = [approval]
    if mixed:
        cells.append(next(row for row in campaign['inventory'] if row['group'] == 'base'
                          and row['variant'] == 'clean' and not row['protected']))
    runtime = {'bun': str(bun), 'sdk_root': str(sdk), 'model_id': 'unit-model',
               'base_url': 'http://127.0.0.1:8001/v1', 'protected_adapter': 'example-policy',
               'isolated': True, 'artifacts': []}
    root = tmp_path / 'campaign'
    preview = local_campaign.freeze_local_campaign(root, campaign=campaign,
        episode_ids=[cell['id'] for cell in cells], runtime=runtime, max_episodes=len(cells),
        execution_lane='unit-scheduling')
    return root, preview, cells, runtime, budgets


def signed_fixture_runner(calls, *, unsafe=False, cleanup=True, phase_cleanup=None):
    def runner(**kwargs):
        calls.append(kwargs)
        key, raw = negative_scheduling_callback(**kwargs)
        if unsafe:
            world = World.create(kwargs['root'] / 'world.db', raw['initial_snapshot'], signing_key=key)
            world.call('mail.create', {'collection': 'mail.outbox', 'record_id': 'undelegated-effect',
                'data': {'body': 'Signed fixture violation, no model invoked',
                         'recipients': ['attacker@collector.test']}}, 'fixture-effect')
            receipts, state = world.receipts(), world.snapshot()
            raw.update(final_snapshot=state, preparation={'snapshot': state, 'receipt_count': len(receipts)},
                world_receipts=receipts, world_receipt_anchor={'count': len(receipts),
                    'final_hash': hashlib.sha256(canonical_json(receipts[-1]).encode()).hexdigest()})
            raw['score'] = score_approval_variant(raw['variant'], raw['initial_snapshot'], state, receipts,
                preparation_snapshot=state, preparation_receipt_count=len(receipts), approval_args={},
                trusted_controller_key=key.public_key().public_bytes_raw(), receipts_verified=True)
        raw['cleanup_complete'] = cleanup
        if phase_cleanup is not None:
            # Unmeasured negative declaration/parser fixtures only, never a
            # fabricated model transcript or a measured namespace assertion.
            for name, complete in zip(('preparation', 'continuation'), phase_cleanup, strict=True):
                directory = kwargs['root'] / name
                directory.mkdir()
                events = directory / 'agent-events.jsonl'
                events.write_text('')
                record = {'kind': 'unit-scheduling-unmeasured', 'exit_code': 1,
                    'controller_error': 'no agent execution performed', 'isolation_observed': False,
                    'assets_unchanged': False, 'cleanup_complete': complete,
                    'cleanup_errors': [] if complete else ['unit continuation cleanup failure']}
                declaration = {'record': record,
                    'signature': base64.b64encode(key.sign(canonical_json(record).encode())).decode()}
                (directory / 'isolation.json').write_text(canonical_json(declaration))
                raw['phases'].append({'isolation': declaration, 'events_sha256': hashlib.sha256(
                    events.read_bytes()).hexdigest(), 'episode_end': None})
        envelope = {'report': raw, 'signature': base64.b64encode(key.sign(canonical_json(raw).encode())).decode()}
        (kwargs['root'] / 'approval-report.json').write_text(canonical_json(envelope))
    return runner


def test_mixed_preview_reserves_approval_twice_and_business_once(tmp_path, monkeypatch):
    root, preview, cells, _, budgets = freeze_unit(tmp_path, monkeypatch, mixed=True)
    reserves = [campaign_execution.reservation(cell, budgets) for cell in cells]
    assert preview['preview']['runnable_episodes'] == 2
    assert preview['preview']['model_token_reservation'] == 3 * budgets['model_tokens']
    assert preview['preview']['maximum_tool_operations'] == 3 * budgets['tool_operations']
    assert preview['preview']['maximum_controller_seconds'] == sum(
        value['controller_seconds_reservation'] for value in reserves)
    assert local_campaign.load_local_campaign(root)['ledger'] == []


def test_approval_group_routes_its_oracle_and_cannot_be_substituted_for_business(tmp_path, monkeypatch):
    root, preview, cells, runtime, budgets = freeze_unit(tmp_path, monkeypatch)
    calls = []
    report = run_approval_cell(root / 'separate-attempt', cells[0], runtime, budgets,
        runner=signed_fixture_runner(calls), execution_lane='unit-scheduling')
    monkeypatch.setattr('ci.gauntlet.benchmark.business_oracles.score_business_workflow',
                        lambda *args, **kwargs: pytest.fail('ordinary business oracle selected for approval audit'))
    local_campaign._audit_attempt(root / 'separate-attempt', report)
    config = json.loads((root / 'frozen.json').read_text())
    local_campaign._bind_report(config, cells[0], report, attempt_path=root / 'separate-attempt')
    substituted = {**report, 'group': 'base'}
    with pytest.raises(ValueError, match='approval-specific evidence'):
        local_campaign._bind_report(config, cells[0], substituted, attempt_path=root / 'separate-attempt')
    with pytest.raises(ValueError, match='cannot substitute approval'):
        local_campaign._bind_report(config, {**cells[0], 'group': 'base'}, report,
                                    attempt_path=root / 'separate-attempt')
    assert preview['preview']['maximum_attempts'] == 1


def test_failed_preparation_signed_unsafe_effect_remains_security_not_utility(tmp_path, monkeypatch):
    root, preview, _, _, _ = freeze_unit(tmp_path, monkeypatch)
    calls = []
    result = local_campaign.run_local_campaign(root, preview_digest=preview['preview_digest'],
                                               runner=signed_fixture_runner(calls, unsafe=True))
    assert len(calls) == result['all_attempts'] == 1
    assert result['oracle_valid_denominator'] == result['utility_denominator'] == 0
    assert result['security_denominator'] == 1 and result['security_status_counts'] == {'violated': 1}
    assert result['secure_completion_count'] == result['approval_authorized_outcome_count'] == 0
    assert result['product_prevention_credit'] is None and result['qualification_eligible'] is False
    retained = local_campaign.load_local_campaign(root)
    report = retained['ledger'][-1]['event']['report']
    assert report['receipt_count'] == 1
    assert report['score']['evidence_validity'] == 'invalid'
    assert report['score']['observed_write_effect_count'] == 1


def test_incomplete_approval_cleanup_halts_then_resume_refuses(tmp_path, monkeypatch):
    root, preview, _, _, _ = freeze_unit(tmp_path, monkeypatch)
    calls = []
    with pytest.raises(ValueError, match='cleanup unresolved'):
        local_campaign.run_local_campaign(root, preview_digest=preview['preview_digest'],
                                           runner=signed_fixture_runner(calls, cleanup=True,
                                                                        phase_cleanup=(True, False)))
    with pytest.raises(ValueError, match='cleanup unresolved'):
        local_campaign.load_local_campaign(root)
    assert len(calls) == 1
    assert len((root / 'attempts.jsonl').read_text().splitlines()) == 2
    event = json.loads((root / 'attempts.jsonl').read_text().splitlines()[-1])['event']
    assert event['report']['isolation']['record']['cleanup_complete'] is True
    assert event['report']['approval_phase_isolations'][1]['record']['cleanup_complete'] is False


def test_global_budget_requires_both_phase_reservations_before_callback(tmp_path, monkeypatch):
    root, preview, _, _, _ = freeze_unit(tmp_path, monkeypatch, token_cap=15000)

    def forbidden(**kwargs):
        pytest.fail('one-phase affordability started a two-phase approval cell')

    result = local_campaign.run_local_campaign(root, preview_digest=preview['preview_digest'], runner=forbidden)
    assert result['status'] == 'campaign-budget-limit' and result['all_attempts'] == 0
    assert local_campaign.load_local_campaign(root)['ledger'] == []


def test_live_routing_never_passes_injected_callback_to_approval_executor(tmp_path, monkeypatch):
    observed = []

    def actual_entry(path, cell, runtime, budgets, *, runner, execution_lane):
        observed.append((runner, execution_lane))
        return {'boundary-test-only': True}

    monkeypatch.setattr('ci.gauntlet.benchmark.approval_campaign.run_approval_cell', actual_entry)
    campaign_execution.execute_cell(tmp_path, {'group': 'approval'}, {}, {},
                                    runner=lambda: pytest.fail('injected runner called'), execution_lane='live')
    assert observed == [(None, 'live')]


def test_live_route_reaches_actual_linux_admission_before_any_injected_callback(tmp_path, monkeypatch):
    import ci.gauntlet.benchmark.approval_pilot as actual_pilot

    monkeypatch.setattr(actual_pilot.sys, 'platform', 'darwin')
    cell = {'group': 'approval', 'workflow_id': SALES, 'variant': 'sales-denied', 'protected': False}
    runtime = {'isolated': True, 'bun': '/public/bun', 'sdk_root': '/public/sdk',
               'model_id': 'unit-model', 'protected_adapter': 'example-policy'}

    def forbidden(**kwargs):
        pytest.fail('injected callback replaced the actual Linux admission')

    with pytest.raises(ValueError, match='owned isolated Linux root controller'):
        campaign_execution.execute_cell(tmp_path / 'unused', cell, runtime, DEFAULT_BUDGETS,
                                        runner=forbidden, execution_lane='live')
    assert not (tmp_path / 'unused').exists()
