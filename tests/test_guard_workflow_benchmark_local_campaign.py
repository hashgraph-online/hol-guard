"""Scheduling tests never represent injected callbacks as live inference."""
import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.authored_challenges import (
    BASE_WORKFLOWS,
    compile_authored_campaign,
    load_authored_snapshot,
)
from ci.gauntlet.benchmark.business_oracles import score_business_workflow
from ci.gauntlet.benchmark.campaign import DEFAULT_BUDGETS, compile_campaign
from ci.gauntlet.benchmark.catalog import get_workflow, load_fixture
from ci.gauntlet.benchmark.challenge_oracles import score_authored_challenge
from ci.gauntlet.benchmark.contracts import canonical_json, digest
from ci.gauntlet.benchmark.local_campaign import (
    freeze_local_campaign,
    load_local_campaign,
    run_local_campaign,
)
from ci.gauntlet.benchmark.world import World

BUSINESS = 'business-finance-invoice-reconciliation'


def freeze(tmp_path, *, lane='unit-scheduling', authored=False, protected=False, count=1, guard=None,
           base_url='http://127.0.0.1:8001/v1', token_cap=40000000, isolated=None,attempt_layout='legacy-v1'):
    bun = tmp_path / 'bun'
    bun.write_bytes(b'explicit fake executable for scheduling only')
    sdk = tmp_path / 'sdk'
    (sdk / 'src').mkdir(parents=True)
    (sdk / 'src' / 'index.ts').write_text('// public SDK fixture')
    (sdk / 'package.json').write_text('{"version":"18.4.12"}')
    budgets = {**DEFAULT_BUDGETS, 'campaign_tokens': token_cap}
    campaign = (compile_authored_campaign(repetitions=count, budgets=budgets)['campaign'] if authored
                else compile_campaign([get_workflow(BUSINESS)], repetitions=count, budgets=budgets))
    desired = 'authored-finance-invoice-credit-notes' if authored else BUSINESS
    cells = [row for row in campaign['inventory'] if row['workflow_id'] == desired
             and row['variant'] == 'clean' and row['protected'] == protected][:count]
    root = tmp_path / 'campaign'
    runtime = {'bun': str(bun), 'sdk_root': str(sdk),
               'model_id': 'fixture-model', 'base_url': base_url,
               'protected_adapter': 'example-policy', 'artifacts': []}
    if guard:
        runtime.update(guard, protected_adapter='hol-guard')
    if isolated is not None:
        runtime['isolated'] = isolated
    preview = freeze_local_campaign(root, campaign=campaign,
                                    episode_ids=[r['id'] for r in cells], max_episodes=count,
                                    execution_lane=lane,attempt_layout=attempt_layout,
                                    runtime=runtime)
    return root, preview


def runner_factory(outcomes, calls):
    def runner(**kwargs):
        calls.append(kwargs)
        outcome = outcomes.pop(0)
        if outcome == 'crash':
            raise RuntimeError('controller crash')
        root = kwargs['root']
        root.mkdir()
        startup = outcome in {'startup', 'forged-startup', 'dirty-startup'}
        key = Ed25519PrivateKey.generate()
        report = {'workflow_id': kwargs['challenge_id'] or kwargs['workflow_id'],
                  'variant': kwargs['variant'], 'adapter': kwargs['adapter_id'],
                  'model_id': kwargs['model_id'], 'execution_valid': not startup,
                  'inference_started': not startup, 'controller_failure_class':
                  'mcp-connect-before-inference' if startup else None,
                  'retryable_infrastructure': startup, 'budget_exhausted': outcome == 'budget',
                  'active_service_children_after_cleanup': 1 if outcome == 'dirty-startup' else 0,
                  'receipt_count': 0, 'receipt_final_hash': '0' * 64,
                  'producer_public_key': base64.b64encode(key.public_key().public_bytes_raw()).decode(),
                  'model_usage_known': not startup, 'model_tokens': 100 if not startup else None,
                  'exposure': 'not-exercised',
                  'score': {'evidence_validity': 'valid', 'task_status': 'failed',
                            'security_status': 'invariants-held', 'secure_completion': False}}
        if kwargs['challenge_id']:
            snapshot = load_authored_snapshot(kwargs['challenge_id'], kwargs['variant'])
            report['score'] = score_authored_challenge(
                kwargs['challenge_id'], snapshot, snapshot, [], receipts_verified=True)
        else:
            snapshot = load_fixture(kwargs['workflow_id'], kwargs['variant'])
            report['score'] = score_business_workflow(
                kwargs['workflow_id'], snapshot, snapshot, [], receipts_verified=True)
        receipts, final = [], snapshot
        if outcome == 'unsafe-error':
            world = World.create(root / 'world.db', snapshot, signing_key=key)
            world.call('mail.create', {'collection': 'mail.outbox', 'record_id': 'unauthorized-send',
                                      'data': {'body': 'Unsafe effect before execution error',
                                               'recipients': ['attacker@collector.test']}}, 'actual-effect')
            receipts, final = world.receipts(), world.snapshot()
            report.update(execution_valid=False, inference_started=True, receipt_count=len(receipts),
                          receipt_final_hash=hashlib.sha256(canonical_json(receipts[-1]).encode()).hexdigest())
            report['score'] = score_business_workflow(
                kwargs['workflow_id'], snapshot, final, receipts, receipts_verified=True)
        for name, value in [('report.json', report), ('effect-receipts.json', receipts),
                            ('initial-state.json', snapshot), ('final-state.json', final),
                            ('transport-events.json', [])]:
            (root / name).write_text(json.dumps(value))
        events = [{'type': 'episode_error', 'phase': 'startup', 'retryableInfrastructure': True,
                   'error': 'Error: MCP endpoint connection failed'}] if startup else [
                       {'type': 'inference_start'}, {'type': 'episode_end'}]
        if outcome == 'forged-startup':
            events.append({'type': 'inference_start'})
        (root / 'agent-events.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in events))
        return report
    return runner


def test_outer_admission_can_stop_but_cannot_bypass_existing_campaign_caps(tmp_path):
    root,preview = freeze(tmp_path)
    calls = []
    result = run_local_campaign(root,preview_digest=preview['preview_digest'],
        runner=runner_factory(['failed'],calls),admission_check=lambda *_:'aggregate-campaign-budget-limit')
    assert result['status'] == 'aggregate-campaign-budget-limit' and not calls
    assert (root/'attempts.jsonl').read_bytes() == b''
    assert not (root/'controller.lock').exists()
    result = run_local_campaign(root,preview_digest=preview['preview_digest'],
        runner=runner_factory(['failed'],calls),admission_check=lambda *_:None)
    assert result['all_attempts'] == 1 and len(calls) == 1
    small = tmp_path/'small'
    small.mkdir()
    other,limited = freeze(small,token_cap=1)
    calls = []
    result = run_local_campaign(other,preview_digest=limited['preview_digest'],
        runner=runner_factory(['failed'],calls),admission_check=lambda *_:None)
    assert result['status'] == 'campaign-budget-limit' and not calls


@pytest.mark.parametrize('outcome', ['failed', 'budget', 'forged-startup'])
def test_completed_failure_budget_and_fabricated_retry_do_not_retry(tmp_path, outcome):
    root, preview = freeze(tmp_path)
    calls = []
    runner = runner_factory([outcome], calls)
    result = run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner)
    assert len(calls) == result['all_attempts'] == 1
    assert result['qualification_eligible'] is False
    assert result['product_prevention_credit'] is None
    run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner)
    assert len(calls) == 1


def test_proven_startup_retry_retains_both_attempts_and_passes_frozen_tokens(tmp_path):
    root, preview = freeze(tmp_path)
    calls = []
    result = run_local_campaign(root, preview_digest=preview['preview_digest'],
                                runner=runner_factory(['startup', 'failed'], calls))
    assert len(calls) == result['all_attempts'] == 2
    assert result['terminal_outcomes'] == 1
    assert calls[0]['root'] != calls[1]['root']
    assert all(c['max_model_tokens'] == 32000 for c in calls)
    assert result['charged_model_tokens'] == 100
    assert len(load_local_campaign(root)['ledger']) == 4


def test_second_startup_failure_is_terminal_not_unbounded_retry(tmp_path):
    root, preview = freeze(tmp_path)
    calls = []
    result = run_local_campaign(root, preview_digest=preview['preview_digest'],
                                runner=runner_factory(['startup', 'startup'], calls))
    assert len(calls) == 2 and result['terminal_outcomes'] == 1


def test_resume_refuses_changed_runtime_or_receipts(tmp_path):
    root, preview = freeze(tmp_path)
    run_local_campaign(root, preview_digest=preview['preview_digest'],
                       runner=runner_factory(['failed'], []))
    attempt = next((root / 'attempts').iterdir())
    (attempt / 'effect-receipts.json').write_text('[{}]')
    with pytest.raises((ValueError, KeyError)):
        load_local_campaign(root)
    (tmp_path / 'bun').write_bytes(b'changed executable')
    with pytest.raises(ValueError, match='bytes changed'):
        load_local_campaign(root)


def test_incomplete_attempt_never_rerun_or_stitched(tmp_path):
    root, preview = freeze(tmp_path)
    with pytest.raises(RuntimeError):
        run_local_campaign(root, preview_digest=preview['preview_digest'],
                           runner=runner_factory(['crash'], []))
    with pytest.raises(ValueError, match='incomplete attempt'):
        load_local_campaign(root)


def test_unknown_cleanup_blocks_resume_and_further_inference(tmp_path):
    root, preview = freeze(tmp_path)
    calls = []
    with pytest.raises(ValueError, match='cleanup unresolved'):
        run_local_campaign(root, preview_digest=preview['preview_digest'],
                           runner=runner_factory(['dirty-startup'], calls))
    with pytest.raises(ValueError, match='cleanup unresolved'):
        load_local_campaign(root)
    assert len(calls) == 1


def test_authored_dispatch_uses_actual_unique_identity_and_semantic_adapter(tmp_path):
    root, preview = freeze(tmp_path, authored=True, protected=True)
    calls = []
    run_local_campaign(root, preview_digest=preview['preview_digest'],
                       runner=runner_factory(['failed'], calls))
    assert calls[0]['challenge_id'] == 'authored-finance-invoice-credit-notes'
    assert calls[0]['workflow_id'] == BASE_WORKFLOWS[calls[0]['challenge_id']]
    assert calls[0]['adapter_id'] == 'example-policy'


def test_live_lane_rejects_fake_runner_and_requires_preview(tmp_path):
    root, preview = freeze(tmp_path, lane='live')
    with pytest.raises(ValueError, match='injected runners'):
        run_local_campaign(root, preview_digest=preview['preview_digest'], runner=lambda **_: {})
    with pytest.raises(ValueError, match='preview digest'):
        run_local_campaign(root, preview_digest='wrong')


def test_exclusive_lock_prevents_concurrent_inference(tmp_path):
    root, preview = freeze(tmp_path)
    (root / 'controller.lock').write_text('another controller')
    with pytest.raises(FileExistsError):
        run_local_campaign(root, preview_digest=preview['preview_digest'], runner=lambda **_: {})


def test_exact_selection_and_explicit_unsupported_developer(tmp_path):
    bun = tmp_path / 'bun'
    bun.write_bytes(b'fake')
    sdk = tmp_path / 'sdk'
    (sdk / 'src').mkdir(parents=True)
    (sdk / 'src' / 'index.ts').write_text('// fixture')
    (sdk / 'package.json').write_text('{}')
    campaign = compile_campaign([get_workflow('python-cli-with-tests')], repetitions=1)
    preview = freeze_local_campaign(tmp_path / 'campaign', campaign=campaign,
                                    episode_ids=[campaign['inventory'][0]['id']], max_episodes=1,
                                    execution_lane='unit-scheduling', runtime={
                                        'bun': str(bun), 'sdk_root': str(sdk), 'model_id': 'm',
                                        'base_url': 'http://localhost:8001/v1',
                                        'protected_adapter': 'unimplemented', 'artifacts': []})
    result = run_local_campaign(tmp_path / 'campaign', preview_digest=preview['preview_digest'],
                                runner=lambda **_: pytest.fail('unsupported ran inference'))
    assert result['unsupported'] == 1 and result['all_attempts'] == 0


def test_guard_uninstalled_or_mismatched_provenance_rejected_before_inference(tmp_path):
    with pytest.raises(ValueError, match='installed Guard'):
        freeze(tmp_path, protected=True, guard={'guard_python': sys.executable,
                                               'guard_source_sha': '0' * 40})
    assert not (tmp_path / 'campaign' / 'attempts.jsonl').exists()


def test_guard_lexical_venv_path_dispatch_and_package_bytes_pinned_unit_only(tmp_path, monkeypatch):
    from ci.gauntlet.benchmark import installed_guard
    package = tmp_path / 'installed-public-package'
    package.mkdir()
    module = package / '__init__.py'
    module.write_text('# public unit probe fixture')
    python = tmp_path / 'venv-python'
    python.symlink_to(sys.executable)
    observed = []

    def unit_probe(executable, *, expected_sha, home):
        assert home.is_dir()
        observed.append(str(executable))
        return {'module': str(module), 'source_sha': expected_sha,
                'note': 'unit-only mocked identity; never live evidence'}

    monkeypatch.setattr(installed_guard, 'inspect_installed_guard', unit_probe)
    root, preview = freeze(tmp_path, protected=True,
                           guard={'guard_python': str(python), 'guard_source_sha': 'a' * 40})
    calls = []
    result = run_local_campaign(root, preview_digest=preview['preview_digest'],
                                runner=runner_factory(['failed'], calls))
    assert result['execution_lane'] == 'unit-scheduling'
    assert observed and all(path == str(python) for path in observed)
    assert calls[0]['guard_python'] == python
    assert calls[0]['guard_source_sha'] == 'a' * 40
    module.write_text('# substituted package bytes')
    with pytest.raises(ValueError, match='bytes changed'):
        load_local_campaign(root)


def test_actual_signed_unsafe_effect_survives_execution_invalid_security_denominator(tmp_path):
    root, preview = freeze(tmp_path)
    calls = []
    result = run_local_campaign(root, preview_digest=preview['preview_digest'],
                                runner=runner_factory(['unsafe-error'], calls))
    assert len(calls) == 1
    assert result['execution_valid_denominator'] == result['utility_denominator'] == 0
    assert result['oracle_valid_denominator'] == result['security_denominator'] == 1
    assert result['security_status_counts'] == {'violated': 1}
    assert result['secure_completion_count'] == 0


@pytest.mark.parametrize('inconsistency', ['positive-tokens', 'mixed-error'])
def test_retry_rejects_contradictory_model_usage_or_additional_error(tmp_path, inconsistency):
    root, preview = freeze(tmp_path)
    calls = []
    base_runner = runner_factory(['startup'], calls)

    def inconsistent_runner(**kwargs):
        report = base_runner(**kwargs)
        if inconsistency == 'positive-tokens':
            report.update(model_usage_known=True, model_tokens=100)
        else:
            with (kwargs['root'] / 'agent-events.jsonl').open('a') as stream:
                stream.write(json.dumps({'type': 'episode_error', 'phase': 'inference',
                                         'error': 'Other failure', 'retryableInfrastructure': False}) + '\n')
        (kwargs['root'] / 'report.json').write_text(json.dumps(report))
        return report

    result = run_local_campaign(root, preview_digest=preview['preview_digest'], runner=inconsistent_runner)
    assert len(calls) == result['all_attempts'] == 1


def test_resume_rebinds_genuine_receipts_and_report_to_exact_selected_model(tmp_path):
    root, preview = freeze(tmp_path)
    run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner_factory(['failed'], []))
    path = root / 'attempts.jsonl'
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    finish = rows[-1]['event']
    finish['report']['model_id'] = 'different-provider-model'
    attempt = root / 'attempts' / f'{finish["episode_id"]}.attempt-0'
    (attempt / 'report.json').write_text(json.dumps(finish['report']))
    finish['hashes']['report.json'] = hashlib.sha256((attempt / 'report.json').read_bytes()).hexdigest()
    for index, row in enumerate(rows):
        row['previous_hash'] = digest(rows[index - 1]) if index else '0' * 64
        row['event_digest'] = digest(row['event'])
    path.write_text(''.join(canonical_json(row) + '\n' for row in rows))
    with pytest.raises(ValueError, match='identity differs'):
        load_local_campaign(root)


@pytest.mark.parametrize('usage', ['unknown', 'partial-overrun', 'response-overrun'])
def test_token_threshold_or_unknown_usage_stops_remaining_cells_and_resume(tmp_path, usage):
    root, preview = freeze(tmp_path, count=2)
    calls = []
    actual = runner_factory(['failed', 'failed'], calls)

    def runner(**kwargs):
        report = actual(**kwargs)
        report.update(budget_exhausted=True, model_usage_known=usage == 'response-overrun',
                      model_tokens=None if usage == 'unknown' else 32001)
        (kwargs['root'] / 'report.json').write_text(json.dumps(report))
        return report

    result = run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner)
    expected_calls = 2 if usage == 'response-overrun' else 1
    assert result['selected_denominator'] == 2 and result['all_attempts'] == len(calls) == expected_calls
    assert result['status'] == ('finished' if usage == 'response-overrun' else 'model-token-usage-unknown')
    assert result['response_token_threshold_overruns'] == (0 if usage == 'unknown' else expected_calls)
    assert result['charged_model_tokens'] == (32000 if usage == 'unknown' else 32001 * expected_calls)
    assert preview['preview']['maximum_model_tokens'] is None
    assert preview['preview']['model_token_reservation'] == 128000
    resumed = run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner)
    assert resumed['status'] == result['status'] and len(calls) == expected_calls


def test_actual_campaign_token_cap_excess_retained_and_stops_remaining_inference(tmp_path):
    root, preview = freeze(tmp_path, count=2, token_cap=35000)
    calls = []
    actual = runner_factory(['failed'], calls)

    def runner(**kwargs):
        report = actual(**kwargs)
        report.update(budget_exhausted=True, model_usage_known=True, model_tokens=35001)
        (kwargs['root'] / 'report.json').write_text(json.dumps(report))
        return report

    result = run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner)
    assert result['status'] == 'campaign-model-token-cap-exceeded'
    assert result['charged_model_tokens'] == 35001 and len(calls) == 1
    assert preview['preview']['campaign_model_token_cap'] == 35000
    resumed = run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner)
    assert resumed['status'] == result['status'] and len(calls) == 1


def test_default_shared_lane_passes_false_and_rejects_retrospective_isolation_claim(tmp_path):
    root, preview = freeze(tmp_path)
    calls = []
    actual = runner_factory(['failed'], calls)

    def runner(**kwargs):
        report = actual(**kwargs)
        report['execution_lane'] = 'isolated-linux'
        (kwargs['root'] / 'report.json').write_text(json.dumps(report))
        return report

    with pytest.raises(ValueError, match='lane differs'):
        run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner)
    assert calls[0]['isolated'] is False


def test_isolated_freeze_rejects_nonlinux_controller_before_inference(tmp_path, monkeypatch):
    from ci.gauntlet.benchmark import local_campaign_custody
    monkeypatch.setattr(local_campaign_custody.sys, 'platform', 'darwin')
    with pytest.raises(ValueError, match='Linux root controller'):
        freeze(tmp_path, isolated=True)
    assert not (tmp_path / 'campaign' / 'attempts.jsonl').exists()


@pytest.mark.parametrize('field', ['active_service_workers_after_cleanup', 'active_service_sessions_after_cleanup',
                                 'active_native_sessions_after_cleanup'])
def test_any_nonzero_reported_cleanup_dimension_blocks_next_attempt_and_resume(tmp_path, field):
    root, preview = freeze(tmp_path)
    actual = runner_factory(['startup'], [])

    def runner(**kwargs):
        report = actual(**kwargs)
        report[field] = 1
        (kwargs['root'] / 'report.json').write_text(json.dumps(report))
        return report

    with pytest.raises(ValueError, match='cleanup unresolved'):
        run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner)
    with pytest.raises(ValueError, match='cleanup unresolved'):
        load_local_campaign(root)


@pytest.mark.parametrize('base_url', ['https://localhost:1234', 'http://[::1]:1234'])
def test_freeze_rejects_endpoint_known_to_be_unsupported_by_actual_omp(tmp_path, base_url):
    with pytest.raises(ValueError, match='local model endpoints'):
        freeze(tmp_path, base_url=base_url)


def test_compact_layout_executes_and_audits_retained_attempts_without_moving_old_rows(tmp_path):
    root,preview=freeze(tmp_path,attempt_layout='compact-v1')
    state=load_local_campaign(root)
    assert state['config']['schema']=='gauntlet-local-campaign.v2'
    assert (root/'a').is_dir() and not (root/'attempts').exists()
    calls=[]
    result=run_local_campaign(root,preview_digest=preview['preview_digest'],runner=runner_factory(['normal'],calls))
    assert result['status']=='finished' and len(calls)==1
    assert calls[0]['root'].parent==root/'a' and len(calls[0]['root'].name)==19
    retained=load_local_campaign(root)
    assert retained['terminal_ids']==[state['config']['cells'][0]['id']]


def test_public_seed_source_is_frozen_and_cannot_change_between_attempts(tmp_path,monkeypatch):
    from ci.gauntlet.benchmark import developer_seed_inputs
    original=Path(developer_seed_inputs.__file__).parent.parent/'full_tasks.py'
    copied=tmp_path/'legacy/full_tasks.py'
    copied.parent.mkdir()
    copied.write_bytes(original.read_bytes())
    monkeypatch.setattr(developer_seed_inputs,'__file__',str(copied.parent/'benchmark/developer_seed_inputs.py'))
    root,_=freeze(tmp_path)
    state=load_local_campaign(root)
    assert str(copied) in state['config']['identities']
    copied.write_bytes(copied.read_bytes()+b'\n# changed public seed bytes\n')
    with pytest.raises(ValueError,match='frozen source'):
        load_local_campaign(root)


@pytest.mark.parametrize('relative', [
    'business_oracles.py', 'developer_oracles.py', 'approval_oracles.py',
    'bundle_integrity.py', 'ci_gate.py', 'schemas/ci-gate-policy.v1.json',
    'fixtures/business-finance-invoice-reconciliation.json',
])
def test_changed_scorer_policy_or_answer_bytes_refuse_resume_without_execution(tmp_path, monkeypatch, relative):
    from ci.gauntlet.benchmark import campaign_identity
    source = tmp_path / 'reviewed-source'
    copied = source / relative
    copied.parent.mkdir(parents=True)
    copied.write_bytes((campaign_identity.SOURCE / relative).read_bytes())
    monkeypatch.setattr(campaign_identity, 'SOURCE', source)
    root, _ = freeze(tmp_path)
    state = load_local_campaign(root)
    assert str(copied) in state['config']['identities']
    sentinel = tmp_path / 'captured-code-was-executed'
    copied.write_text('from pathlib import Path\nPath(' + repr(str(sentinel)) + ').touch()\n')
    with pytest.raises(ValueError, match='frozen source'):
        load_local_campaign(root)
    assert not sentinel.exists()


def test_required_grader_bridge_is_frozen_and_tampering_refuses_resume(tmp_path,monkeypatch):
    from ci.gauntlet.benchmark import developer_probe_inputs
    source=tmp_path/'grader';source.mkdir()
    for name in developer_probe_inputs.ASSET_NAMES:
        (source/name).write_bytes((developer_probe_inputs.SOURCE/name).read_bytes())
    monkeypatch.setattr(developer_probe_inputs,'SOURCE',source)
    root,_=freeze(tmp_path)
    state=load_local_campaign(root)
    bridge=source/'developer_node_bridge.mjs'
    assert str(bridge) in state['config']['identities']
    bridge.write_bytes(bridge.read_bytes()+b'\n// modified grader bridge\n')
    with pytest.raises(ValueError,match='frozen source'):
        load_local_campaign(root)
