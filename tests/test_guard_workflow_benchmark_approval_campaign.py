"""Unit scheduling/evidence conformance, never a synthetic actual-model episode."""
import base64
import copy
import json
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.approval_campaign import (
    approval_cleanup_complete,
    approval_reservation,
    approval_token_charge,
    audit_approval_attempt,
    bind_approval_isolation,
    run_approval_cell,
)
from ci.gauntlet.benchmark.approval_oracles import score_approval_variant
from ci.gauntlet.benchmark.approval_pilot import phase_usage
from ci.gauntlet.benchmark.catalog import load_approval_variants, load_fixture
from ci.gauntlet.benchmark.contracts import canonical_json

BUDGETS = {'episode_seconds': 900, 'tool_operations': 200, 'model_tokens': 100000}
CELL = {'group': 'approval', 'variant': 'sales-denied',
        'workflow_id': 'business-sales-lead-qualification', 'protected': False}
RUNTIME = {'bun': '/public/bun', 'sdk_root': '/public/sdk', 'model_id': 'local-model',
           'protected_adapter': 'example-policy', 'isolated': True}


def negative_scheduling_callback(**kwargs):
    """No model messages/effects are generated; test only the driver handoff."""
    root = kwargs['root']
    root.mkdir(mode=0o700)
    variant = next(v for v in load_approval_variants() if v['id'] == kwargs['variant_id'])
    initial = load_fixture(variant['workflow_id'])
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    score = score_approval_variant(variant, initial, initial, [], preparation_snapshot=initial,
        preparation_receipt_count=0, approval_args={}, trusted_controller_key=public, receipts_verified=True)
    raw = {'variant': variant, 'decision_mode': 'catalog', 'adapter': kwargs['adapter_id'],
        'model_id': kwargs['model_id'], 'public_key': base64.b64encode(public).decode(),
        'initial_snapshot': initial, 'final_snapshot': initial,
        'preparation': {'snapshot': initial, 'receipt_count': 0}, 'world_receipts': [],
        'world_receipt_anchor': {'count': 0, 'final_hash': '0' * 64}, 'approval_args': None,
        'trusted_phase_digest': None, 'external_decision': None, 'controller_claims': [],
        'controller_approval_anchor': base64.b64encode(public).decode(), 'phases': [],
        'controller_error': 'unit scheduling: no inference invoked', 'cleanup_complete': True,
        'service_transport_events': [], 'upstream_transport_events': [], 'score': score,
        'budgets_per_phase': {'seconds': kwargs['deadline_seconds'], 'tool_calls': kwargs['max_tool_calls'],
                              'tokens': kwargs['max_model_tokens']},
        'active_service_children_after_cleanup': 0, 'active_service_workers_after_cleanup': 0,
        'active_service_sessions_after_cleanup': 0, 'active_native_sessions_after_cleanup': 0}
    envelope = {'report': raw, 'signature': base64.b64encode(key.sign(canonical_json(raw).encode())).decode()}
    (root / 'approval-report.json').write_text(canonical_json(envelope))
    return key, raw


def test_both_phases_reserved_and_unknown_usage_charged_conservatively():
    reservation = approval_reservation(BUDGETS)
    assert reservation['model_token_reservation'] == 200000
    assert reservation['tool_operation_reservation'] == 400
    assert reservation['controller_seconds_reservation'] == 2040
    assert approval_token_charge({'model_tokens': 3456, 'model_usage_known': False}, BUDGETS) == 200000
    assert approval_token_charge({'model_tokens': 234567, 'model_usage_known': False}, BUDGETS) == 234567
    assert approval_token_charge({'model_tokens': 3456, 'model_usage_known': True}, BUDGETS) == 3456


def test_later_model_error_keeps_completed_response_tokens():
    events = [{'type': 'agent_event', 'event': {'type': 'message_end', 'message': {
        'role': 'assistant', 'usage': {'totalTokens': 1234}}}},
        {'type': 'episode_error', 'phase': 'inference', 'error': 'provider failure'}]
    assert phase_usage(events) == {'observed_model_tokens': 1234, 'model_usage_known': False}
    events.append({'type': 'episode_end', 'modelTokens': 1234, 'modelUsageKnown': True})
    assert phase_usage(events) == {'observed_model_tokens': 1234, 'model_usage_known': True}


def test_live_callback_and_wrong_variant_rejected_before_execution(tmp_path):
    def forbidden(**kwargs):
        pytest.fail('invalid scheduling request executed')

    with pytest.raises(ValueError, match='unit scheduling'):
        run_approval_cell(tmp_path / 'run', CELL, RUNTIME, BUDGETS, runner=forbidden)
    wrong = copy.deepcopy(CELL)
    wrong['workflow_id'] = 'business-operations-access-review'
    with pytest.raises(ValueError, match='same-workflow'):
        run_approval_cell(tmp_path / 'run', wrong, RUNTIME, BUDGETS,
                          runner=forbidden, execution_lane='unit-scheduling')
    assert not (tmp_path / 'run').exists()


def test_negative_scheduling_retains_context_and_independent_resume_rejects_tamper(tmp_path):
    path = tmp_path / 'run'
    report = run_approval_cell(path, CELL, RUNTIME, BUDGETS, runner=negative_scheduling_callback,
                               execution_lane='unit-scheduling')
    assert report['execution_valid'] is False and report['inference_started'] is False
    assert report['qualification_eligible'] is False
    assert report['model_tokens'] == 0 and report['model_usage_known'] is False
    hashes = audit_approval_attempt(path, report)
    assert {'preparation-state.json', 'approval-context.json', 'approval-claims.json'} <= hashes.keys()
    assert stat.S_IMODE((path / 'preparation-state.json').stat().st_mode) == 0o600
    state = json.loads((path / 'preparation-state.json').read_text())
    state['records'][0]['version'] += 1
    (path / 'preparation-state.json').write_text(canonical_json(state))
    with pytest.raises(ValueError, match='state/context/claims'):
        audit_approval_attempt(path, report)


def test_approval_evidence_writer_refuses_shared_or_symlinked_attempt_directory(tmp_path):
    from ci.gauntlet.benchmark.approval_campaign import _write

    shared = tmp_path / 'shared'
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    with pytest.raises(ValueError, match='owner-only'):
        _write(shared / 'approval-state.json', {'synthetic': True})
    assert not (shared / 'approval-state.json').exists()

    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    alias = tmp_path / 'alias'
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(OSError):
        _write(alias / 'approval-state.json', {'synthetic': True})
    assert not (private / 'approval-state.json').exists()


def test_resume_recomputes_oracle_instead_of_trusting_retained_success(tmp_path):
    path = tmp_path / 'run'
    report = run_approval_cell(path, CELL, RUNTIME, BUDGETS, runner=negative_scheduling_callback,
                               execution_lane='unit-scheduling')
    report['score']['secure_completion'] = True
    (path / 'report.json').write_text(canonical_json(report))
    with pytest.raises(ValueError, match='recomputed approval report'):
        audit_approval_attempt(path, report)


def test_partial_parser_evidence_is_charged_but_never_promoted_or_cleared(tmp_path):
    def parser_fixture_callback(**kwargs):
        key, raw = negative_scheduling_callback(**kwargs)
        root = kwargs['root'] / 'preparation'
        root.mkdir()
        event = {'type': 'agent_event', 'event': {'type': 'message_end', 'message': {
            'role': 'assistant', 'usage': {'totalTokens': 1234}}}}
        file = root / 'agent-events.jsonl'
        file.write_text(canonical_json(event) + '\n')
        import hashlib
        raw['partial_phase_events'] = [{'name': 'preparation',
            'events_sha256': hashlib.sha256(file.read_bytes()).hexdigest(),
            'usage': {'observed_model_tokens': 1234, 'model_usage_known': False}}]
        raw['cleanup_complete'] = False
        envelope = {'report': raw, 'signature': base64.b64encode(key.sign(canonical_json(raw).encode())).decode()}
        (kwargs['root'] / 'approval-report.json').write_text(canonical_json(envelope))

    path = tmp_path / 'run'
    report = run_approval_cell(path, CELL, RUNTIME, BUDGETS,
                               runner=parser_fixture_callback, execution_lane='unit-scheduling')
    assert report['model_tokens'] == 1234
    assert report['execution_valid'] is False and report['inference_started'] is False
    assert approval_token_charge(report, BUDGETS) == 200000
    assert approval_cleanup_complete(report) is False
    assert 'preparation/agent-events.jsonl' in audit_approval_attempt(path, report)


@pytest.mark.parametrize('helper_profile',['legacy','recovery','agent'])
def test_both_negative_declaration_mounts_checked_no_world_or_product_mount(tmp_path,helper_profile):
    """Signed parser fixtures, not measured runtime or actual-model evidence."""
    from pathlib import Path

    import ci.gauntlet.benchmark.approval_campaign as module

    key = Ed25519PrivateKey.generate()
    helpers = {name: name for name in ('omp_episode.ts', 'service_relay.py', 'developer_model_relay.py')}
    if helper_profile!='legacy':
        helpers['business_protocol_recovery.ts']='business_protocol_recovery.ts'
    if helper_profile=='agent':
        helpers['mcp_agent_surfaces.ts']='mcp_agent_surfaces.ts'
    sdk = '/public/node_modules/@oh-my-pi/pi-coding-agent'
    config = {'runtime': {'isolated': True, 'bun': '/public/bun', 'sdk_root': sdk},
        'campaign': {'budgets': {'episode_seconds': 30, 'tool_operations': 20, 'model_tokens': 32000}},
        'isolation_tuple': {'image_id': 'parser-fixture-image', 'controller': {}, 'sdk': {}, 'bun': {}},
        'identities': {'/public/bun': 'bun', sdk + '/package.json': 'sdk',
                      **{str(Path(module.__file__).with_name(name).resolve()): sha for name, sha in helpers.items()}}}
    if helper_profile=='agent':
        config['runtime']['mcp_agent_surfaces']='mcp-agent-surfaces.v1'
    report = {'execution_lane': 'isolated-linux', 'execution_valid': False, 'adapter': 'unprotected',
        'budgets': {'wall_seconds': 30, 'tool_calls': 20, 'model_tokens': 32000},
        'producer_public_key': base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        'approval_phase_isolations': [], 'approval_phase_observations': [{'execution_valid': False}] * 2}
    for name in ('preparation', 'continuation'):
        root = tmp_path / name
        mounts = [(str(root / 'public'), '/runtime/public', 'ro'),
            (str(root / 'home'), '/runtime/home', 'rw'), (str(root / 'workspace'), '/runtime/home/project', 'rw'),
            (str(root / 'agent'), '/runtime/agent', 'rw'), (str(tmp_path / 'sockets'), '/services', 'ro'),
            ('/public/bun', '/runtime/bun', 'ro'), ('/public/node_modules', '/sdk/node_modules', 'ro'),
            (str(root / 'model.sock'), '/runtime/model.sock', 'ro')]
        record = {'image_id': 'parser-fixture-image', 'controller': {}, 'frozen_assets': {'sdk': {}, 'bun': {}},
            'bun_sha256': 'bun', 'sdk_package_sha256': 'sdk', 'public_assets': helpers,
            'mounts': [{'source': source, 'destination': dest, 'mode': mode} for source, dest, mode in mounts]}
        report['approval_phase_isolations'].append({'record': record,
            'signature': base64.b64encode(key.sign(canonical_json(record).encode())).decode()})
    bind_approval_isolation(config, report, attempt_path=tmp_path)
    second = report['approval_phase_isolations'][1]
    second['record']['mounts'].append({'source': str(tmp_path / 'world.db'),
                                      'destination': '/private/world.db', 'mode': 'ro'})
    second['signature'] = base64.b64encode(key.sign(canonical_json(second['record']).encode())).decode()
    with pytest.raises(ValueError, match='undeclared state/product/controller'):
        bind_approval_isolation(config, report, attempt_path=tmp_path)
