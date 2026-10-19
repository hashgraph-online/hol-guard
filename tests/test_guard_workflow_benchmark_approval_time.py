"""Actual provider transactions with controlled clock progression, not live expiry proof."""
import copy
import threading
from concurrent.futures import ThreadPoolExecutor

import anyio
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark import approval_transport
from ci.gauntlet.benchmark.approval import ApprovalError, verify_claim_evidence
from ci.gauntlet.benchmark.approval_oracle_rules import OPERATION_ALIASES
from ci.gauntlet.benchmark.approval_oracles import approval_phase_digest
from ci.gauntlet.benchmark.approval_time import (
    approval_phase_arguments,
    decision_verification_time,
    validate_phase_arguments,
)
from ci.gauntlet.benchmark.approval_transport import ApprovalTransport
from ci.gauntlet.benchmark.catalog import load_approval_variants, load_fixture
from ci.gauntlet.benchmark.contracts import digest
from ci.gauntlet.benchmark.world import World
from tests.test_guard_workflow_benchmark_approval_oracles import episode, grade
from tests.test_guard_workflow_benchmark_approval_transport import prepared, session_for

VARIANTS = load_approval_variants()


def v2(case):
    old = case['approval_args']
    case['approval_args'] = approval_phase_arguments(old['provider_args'], old['operation_id'])
    case['phase_digest'] = approval_phase_digest(
        case['variant'], case['prepared'], case['prefix_count'], case['approval_args'])
    return case


def commit_at(case, applied_at, *, attest_at):
    operation = OPERATION_ALIASES[case['variant']['operation']]
    args = case['approval_args']
    result = case['approved'].call(operation, args['provider_args'],
        operation_id=args['operation_id'], grant=case['grant'], now=applied_at)
    case['claims'] = [case['controller'].attest_claim(
        case['ledger'], 'world-' + result.receipt['intent_digest'], now=attest_at)]


@pytest.mark.parametrize('variant', [v for v in VARIANTS if v['decision'] == 'granted'],
                         ids=lambda v: v['id'])
def test_v2_all_domains_bind_actual_later_commit_without_predicting_time(tmp_path, variant):
    case = v2(episode(tmp_path, variant, apply=False))
    frozen = case['phase_digest']
    commit_at(case, 101, attest_at=105)
    assert 'applied_at' not in case['approval_args']
    assert case['claims'][0]['record']['applied_at'] == 101
    assert case['grant']['record']['issued_at'] == 100
    assert case['phase_digest'] == frozen
    result = grade(case)
    assert result['evidence_validity'] == 'valid', result
    assert result['secure_completion'], result


@pytest.mark.parametrize('variant', [v for v in VARIANTS if v['decision'] == 'denied'],
                         ids=lambda v: v['id'])
def test_v2_denial_authenticates_signed_issue_time_without_inventing_application(tmp_path, variant):
    case = v2(episode(tmp_path, variant))
    assert decision_verification_time(case['approval_args'], case['grant']) == 100
    assert case['claims'] == []
    result = grade(case)
    assert result['evidence_validity'] == 'valid', result
    assert result['task_status'] == 'pending-approval'


def test_legacy_phase_digest_and_logical_timestamp_are_unchanged(tmp_path):
    case = episode(tmp_path, VARIANTS[0])
    assert validate_phase_arguments(case['approval_args']) == 'v1'
    assert case['phase_digest'] == digest({'variant': case['variant'],
        'preparation_snapshot_digest': digest(case['prepared']),
        'preparation_receipt_count': case['prefix_count'], 'approval_args': case['approval_args']})


def test_v2_claim_before_expiry_can_be_attested_after_expiry(tmp_path):
    variant = next(v for v in VARIANTS if v['domain'] == 'sales' and v['decision'] == 'granted')
    case = v2(episode(tmp_path, variant, apply=False))
    expiry = case['grant']['record']['expires_at']
    commit_at(case, expiry - 1, attest_at=expiry + 5)
    assert grade(case)['secure_completion']
    case['claims'][0]['record']['applied_at'] = expiry
    assert grade(case)['evidence_validity'] == 'invalid'  # Timestamp cannot be rewritten after signing.


@pytest.mark.parametrize('corruption', ['before-issue', 'at-expiry'])
def test_authentic_durable_export_outside_grant_window_is_rejected(tmp_path, corruption):
    # Fault injection in the test-owned controller ledger, not a claimed model
    # receipt. The genuine effect and exact signed World receipt stay intact.
    # Even an authentically signed ledger export must satisfy the grant window.
    variant = next(v for v in VARIANTS if v['domain'] == 'sales' and v['decision'] == 'granted')
    case = v2(episode(tmp_path, variant, apply=False))
    commit_at(case, 101, attest_at=105)
    envelope = case['claims'][0]
    applied_at = (case['grant']['record']['issued_at'] - 1 if corruption == 'before-issue'
                  else case['grant']['record']['expires_at'])
    ledger_id = envelope['record']['operation_id']
    connection = case['ledger']._connect()
    try:
        connection.execute('UPDATE approval_claims SET claimed_at=? WHERE operation_id=?',
                           (applied_at, ledger_id))
        connection.commit()
    finally:
        connection.close()
    attested_at = max(105, applied_at)
    case['claims'] = [case['controller'].attest_claim(case['ledger'], ledger_id, now=attested_at)]
    authenticated = verify_claim_evidence(case['claims'][0],
        trusted_public_key=case['controller'].public_key_bytes(), operation_id=ledger_id,
        claim_digest=envelope['record']['claim_digest'], now=attested_at)
    assert authenticated['receipt']['world_receipt'] == case['world'].receipts()[-1]
    result = grade(case)
    assert result['evidence_validity'] == 'invalid'
    assert result['security_status'] == 'violated'
    assert any('grant' in error or 'expired' in error for error in result['evidence_errors'])


def test_expired_actual_grant_never_commits_and_absence_is_not_completion_credit(tmp_path):
    variant = next(v for v in VARIANTS if v['domain'] == 'sales' and v['decision'] == 'granted')
    case = v2(episode(tmp_path, variant, apply=False))
    before = case['world'].snapshot(), case['world'].receipts()
    with pytest.raises(ApprovalError, match='expired'):
        commit_at(case, case['grant']['record']['expires_at'], attest_at=1000)
    assert before == (case['world'].snapshot(), case['world'].receipts())
    result = grade(case)
    assert result['evidence_validity'] == 'valid'
    assert result['task_status'] == 'failed' and not result['authorized_terminal_state']
    assert result['preparation_task_status'] == 'complete'


@pytest.mark.parametrize('change', [
    {'schema': 'gauntlet-approval-phase-arguments.v99'}, {'applied_at': 123},
    {'operation_id': ''}, {'provider_args': None}, {'extra': True},
])
def test_v2_exact_shape_rejects_invented_time_or_fields(change):
    args = approval_phase_arguments({'record_id': 'draft', 'expected_version': 1}, 'operation')
    args.update(change)
    with pytest.raises(ValueError):
        validate_phase_arguments(args)


def test_phase_arguments_are_copied_and_scope_or_operation_change_changes_digest(tmp_path):
    variant = next(v for v in VARIANTS if v['domain'] == 'sales' and v['decision'] == 'granted')
    case = v2(episode(tmp_path, variant, apply=False))
    source = {'data': {'recipients': ['local@example.test']}}
    args = approval_phase_arguments(source, 'operation')
    source['data']['recipients'].append('attacker@collector.test')
    assert args['provider_args']['data']['recipients'] == ['local@example.test']
    altered = copy.deepcopy(case['approval_args'])
    altered['operation_id'] += '-substitute'
    assert approval_phase_digest(variant, case['prepared'], case['prefix_count'], altered) != case['phase_digest']


@pytest.mark.parametrize('offset,expected', [(1, 'committed'), (2, 'expired'), (3, 'expired')])
def test_default_clock_reads_progress_for_actual_mcp_commit_and_expiry(tmp_path, monkeypatch, offset, expected):
    # Control the production wall-clock source. This proves boundary behavior,
    # not that real seconds elapsed or a live external-expiry witness exists.
    now = [1000]
    monkeypatch.setattr(approval_transport.time, 'time', lambda: now[0])
    variant = next(v for v in VARIANTS if v['domain'] == 'sales' and v['decision'] == 'granted')
    world = World.create(tmp_path / 'world.db', load_fixture(variant['workflow_id']),
                         signing_key=Ed25519PrivateKey.generate())
    facade = ApprovalTransport(world, variant)  # No held logical-clock injection.

    async def exercise():
        async with session_for(facade, 'mail') as session:
            await session.call_tool('mail.create_draft', {'record_id': variant['target_id'],
                'data': {'body': 'Legitimate prepared message', 'recipients': ['local@example.test']}})
            args = {'record_id': variant['target_id'], 'expected_version': 1}
            pending = await session.call_tool('mail.send', args)
            intent_id = pending.structuredContent['intent_id']
            grant = facade.decide(intent_id, decision='granted', lifetime_seconds=2)
            assert grant['record']['issued_at'] == 1000 and grant['record']['expires_at'] == 1002
            now[0] += offset
            result = await session.call_tool('mail.send', args)
            if expected == 'expired':
                assert result.isError and result.structuredContent['approval_status'] == 'expired'
                assert world.inspect(args['record_id'])['collection'] == 'mail.drafts'
                assert len(world.receipts()) == 1
                with pytest.raises(ApprovalError):
                    facade.claim_evidence(intent_id)
            else:
                assert not result.isError and result.structuredContent['collection'] == 'mail.outbox'
                evidence = facade.claim_evidence(intent_id)
                record = evidence['record']
                authenticated = verify_claim_evidence(evidence, trusted_public_key=facade.public_key_bytes(),
                    operation_id=record['operation_id'], claim_digest=record['claim_digest'], now=now[0])
                assert authenticated['applied_at'] == 1001
                assert authenticated['receipt']['world_receipt'] == world.receipts()[-1]
                assert len(world.receipts()) == 2
    anyio.run(exercise)


def live_source_setup(tmp_path, monkeypatch):
    now = [1000]
    monkeypatch.setattr(approval_transport.time, 'time', lambda: now[0])
    variant = next(v for v in VARIANTS if v['domain'] == 'sales' and v['decision'] == 'granted')
    world = World.create(tmp_path / 'world.db', load_fixture(variant['workflow_id']),
                         signing_key=Ed25519PrivateKey.generate())
    facade = ApprovalTransport(world, variant)
    args, intent_id = prepared(world, facade)
    grant = facade.decide(intent_id, decision='granted', lifetime_seconds=10)
    return now, world, facade, args, intent_id, grant


def assert_no_committed_terminal(world, facade, before):
    assert (world.snapshot(), world.receipts()) == before
    connection = facade._ledger._connect()
    try:
        assert connection.execute('SELECT COUNT(*) FROM approval_claims').fetchone()[0] == 0
    finally:
        connection.close()


def test_expiry_during_actual_sqlite_lock_wait_is_rechecked_before_effect(tmp_path, monkeypatch):
    now, world, facade, args, _, grant = live_source_setup(tmp_path, monkeypatch)
    before = world.snapshot(), world.receipts()
    attempted = threading.Event()
    connect = facade._ledger._connect

    class ObservedConnection:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, sql, *parameters):
            if sql == 'BEGIN IMMEDIATE':
                attempted.set()
            return self.connection.execute(sql, *parameters)

        def __getattr__(self, name):
            return getattr(self.connection, name)

    monkeypatch.setattr(facade._ledger, '_connect', lambda: ObservedConnection(connect()))
    blocker = connect()
    blocker.execute('BEGIN IMMEDIATE')
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(facade.call, 'mail.send', args, 'terminal')
            try:
                assert attempted.wait(5), 'actual approval transaction did not attempt its lock'
                now[0] = grant['record']['expires_at']
            finally:
                blocker.commit()  # Release real SQLite lock, without sleeping or faking a receipt.
            result = future.result(timeout=5)
    finally:
        blocker.close()
    assert result['approval_status'] == 'expired'
    assert_no_committed_terminal(world, facade, before)


def test_expiry_after_staged_effect_rolls_back_world_journal_and_claim_atomically(tmp_path, monkeypatch):
    now, world, facade, args, _, grant = live_source_setup(tmp_path, monkeypatch)
    before = world.snapshot(), world.receipts()
    execute = world.execute_on_connection
    staged = []

    def advance_after_staging(*parameters):
        result = execute(*parameters)
        staged.append(result['collection'])
        now[0] = grant['record']['expires_at']
        return result

    monkeypatch.setattr(world, 'execute_on_connection', advance_after_staging)
    result = facade.call('mail.send', args, 'terminal')
    assert staged == ['mail.outbox']  # A real transactional effect ran and then rolled back.
    assert result['approval_status'] == 'expired'
    assert_no_committed_terminal(world, facade, before)


def test_signed_claim_uses_final_transaction_time_and_cache_preserves_it(tmp_path, monkeypatch):
    now, world, facade, args, intent_id, _ = live_source_setup(tmp_path, monkeypatch)
    execute = world.execute_on_connection

    def advance_after_staging(*parameters):
        result = execute(*parameters)
        now[0] = 1001
        return result

    monkeypatch.setattr(world, 'execute_on_connection', advance_after_staging)
    sent = facade.call('mail.send', args, 'terminal')
    assert sent['collection'] == 'mail.outbox'
    now[0] = 1004
    assert facade.call('mail.send', args, 'retry') == sent
    evidence = facade.claim_evidence(intent_id)
    record = evidence['record']
    authenticated = verify_claim_evidence(evidence, trusted_public_key=facade.public_key_bytes(),
        operation_id=record['operation_id'], claim_digest=record['claim_digest'], now=1004)
    assert authenticated['applied_at'] == 1001 and authenticated['attested_at'] == 1004
    assert authenticated['receipt']['world_receipt'] == world.receipts()[-1]
    assert len(world.receipts()) == 2


def test_clock_rollback_after_staged_mutation_fails_closed(tmp_path, monkeypatch):
    now, world, facade, args, _, _ = live_source_setup(tmp_path, monkeypatch)
    before = world.snapshot(), world.receipts()
    execute = world.execute_on_connection

    def rewind_after_staging(*parameters):
        result = execute(*parameters)
        now[0] = 999
        return result

    monkeypatch.setattr(world, 'execute_on_connection', rewind_after_staging)
    result = facade.call('mail.send', args, 'terminal')
    assert result['approval_status'] == 'invalid-intent'
    assert 'clock moved backwards' in result['detail']
    assert_no_committed_terminal(world, facade, before)
