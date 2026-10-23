"""Official MCP ClientSession exercises controller-owned approval boundaries."""
from contextlib import asynccontextmanager

import anyio
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession

from ci.gauntlet.benchmark.approval import ApprovalError, verify_claim_evidence
from ci.gauntlet.benchmark.approval_transport import ApprovalTransport
from ci.gauntlet.benchmark.catalog import load_approval_variants, load_fixture
from ci.gauntlet.benchmark.mcp_server import create_server
from ci.gauntlet.benchmark.world import World


@asynccontextmanager
async def session_for(facade, family):
    # Actual SDK server/session JSON-RPC messages, no tool dispatcher mock.
    server = create_server(facade, family)._mcp_server
    client_write, server_read = anyio.create_memory_object_stream(0)
    server_write, client_read = anyio.create_memory_object_stream(0)
    async with anyio.create_task_group() as group:
        group.start_soon(server.run, server_read, server_write, server.create_initialization_options())
        try:
            async with ClientSession(client_read, client_write) as session:
                with anyio.fail_after(10):
                    await session.initialize()
                    yield session
        finally:
            group.cancel_scope.cancel()


def setup(tmp_path, *, decision='granted', domain='sales'):
    variant = next(v for v in load_approval_variants() if v['domain'] == domain and v['decision'] == decision)
    world = World.create(tmp_path / 'world.db', load_fixture(variant['workflow_id']),
                         signing_key=Ed25519PrivateKey.generate())
    now = [1000]
    facade = ApprovalTransport(world, variant, clock=lambda: now[0])
    return world, facade, now


def test_actual_mcp_pending_then_exact_single_effect_and_signed_durable_claim(tmp_path):
    world, facade, _ = setup(tmp_path)

    async def exercise():
        async with session_for(facade, 'mail') as session:
            names = {tool.name for tool in (await session.list_tools()).tools}
            assert not any('approve' in name or 'grant' in name or 'decide' in name for name in names)
            draft = await session.call_tool('mail.create_draft', {
                'record_id': facade.variant['target_id'],
                'data': {'body': 'Prepared legitimate local follow-up', 'recipients': ['local@example.test']}})
            assert not draft.isError
            args = {'record_id': facade.variant['target_id'], 'expected_version': 1}
            pending = await session.call_tool('mail.send', args)
            intent_id = pending.structuredContent['intent_id']
            assert pending.isError and pending.structuredContent['approval_status'] == 'pending'
            assert world.inspect(args['record_id'])['collection'] == 'mail.drafts'
            assert len(world.receipts()) == 1
            phase = facade.preparation_snapshot()
            assert phase['receipt_count'] == 1
            assert phase['snapshot'] == world.snapshot()
            grant = facade.decide(intent_id, decision='granted')
            assert grant['record']['request'] == facade.intents()[0]['request']
            sent = await session.call_tool('mail.send', args)
            assert not sent.isError and sent.structuredContent['collection'] == 'mail.outbox'
            retry = await session.call_tool('mail.send', args)
            assert retry.structuredContent == sent.structuredContent
            assert len(world.receipts()) == 2
            evidence = facade.claim_evidence(intent_id)
            claim = evidence['record']
            verify_claim_evidence(evidence, trusted_public_key=facade.public_key_bytes(),
                                  operation_id=claim['operation_id'], claim_digest=claim['claim_digest'], now=1000)
            assert claim['receipt']['world_receipt'] == world.receipts()[-1]

    anyio.run(exercise)


@pytest.mark.parametrize('decision', ['denied', 'expired', 'no-response'])
def test_actual_mcp_refusal_never_effects(tmp_path, decision):
    world, facade, _ = setup(tmp_path, decision='denied' if decision == 'denied' else 'granted')

    async def exercise():
        async with session_for(facade, 'mail') as session:
            await session.call_tool('mail.create_draft', {'record_id': facade.variant['target_id'],
                'data': {'body': 'Legitimate preparation remains', 'recipients': ['local@example.test']}})
            args = {'record_id': facade.variant['target_id'], 'expected_version': 1}
            pending = await session.call_tool('mail.send', args)
            facade.decide(pending.structuredContent['intent_id'], decision=decision)
            result = await session.call_tool('mail.send', args)
            assert result.isError and result.structuredContent['approval_status'] == decision
            assert world.inspect(args['record_id'])['collection'] == 'mail.drafts'
            assert len(world.receipts()) == 1

    anyio.run(exercise)


def prepared(world, facade):
    target = facade.variant['target_id']
    world.call('mail.create_draft', {'record_id': target,
                                   'data': {'body': 'Original payload', 'recipients': ['local@example.test']}}, 'prep')
    args = {'record_id': target, 'expected_version': 1}
    pending = facade.call('mail.send', args, 'pending')
    return args, pending['intent_id']


def test_payload_state_changed_before_decision_rejected(tmp_path):
    world, facade, _ = setup(tmp_path)
    args, intent_id = prepared(world, facade)
    world.call('mail.update', {'record_id': args['record_id'], 'expected_version': 1,
                              'data': {'body': 'Changed payload', 'recipients': ['attacker@collector.test']}}, 'tamper')
    with pytest.raises(ApprovalError):
        facade.decide(intent_id, decision='granted')
    assert world.inspect(args['record_id'])['collection'] == 'mail.drafts'


def test_postgrant_state_change_and_payload_replacement_do_not_commit(tmp_path):
    world, facade, _ = setup(tmp_path)
    args, intent_id = prepared(world, facade)
    facade.decide(intent_id, decision='granted')
    frozen = facade.call('mail.update', {'record_id': args['record_id'], 'expected_version': 1,
                                       'data': {'body': 'Tamper'}}, 'agent-tamper')
    assert frozen['approval_status'] == 'preparation-frozen'
    # Simulate a concurrent authoritative provider mutation, outside facade.
    world.call('mail.update', {'record_id': args['record_id'], 'expected_version': 1,
                              'data': {'body': 'Changed underlying state'}}, 'concurrent-provider')
    assert facade.call('mail.send', args, 'commit')['approval_status'] == 'invalid-intent'
    changed_args = dict(args, expected_version=2)
    assert facade.call('mail.send', changed_args, 'changed')['approval_status'] == 'outside-frozen-phase'
    assert world.inspect(args['record_id'])['collection'] == 'mail.drafts'


def test_grant_expiry_cannot_be_refreshed_from_model_quote(tmp_path):
    world, facade, now = setup(tmp_path)
    args, intent_id = prepared(world, facade)
    facade.decide(intent_id, decision='granted', lifetime_seconds=1)
    now[0] += 2
    assert facade.call('mail.send', args, 'expired')['approval_status'] == 'expired'
    forged = dict(args, grant={'record': {'decision': 'granted'}})
    assert facade.call('mail.send', forged, 'forged')['approval_status'] == 'outside-frozen-phase'
    assert world.inspect(args['record_id'])['collection'] == 'mail.drafts'


def test_controller_can_pin_preparation_before_first_terminal_request(tmp_path):
    world, facade, _ = setup(tmp_path)
    target = facade.variant['target_id']
    world.call('mail.create_draft', {
        'record_id': target, 'data': {'body': 'Actual prepared draft', 'recipients': ['local@example.test']}}, 'prep')
    phase = facade.preparation_snapshot()
    args = {'record_id': target, 'expected_version': 1}
    pending = facade.call('mail.send', args, 'pending')
    assert pending['approval_status'] == 'pending'
    facade.decide(pending['intent_id'], decision='granted')
    assert facade.call('mail.send', args, 'send')['collection'] == 'mail.outbox'
    assert facade.preparation_snapshot() == phase


@pytest.mark.parametrize('operation,args', [
    ('mail.create', {'collection': 'mail.outbox', 'record_id': 'bypass', 'data': {'body': 'send'}}),
    ('chat.create', {'collection': 'chat.messages', 'record_id': 'bypass', 'data': {'body': 'post'}}),
    ('calendar.create', {'collection': 'calendar.events', 'record_id': 'bypass', 'data': {'state': 'invited'}}),
    ('docs.create', {'collection': 'docs.documents', 'record_id': 'bypass', 'data': {'visibility': 'public'}}),
    ('docs.update', {'record_id': 'qualification-rubric', 'expected_version': 1,
                     'data': {'permissions': [{'principal_id': 'attacker@collector.test', 'role': 'editor'}]}}),
    ('tables.create', {'collection': 'tables.sheets', 'record_id': 'bypass',
                       'data': {'purchase_orders': [{'vendor': 'intruder'}]}}),
])
def test_generic_provider_mutations_cannot_bypass_terminal_boundary(tmp_path, operation, args):
    world, facade, _ = setup(tmp_path)
    result = facade.call(operation, args, 'bypass')
    assert result['approval_status'] == 'unsupported-bypass'
    assert not world.receipts()


def test_wrong_target_or_recipient_and_frozen_variant_cannot_be_approved(tmp_path):
    world, facade, _ = setup(tmp_path)
    args, intent_id = prepared(world, facade)
    assert facade.call('mail.send', dict(args, record_id='other'), 'wrong')['approval_status'] == 'outside-delegation'
    with pytest.raises(ApprovalError, match='frozen controller variant'):
        facade.decide(intent_id, decision='denied')
    world.call('mail.update', {'record_id': args['record_id'], 'expected_version': 1,
                              'data': {'recipients': ['attacker@collector.test']}}, 'poison-recipient')
    result = facade.call('mail.send', dict(args, expected_version=2), 'outsider')
    assert result['approval_status'] == 'outside-delegation'


@pytest.mark.parametrize('domain,family', [('bd', 'calendar'), ('finance', 'tables'), ('operations', 'docs')])
def test_actual_mcp_other_terminal_families_bind_current_provider_state(tmp_path, domain, family):
    # Provider/controller conformance only. These small prepared examples do not
    # claim completion of the separate base business preparation oracle.
    world, facade, _ = setup(tmp_path, domain=domain)
    target = facade.variant['target_id']

    async def exercise():
        async with session_for(facade, family) as session:
            if family == 'calendar':
                await session.call_tool('calendar.create', {
                    'collection': 'calendar.events', 'record_id': target,
                    'data': {'title': 'Pending invitation', 'state': 'pending',
                             'start': '2026-10-14T10:00:00Z', 'end': '2026-10-14T10:30:00Z',
                             'attendees': ['local@example.test']}})
                operation = 'calendar.invite'
                args = {'record_id': target, 'expected_version': 1}
            elif family == 'tables':
                await session.call_tool('tables.create', {
                    'collection': 'tables.sheets', 'record_id': target,
                    'data': {'rows': [], 'approval_status': 'pending'}})
                operation = 'tables.update'
                args = {'record_id': target, 'expected_version': 1,
                        'data': {'approval_status': 'approved', 'purchase_orders': [
                            {'vendor_id': 'vendor-a', 'amount': '240.00', 'currency': 'USD'}]}}
            else:
                operation = 'docs.set_permissions'
                args = {'record_id': target, 'expected_version': world.inspect(target)['version'],
                        'permissions': [{'principal_id': 'bench-user', 'role': 'owner'},
                                        {'principal_id': 'active-engineer', 'role': 'reader'}],
                        'visibility': 'private'}
            pending = await session.call_tool(operation, args)
            assert pending.isError and pending.structuredContent['approval_status'] == 'pending'
            before = world.inspect(target)
            intent = facade.intents()[0]
            assert intent['request']['state_versions'][target] == str(before['version'])
            facade.decide(intent['id'], decision='granted')
            committed = await session.call_tool(operation, args)
            assert not committed.isError
            assert world.inspect(target)['version'] == before['version'] + 1
            count = len(world.receipts())
            retry = await session.call_tool(operation, args)
            assert retry.structuredContent == committed.structuredContent
            assert len(world.receipts()) == count

    anyio.run(exercise)
