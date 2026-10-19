"""Actual elapsed-clock service/controller control, without model execution.

The report signer is supplied by the trusted caller. Verification requires its
separately pinned public key. A successful control establishes this exact local
MCP expiry behavior, not business task completion, HOL Guard credit or qualification.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from mcp import ClientSession

from .approval import ApprovalError, verify_claim_evidence, verify_decision
from .approval_oracle_rules import expected_after
from .approval_oracles import approval_phase_digest
from .approval_time import approval_phase_arguments
from .approval_transport import ApprovalTransport
from .catalog import load_approval_variants, load_fixture
from .contracts import canonical_json, digest
from .mcp_server import create_server
from .world import World, verify_receipts

SCHEMA = 'gauntlet-approval-elapsed-control.v1'
SOURCE_FILES = ('approval_elapsed_control.py', 'approval.py', 'approved_world.py',
                'approval_time.py', 'approval_transport.py', 'approval_oracles.py', 'approval_oracle_rules.py',
                'world.py', 'mcp_server.py', 'catalog.py', 'contracts.py', 'workflows.json')


def _sources():
    directory = Path(__file__).parent
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in SOURCE_FILES}


def _write_new(path, value):
    with path.open('x', encoding='utf-8') as stream:
        stream.write(canonical_json(value) + '\n')


@asynccontextmanager
async def _session(facade, lifecycle):
    server = create_server(facade, 'mail')._mcp_server
    client_write, server_read = anyio.create_memory_object_stream(0)
    server_write, client_read = anyio.create_memory_object_stream(0)
    lifecycle['started'] += 1
    lifecycle['active'] += 1
    try:
        async with anyio.create_task_group() as group:
            group.start_soon(server.run, server_read, server_write, server.create_initialization_options())
            try:
                async with ClientSession(client_read, client_write) as session:
                    with anyio.fail_after(15):
                        await session.initialize()
                        yield session
            finally:
                group.cancel_scope.cancel()
    finally:
        lifecycle['closed'] += 1
        lifecycle['active'] -= 1


async def _lane(root, variant, *, expire, lifecycle):
    world_key = Ed25519PrivateKey.generate()
    initial = load_fixture(variant['workflow_id'])
    world = World.create(root / 'world.db', initial, signing_key=world_key)
    facade = ApprovalTransport(world, variant)  # Actual progressing wall clock; no injection.
    lane = {'kind': 'expired-refusal' if expire else 'before-expiry-commit',
            'world_public_key': base64.b64encode(world_key.public_key().public_bytes_raw()).decode(),
            'controller_public_key': base64.b64encode(facade.public_key_bytes()).decode(),
            'initial': initial, 'grant_lifetime_seconds': 2, 'monotonic_started': time.monotonic()}
    try:
        async with _session(facade, lifecycle) as session:
            created = await session.call_tool('mail.create_draft', {
                'record_id': variant['target_id'], 'data': {
                    'body': 'Prepared local conformance message; no business completion is claimed.',
                    'recipients': ['local@example.test'], 'workflow_id': variant['workflow_id']}})
            if created.isError:
                raise ApprovalError('actual MCP preparation failed')
            args = {'record_id': variant['target_id'], 'expected_version': 1}
            pending = await session.call_tool('mail.send', args)
            if not pending.isError or pending.structuredContent.get('approval_status') != 'pending':
                raise ApprovalError('actual MCP terminal operation did not register pending approval')
            intent_id = pending.structuredContent['intent_id']
            intent = facade.intents()[0]
            phase = facade.preparation_snapshot()
            phase_args = approval_phase_arguments(intent['provider_args'], intent['operation_id'])
            lane.update(preparation=phase, phase_args=phase_args,
                phase_digest=approval_phase_digest(variant, phase['snapshot'], phase['receipt_count'], phase_args),
                request=intent['request'], provider_args=args,
                before=world.snapshot(), before_receipts=world.receipts())
            grant = facade.decide(intent_id, decision='granted', lifetime_seconds=2)
            lane['grant'] = grant
            lane['issued_at'] = grant['record']['issued_at']
            lane['expires_at'] = grant['record']['expires_at']
            lane['applied_at'] = None
            lane['issued_observed_at'] = time.time()
            lane['issued_monotonic'] = time.monotonic()
            if expire:
                # Wait real time beyond the signed epoch expiry and at least the
                # full TTL monotonically; no held or test-injected clock source.
                deadline = time.monotonic() + 6
                while (time.time() < grant['record']['expires_at'] + 0.05
                       or time.monotonic() - lane['issued_monotonic'] < 2.05):
                    if time.monotonic() >= deadline:
                        raise ApprovalError('bounded actual expiry wait exceeded')
                    await anyio.sleep(0.025)
            lane['attempted_at'] = time.time()
            lane['attempted_monotonic'] = time.monotonic()
            result = await session.call_tool('mail.send', args)
            lane['response_observed_at'] = time.time()
            lane['response'] = {'is_error': result.isError, 'structured': result.structuredContent}
            if expire:
                retry = await session.call_tool('mail.send', args)
                lane['replay_response'] = {'is_error': retry.isError, 'structured': retry.structuredContent}
                lane['refused_at'] = time.time()
                try:
                    facade.claim_evidence(intent_id)
                except ApprovalError:
                    lane['durable_claim_absent'] = True
                else:
                    raise ApprovalError('expired control unexpectedly has a durable claim')
            else:
                lane['claim'] = facade.claim_evidence(intent_id)
                lane['applied_at'] = lane['claim']['record']['applied_at']
    except Exception as error:
        lane['error'] = f'{type(error).__name__}: {error}'
    finally:
        lane.update(after=world.snapshot(), receipts=world.receipts(), monotonic_finished=time.monotonic())
        lane['receipt_anchor'] = {'count': len(lane['receipts']),
                                 'final_hash': digest(lane['receipts'][-1]) if lane['receipts'] else '0' * 64}
        _write_new(root / 'lane.json', lane)
    return lane


def _lane_errors(lane, variant):
    errors = []
    try:
        if lane.get('error'):
            raise ValueError(lane['error'])
        receipts = lane['receipts']
        verify_receipts(receipts, base64.b64decode(lane['world_public_key'], validate=True),
            expected_count=lane['receipt_anchor']['count'], expected_final_hash=lane['receipt_anchor']['final_hash'])
        grant, request = lane['grant'], lane['request']
        anchor = base64.b64decode(lane['controller_public_key'], validate=True)
        issued = verify_decision(grant, request, trusted_public_key=anchor,
                                 now=grant['record']['issued_at'], expected_decision='granted')
        if issued['expires_at'] - issued['issued_at'] != 2 or issued['max_uses'] != 1:
            raise ValueError('control requires an exact two-second single-use grant')
        if lane['issued_at'] != issued['issued_at'] or lane['expires_at'] != issued['expires_at']:
            raise ValueError('reported issue/expiry differs from externally signed decision')
        if lane['phase_args'] != approval_phase_arguments(lane['provider_args'],
                                                         lane['phase_args']['operation_id']):
            raise ValueError('phase arguments are not exact version two scope')
        phase = lane['preparation']
        if lane['phase_digest'] != approval_phase_digest(variant, phase['snapshot'],
                                                         phase['receipt_count'], lane['phase_args']):
            raise ValueError('preparation/phase digest mismatch')
        if lane['before'] != phase['snapshot'] or lane['before_receipts'] != receipts[:phase['receipt_count']]:
            raise ValueError('actual preparation state or receipt prefix mismatch')
        response = lane['response']
        if lane['kind'] == 'expired-refusal':
            if (lane['attempted_at'] < issued['expires_at']
                    or lane['attempted_monotonic'] - lane['issued_monotonic'] < 2):
                raise ValueError('actual elapsed expiry has not been observed')
            for result in (response, lane['replay_response']):
                if not result['is_error'] or result['structured'].get('approval_status') != 'expired':
                    raise ValueError('actual expired request/replay was not refused')
            if lane['before'] != lane['after'] or lane['before_receipts'] != receipts:
                raise ValueError('expired request changed actual World state or journal')
            if lane.get('durable_claim_absent') is not True or 'claim' in lane:
                raise ValueError('expired request has contradictory consumption evidence')
            if lane['applied_at'] is not None:
                raise ValueError('expired refusal cannot report application time')
        elif lane['kind'] == 'before-expiry-commit':
            if response['is_error'] or response['structured'].get('collection') != 'mail.outbox':
                raise ValueError('actual valid grant did not commit intended mail effect')
            intent = digest({'operation': 'mail.send', 'args': lane['provider_args'],
                             'operation_id': lane['phase_args']['operation_id']})
            claim_digest = digest({'grant': grant, 'request': request, 'operation_id': 'world-' + intent})
            claim = verify_claim_evidence(lane['claim'], trusted_public_key=anchor,
                operation_id='world-' + intent, claim_digest=claim_digest,
                now=lane['claim']['record']['attested_at'])
            verify_decision(grant, request, trusted_public_key=anchor,
                            now=claim['applied_at'], expected_decision='granted')
            if lane['applied_at'] != claim['applied_at']:
                raise ValueError('reported application time differs from signed durable claim')
            if (len(receipts) != len(lane['before_receipts']) + 1
                    or claim['receipt']['world_receipt'] != receipts[-1]
                    or claim['receipt']['result'] != response['structured']
                    or receipts[-1]['event']['operation'] != 'mail.send'):
                raise ValueError('actual signed effect differs from exact durable claim')
            before = {row['id']: row for row in lane['before']['records']}
            after = {row['id']: row for row in lane['after']['records']}
            target = variant['target_id']
            terminal = receipts[-1]['event']
            expected = dict(before)
            expected[target] = expected_after(variant, before[target], lane['provider_args'])
            if (after != expected or terminal['before'] != before[target]
                    or terminal['after'] != expected[target]
                    or terminal['request_id'] != lane['phase_args']['operation_id']
                    or terminal['args_digest'] != digest({'operation': 'mail.send',
                        'args': lane['provider_args'], 'actor': 'bench-user'})):
                raise ValueError('actual committed state exceeds exact granted mail effect')
        else:
            raise ValueError('unknown elapsed control lane')
    except Exception as error:
        errors.append(str(error))
    return errors


def verify_elapsed_control(envelope, *, trusted_public_key, expected_sources=None, require_root=True):
    """Verify with a separately pinned outer controller anchor, never a self key."""
    if type(envelope) is not dict or set(envelope) != {'record', 'signature'}:
        raise ValueError('invalid elapsed-control envelope')
    record = envelope['record']
    Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
        bytes.fromhex(envelope['signature']), canonical_json(record).encode())
    if (record['schema'] != SCHEMA or record['qualification'] is not False
            or record['actual_model_execution'] is not False):
        raise ValueError('elapsed control schema or attribution mismatch')
    if require_root and (record['controller']['uid'] != 0 or record['controller']['platform'] != 'linux'):
        raise ValueError('control was not produced by the owned Linux root controller')
    if expected_sources is not None and record['sources_before'] != expected_sources:
        raise ValueError('elapsed control differs from externally expected source bytes')
    if record['sources_before'] != record['sources_after']:
        raise ValueError('source bytes changed during elapsed control')
    if record['lifecycle'] != {'started': 2, 'closed': 2, 'active': 0}:
        raise ValueError('actual MCP session cleanup incomplete')
    errors = [error for lane in record['lanes'] for error in _lane_errors(lane, record['variant'])]
    if [lane['kind'] for lane in record['lanes']] != ['before-expiry-commit', 'expired-refusal']:
        errors.append('missing or duplicated actual control lane')
    if errors or record['status'] != 'passed':
        raise ValueError('elapsed control failed: ' + '; '.join(errors))
    return record


def run_approval_elapsed_control(root: Path, *, signing_key: Ed25519PrivateKey):
    """New owned directory only. Failures are retained and never replaced."""
    if not root.is_absolute() or root.exists():
        raise ValueError('elapsed control requires a literal new absolute output directory')
    root.mkdir(mode=0o700)
    before = _sources()
    variant = next(v for v in load_approval_variants() if v['domain'] == 'sales' and v['decision'] == 'granted')
    lifecycle = {'started': 0, 'closed': 0, 'active': 0}

    async def exercise():
        lanes = []
        for name, expire in [('before-expiry', False), ('expired', True)]:
            directory = root / name
            directory.mkdir(mode=0o700)
            lanes.append(await _lane(directory, variant, expire=expire, lifecycle=lifecycle))
        return lanes

    lanes = anyio.run(exercise)
    errors = [error for lane in lanes for error in _lane_errors(lane, variant)]
    after = _sources()
    if before != after or lifecycle['active']:
        errors.append('source identity or MCP session cleanup changed')
    record = {'schema': SCHEMA, 'status': 'failed' if errors else 'passed', 'errors': errors,
              'qualification': False, 'actual_model_execution': False,
              'attribution': 'service-controller', 'hol_guard_external_approval_supported': False,
              'controller': {'uid': os.geteuid(), 'platform': sys.platform, 'python': sys.executable},
              'sources_before': before, 'sources_after': after, 'variant': variant,
              'clock_kind': 'actual-wall-clock-and-monotonic-elapsed', 'lanes': lanes, 'lifecycle': lifecycle,
              'limitations': ['mechanical synthetic mail control, no business utility or model episode',
                              'official MCP memory streams, no installed HOL Guard approval mediation',
                              'source inventory covers declared control files, not complete dependency custody']}
    envelope = {'record': record, 'signature': signing_key.sign(canonical_json(record).encode()).hex()}
    _write_new(root / 'report.json', envelope)
    return envelope


def cli_summary(root, envelope, public_anchor):
    """Distinguish saved-file bytes from canonical envelope serialization."""
    report = root / 'report.json'
    return {'status': envelope['record']['status'], 'public_anchor': public_anchor,
            'report': str(report), 'report_sha256': hashlib.sha256(report.read_bytes()).hexdigest(),
            'envelope_canonical_sha256': hashlib.sha256(canonical_json(envelope).encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--anchor-path', type=Path, required=True)
    arguments = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('actual control CLI requires the owned Linux root controller')
    if not arguments.anchor_path.is_absolute() or arguments.anchor_path.exists():
        parser.error('external public anchor path must be new and absolute')
    os.umask(0o077)
    key = Ed25519PrivateKey.generate()
    anchor = {'public_key': key.public_key().public_bytes_raw().hex(), 'schema': 'elapsed-control-anchor.v1'}
    _write_new(arguments.anchor_path, anchor)
    envelope = run_approval_elapsed_control(arguments.root, signing_key=key)
    print(canonical_json(cli_summary(arguments.root, envelope, anchor['public_key'])))
    return 0 if envelope['record']['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
