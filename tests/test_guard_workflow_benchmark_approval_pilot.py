"""Controller conformance; no synthetic model transcript or host candidate execution."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.approval import ApprovalError
from ci.gauntlet.benchmark.approval_pilot import run_approval_pilot, select_intent
from ci.gauntlet.benchmark.approval_transport import ApprovalTransport
from ci.gauntlet.benchmark.catalog import load_approval_variants, load_fixture
from ci.gauntlet.benchmark.world import World


def test_approval_runner_refuses_host_before_world_or_process(monkeypatch, tmp_path):
    import ci.gauntlet.benchmark.approval_pilot as module

    monkeypatch.setattr(module.sys, 'platform', 'darwin')
    monkeypatch.setattr(module, 'World', None)
    with pytest.raises(ValueError, match='isolated Linux root'):
        run_approval_pilot(root=tmp_path / 'run', variant_id='sales-granted', bun=Path('/bun'),
                           sdk_root=Path('/sdk'), model_id='local-model')
    assert not (tmp_path / 'run').exists()


def test_controller_selects_only_actual_pending_scope_not_claimed_approval(tmp_path):
    variant = next(v for v in load_approval_variants() if v['id'] == 'sales-granted')
    world = World.create(tmp_path / 'world.db', load_fixture(variant['workflow_id']),
                         signing_key=Ed25519PrivateKey.generate())
    facade = ApprovalTransport(world, variant, clock=lambda: 1000)
    with pytest.raises(ApprovalError, match='exactly one'):
        select_intent(facade)
    assert facade.call('mail.send', {'record_id': 'forged-target', 'expected_version': 1}, 'claimed-grant')[
        'approval_status'] == 'outside-delegation'
    assert not facade.intents()
    facade.call('mail.create_draft', {'record_id': variant['target_id'],
        'data': {'body': 'Controller conformance only', 'recipients': ['local@example.test']}}, 'prepare')
    args = {'record_id': variant['target_id'], 'expected_version': 1}
    pending = facade.call('mail.send', args, 'actual-request')
    intent = select_intent(facade)
    assert intent['id'] == pending['intent_id']
    assert intent['provider_args'] == args
    assert intent['request_id'] == 'actual-request'
    # Different actual scopes are ambiguous; the controller cannot choose a
    # model-preferred winner, and no grant is issued for either.
    facade.call('mail.update', {'record_id': variant['target_id'], 'expected_version': 1,
                               'data': {'body': 'Changed preparation'}}, 'change')
    facade.call('mail.send', dict(args, expected_version=2), 'ambiguous')
    with pytest.raises(ApprovalError, match='exactly one'):
        select_intent(facade)
    assert world.inspect(variant['target_id'])['collection'] == 'mail.drafts'
