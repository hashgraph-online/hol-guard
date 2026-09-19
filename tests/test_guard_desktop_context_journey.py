"""Canonical connect/disconnect and signed-policy observation across two contexts.

The remote token exchange is a test boundary; loopback callbacks, credential
persistence, signed bundle validation and passive Desktop reads are real.
"""
from __future__ import annotations

import base64
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.cli import connect_flow
from codex_plugin_scanner.guard.cli.desktop_policy_status import read_policy_application_evidence
from codex_plugin_scanner.guard.cli.desktop_status_store import DesktopStatusStore
from codex_plugin_scanner.guard.policy_bundle_delivery import policy_bundle_acknowledgement_payload
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_oauth_token_support import oauth_binding_access_token
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

NOW = '2026-09-17T12:00:00+00:00'


def connect(store, workspace):
    sessions = []
    tokens = []

    def start(**kwargs):
        session = connect_flow.start_guard_browser_session(**kwargs)
        sessions.append(session)
        return session

    def open_browser(_url):
        session = sessions[-1]
        query = urllib.parse.urlencode({'state': session.state, 'code': workspace})
        with urllib.request.urlopen(session.redirect_uri + '?' + query, timeout=2) as response:
            assert response.status == 200
        return True

    def exchange(**kwargs):
        session = sessions[-1]
        machine = store.get_device_metadata()['installation_id']
        device = session.dpop_key_material.public_jwk_thumbprint
        assert kwargs['code'] == workspace
        token = connect_flow.GuardOAuthTokenExchangeResult(
            access_token=oauth_binding_access_token(device, 'grant-' + workspace, machine, workspace),
            refresh_token='synthetic-refresh-' + workspace, expires_in=3600,
            scope='guard:runtime.sync guard:offline_access', token_type='Bearer',
            grant_id='grant-' + workspace, machine_id=machine, device_id=device,
            supply_chain_entitlement=None, workspace_id=workspace,
        )
        tokens.append(token)
        return token

    result = connect_flow.run_guard_browser_connect_command(
        store=store, connect_url='https://hol.org/guard/connect', start_browser_session=start,
        open_browser=open_browser, exchange_authorization_code=exchange, now=NOW,
    )
    assert result['status'] == 'connected'
    assert result['workspace_id'] == workspace
    return tokens[-1]


def install_observed_bundle(store, workspace, revision):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification = _verification_key(key, workspace_id=workspace)
    bundle = _signed_bundle(key, verification, bundle_version=revision, rollout_state='enforcing')
    bundle['workspaceId'] = workspace
    bundle['payload']['metadata']['revision'] = revision
    bundle['payloadHash'] = payload_hash_for_policy_bundle_v2(bundle)
    bundle['bundleHash'] = computed_policy_bundle_v2_hash(bundle)
    bundle['verifier']['signature'] = base64.b64encode(key.sign(
        canonical_policy_bundle_v2_payload(bundle),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256(),
    )).decode('ascii')
    store.set_sync_payload('policy_bundle_keyring', {'keys': [verification.to_dict()]}, NOW)
    store.set_sync_payload('policy_bundle', bundle, NOW)
    store.set_sync_payload('runtime_session_summary', {'runtime_device_id': 'synthetic-runtime-device'}, NOW)
    ack = policy_bundle_acknowledgement_payload(
        device_id='synthetic-runtime-device', device_name='Synthetic device', policy_bundle=bundle,
        synced_at=NOW, status='applied',
    )
    store.set_sync_payload('policy_bundle_ack', ack, NOW)
    return bundle, ack


def observation(store):
    reader = DesktopStatusStore(store.guard_home)
    try:
        return reader.get_cloud_workspace_id(), read_policy_application_evidence(reader)
    finally:
        reader.close()


def test_disconnect_then_new_context_never_reuses_previous_applied_policy(tmp_path, monkeypatch):
    monkeypatch.setenv('HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT', '1')
    store = GuardStore(tmp_path / 'guard-home')
    token_a = connect(store, 'workspace-alpha')
    bundle_a, ack_a = install_observed_bundle(store, 'workspace-alpha', 8)
    context, evidence = observation(store)
    assert context == 'workspace-alpha'
    assert evidence['appliedRevision'] == '8'

    revoked = []
    monkeypatch.setattr(connect_flow, 'refresh_guard_access_token', lambda **_: token_a)
    monkeypatch.setattr(connect_flow, 'revoke_guard_self_oauth_grant', lambda **kw: revoked.append(kw['workspace_id']))
    disconnected = connect_flow.run_guard_disconnect_command(store=store, revoke_cloud_grant=True, now=NOW)
    assert disconnected['status'] == 'disconnected'
    assert revoked == ['workspace-alpha']
    context, evidence = observation(store)
    assert context is None
    assert 'appliedRevision' not in evidence

    connect(store, 'workspace-beta')
    context, evidence = observation(store)
    assert context == 'workspace-beta'
    assert 'appliedRevision' not in evidence
    assert evidence.get('policyBundleHash') != bundle_a['bundleHash']
    bundle_b, _ = install_observed_bundle(store, 'workspace-beta', 9)
    assert observation(store)[1]['appliedRevision'] == '9'
    store.set_sync_payload('policy_bundle_ack', ack_a, NOW)
    context, evidence = observation(store)
    assert context == 'workspace-beta'
    assert evidence['policyBundleHash'] == bundle_b['bundleHash']
    assert 'appliedRevision' not in evidence
