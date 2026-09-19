"""Signed Cloud defaults must reach the resident policy before application."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import validated_synced_policy_bundle
from tests.native_policy_snapshot_test_fixtures import _ack, _status
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.test_policy_bundle_activation_atomicity import _signed_bundle as _legacy_bundle
from tests.test_policy_bundle_v2 import _signed_bundle as _canonical_bundle
from tests.test_policy_bundle_v2 import _verification_key


def _signed_defaults_bundle(version: int, action: str) -> tuple[dict[str, object], dict[str, object]]:
    if version == 1:
        bundle = _legacy_bundle(rollout_state="enforcing")
        bundle["rules"] = []
        defaults = bundle["policyDefaults"]
        assert isinstance(defaults, dict)
        defaults.update({"mode": "enforce", "defaultAction": action})
        return sign_policy_bundle(bundle), policy_bundle_test_keyring()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private_key, workspace_id="workspace-alpha")
    bundle = _canonical_bundle(private_key, key)
    payload = bundle["payload"]
    assert isinstance(payload, dict)
    spec = payload["spec"]
    assert isinstance(spec, dict)
    spec["rules"] = []
    spec["defaults"] = {"mode": "enforce", "defaultAction": action}
    return (
        _canonical_bundle(private_key, key, payload_base=payload, rollout_state="enforcing"),
        policy_bundle_keyring_payload((key,), workspace_id="workspace-alpha"),
    )


def _activate_defaults(store: GuardStore, bundle: dict[str, object], keyring: dict[str, object]) -> None:
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": bundle["workspaceId"]}, "2026-09-17T00:00:00Z")
    assert (
        store.apply_policy_bundle_authority(
            [],
            "2026-09-17T00:00:00Z",
            policy_bundle=bundle,
            policy_bundle_keyring=keyring,
            cloud_exceptions=[],
            policy_bundle_ack={
                "bundleHash": bundle["bundleHash"],
                "bundleVersion": bundle["bundleVersion"],
                "status": "synced",
            },
            policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
            update_last_good=True,
            remote_write_authorized=True,
        )
        is not None
    )
    assert validated_synced_policy_bundle(store) == bundle


@pytest.mark.parametrize("version", [1, 2])
def test_signed_default_is_present_in_the_acknowledged_native_snapshot(tmp_path: Path, version: int) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle, keyring = _signed_defaults_bundle(version, "block")
    _activate_defaults(store, bundle, keyring)

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client_request)
    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        snapshot = publisher.current_snapshot()
        assert isinstance(snapshot, dict)
        effective_policy = snapshot["effective_policy"]
        assert isinstance(effective_policy, dict)
        assert effective_policy["default_action"] == "block"
    finally:
        publisher.close()
