"""Receipt-upload ACKs remain bound to their current identity domain."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_delivery import policy_bundle_acknowledgement_payload
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    policy_bundle_keyring_payload,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import validated_policy_bundle_v2_acknowledgement
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import validated_synced_policy_bundle
from tests.policy_bundle_signing_helpers import policy_bundle_test_verification_key, sign_policy_bundle
from tests.test_policy_bundle_delivery_runtime import _v2_delivery
from tests.test_policy_bundle_parser import _sample_policy_bundle
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

_TIME = "2026-09-18T00:00:00Z"
_INSTALLATION = "installation-current"
_CLOUD = "cloud-current"
_NAME = "Current Guard"


def _context(store: GuardStore, *, device_id: str = _INSTALLATION) -> dict[str, object]:
    return runner._receipt_sync_context(
        store, local_guard_online_at=_TIME, device_id=device_id, device_name=_NAME,
    )


def _managed_ack(device_id: str) -> dict[str, object]:
    acknowledgement = {
        "contractVersion": "guard-policy-bundle.v2",
        **_v2_delivery(bundle_version=3),
        "deviceId": device_id,
        "sequence": 1,
        "status": "applied",
        "observedAt": _TIME,
        "appliedExtensionAuthorityRevision": 8,
        "appliedEffectiveProjectionDigest": "sha256:" + "f" * 64,
    }
    assert validated_policy_bundle_v2_acknowledgement(acknowledgement) == (acknowledgement, None)
    return acknowledgement


def _signed_store(
    tmp_path: Path, bundle: dict[str, object], key: PolicyBundleVerificationKey,
) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    workspace_id = bundle["workspaceId"]
    assert isinstance(workspace_id, str)
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": workspace_id}, _TIME)
    store.set_sync_payload(
        "policy_bundle_keyring", policy_bundle_keyring_payload((key,), workspace_id=workspace_id), _TIME,
    )
    store.set_sync_payload("policy_bundle", bundle, _TIME)
    store.set_sync_payload("runtime_session_summary", {"runtime_device_id": _CLOUD}, _TIME)
    assert validated_synced_policy_bundle(store) == bundle
    return store


@pytest.mark.parametrize(
    ("runtime_device_id", "current_device_id", "ack_device_id", "included"),
    [
        (None, _INSTALLATION, _INSTALLATION, True),
        (None, "installation-other", _INSTALLATION, False),
        (_CLOUD, _INSTALLATION, _CLOUD, True),
        ("cloud-other", _INSTALLATION, _CLOUD, False),
        (_CLOUD, _INSTALLATION, _INSTALLATION, False),
    ],
)
def test_managed_ack_uses_current_delivery_device_identity(
    tmp_path: Path,
    runtime_device_id: str | None,
    current_device_id: str,
    ack_device_id: str,
    included: bool,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    if runtime_device_id is not None:
        store.set_sync_payload("runtime_session_summary", {"runtime_device_id": runtime_device_id}, _TIME)
    acknowledgement = _managed_ack(ack_device_id)
    store.set_sync_payload("policy_bundle_ack", acknowledgement, _TIME)

    context = _context(store, device_id=current_device_id)

    assert context["deviceId"] == current_device_id
    assert "policyBundleAcknowledgement" not in context
    assert context.get("policyBundleAcknowledgementV2") == (acknowledgement if included else None)
    assert "deviceName" not in acknowledgement
    assert store.get_sync_payload("policy_bundle_ack") == acknowledgement


def test_malformed_managed_ack_still_fails_closed_for_matching_device(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    acknowledgement = _managed_ack(_INSTALLATION)
    acknowledgement.pop("runtimeSessionId")
    assert validated_policy_bundle_v2_acknowledgement(acknowledgement)[0] is None
    store.set_sync_payload("policy_bundle_ack", acknowledgement, _TIME)

    assert "policyBundleAcknowledgementV2" not in _context(store)
    assert store.get_sync_payload("policy_bundle_ack") == acknowledgement


@pytest.mark.parametrize("ack_device_id", [_INSTALLATION, _CLOUD])
def test_generic_ack_keeps_installation_identity_with_distinct_cloud_device(
    tmp_path: Path, ack_device_id: str,
) -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private, workspace_id="workspace-alpha")
    bundle = _signed_bundle(private, key, rollout_state="enforcing")
    store = _signed_store(tmp_path, bundle, key)
    acknowledgement = policy_bundle_acknowledgement_payload(
        device_id=ack_device_id, device_name=_NAME, policy_bundle=bundle, synced_at=_TIME,
    )
    assert validated_policy_bundle_v2_acknowledgement(acknowledgement) == (acknowledgement, None)
    assert "deliveryId" not in acknowledgement
    store.set_sync_payload("policy_bundle_ack", acknowledgement, _TIME)

    context = _context(store)

    assert context.get("policyBundleAcknowledgementV2") == (
        acknowledgement if ack_device_id == _INSTALLATION else None
    )
    assert "policyBundleAcknowledgement" not in context


@pytest.mark.parametrize(
    ("ack_device_id", "ack_device_name", "included"),
    [(_INSTALLATION, _NAME, True), (_CLOUD, _NAME, False), (_INSTALLATION, "Other Guard", False)],
)
def test_legacy_ack_keeps_device_id_and_name_binding(
    tmp_path: Path, ack_device_id: str, ack_device_name: str, included: bool,
) -> None:
    key = policy_bundle_test_verification_key()
    bundle = sign_policy_bundle(_sample_policy_bundle(), key=key)
    store = _signed_store(tmp_path, bundle, key)
    acknowledgement = policy_bundle_acknowledgement_payload(
        device_id=ack_device_id, device_name=ack_device_name, policy_bundle=bundle, synced_at=_TIME,
    )
    store.set_sync_payload("policy_bundle_ack", acknowledgement, _TIME)

    context = _context(store)

    assert context.get("policyBundleAcknowledgement") == (acknowledgement if included else None)
    assert "policyBundleAcknowledgementV2" not in context
    assert store.get_sync_payload("policy_bundle_ack") == acknowledgement
