"""Unsupported signed semantics cannot be acknowledged as defaults-only policy."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.native_cloud_policy_capabilities import (
    NativeCloudPolicyRequirement,
    native_cloud_policy_requirements,
    require_native_v3_cloud_policy_support,
)
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _ack, _status
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring
from tests.test_native_cloud_policy_activation import _activate_defaults, _signed_defaults_bundle
from tests.test_policy_bundle_activation_atomicity import _signed_bundle
from tests.test_policy_bundle_v2 import _signed_bundle as _canonical_bundle
from tests.test_policy_bundle_v2 import _verification_key


@pytest.mark.parametrize(
    ("rule", "required"),
    [
        ({"enabled": True, "effect": "block"}, frozenset({NativeCloudPolicyRequirement.SCOPED_RULES})),
        ({"enabled": False, "effect": "block"}, frozenset()),
        ({"enabled": True, "effect": "ignore"}, frozenset()),
        (
            {"enabled": True, "effect": "review", "x-hol-extension-targets": {}},
            frozenset({NativeCloudPolicyRequirement.MANAGED_CONTROLS}),
        ),
    ],
)
def test_canonical_requirements_preserve_active_authority(
    rule: dict[str, object], required: frozenset[NativeCloudPolicyRequirement]
) -> None:
    bundle = {"contractVersion": "guard-policy-bundle.v2", "payload": {"spec": {"rules": [rule]}}}
    assert native_cloud_policy_requirements(bundle) == required
    if required:
        with pytest.raises(NativePolicySnapshotError, match="native_cloud_policy_semantics_unsupported"):
            require_native_v3_cloud_policy_support(bundle)
    else:
        require_native_v3_cloud_policy_support(bundle)


@pytest.mark.parametrize("extension", ["x-hol-extension-controls", "x-hol-custom-extension-continuity"])
def test_empty_extension_payload_still_requires_its_authority_contract(extension: str) -> None:
    bundle = {
        "contractVersion": "guard-policy-bundle.v2",
        "payload": {"spec": {"rules": []}, extension: {}},
    }
    with pytest.raises(NativePolicySnapshotError, match="native_cloud_policy_semantics_unsupported"):
        require_native_v3_cloud_policy_support(bundle)


def test_legacy_exceptions_require_native_authority() -> None:
    bundle = {"contractVersion": "guard-policy-bundle.v1", "rules": [], "cloudExceptions": [{"effect": "allow"}]}
    assert native_cloud_policy_requirements(bundle) == frozenset({NativeCloudPolicyRequirement.CLOUD_EXCEPTIONS})
    with pytest.raises(NativePolicySnapshotError, match="native_cloud_policy_semantics_unsupported"):
        require_native_v3_cloud_policy_support(bundle)


def test_scoped_replacement_revokes_ready_defaults_without_sending_partial_snapshot(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    initial, keyring = _signed_defaults_bundle(1, "allow")
    _activate_defaults(store, initial, keyring)
    pushes: list[bytes] = []

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        pushes.append(payload)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client_request)
    try:
        publisher._publish_once()
        assert publisher.is_ready()
        replacement = _signed_bundle(
            rollout_state="enforcing", bundle_version="policy-scoped-next", issued_at="2026-07-02T00:00:00Z"
        )
        _activate_defaults(store, replacement, policy_bundle_test_keyring())
        publisher._publish_once()
        assert len(pushes) == 1
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        assert publisher.last_error == "native_cloud_policy_semantics_unsupported"
    finally:
        publisher.close()


def test_authenticated_canonical_rules_never_publish_as_defaults_only(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private_key, workspace_id="workspace-alpha")
    bundle = _canonical_bundle(private_key, key, rollout_state="enforcing")
    _activate_defaults(store, bundle, policy_bundle_keyring_payload((key,), workspace_id="workspace-alpha"))

    def client_request(**_kwargs: object) -> bytes:
        pytest.fail("a partial projection must not reach the resident")

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client_request)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        assert publisher.last_error == "native_cloud_policy_semantics_unsupported"
    finally:
        publisher.close()
