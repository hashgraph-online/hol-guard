from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_v2 import validated_policy_bundle_v2_payload
from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.custom_extension_continuity import CustomExtensionContinuityError
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.network import stub_authenticated_urlopen
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key


def test_signed_v2_bundle_validates_canonical_document_and_rsa_pss_signature() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    bundle = _signed_bundle(private_key, verification_key)
    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )
    assert reason is None and validated == bundle


def test_custom_extension_continuity_is_covered_by_bundle_signature() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(
        private_key,
        verification_key,
        payload_extensions={
            "x-hol-custom-extension-continuity": {
                "schemaVersion": "guard.custom-extension-continuity.v1",
                "revision": 1,
                "observedAt": "2026-07-15T12:00:00Z",
                "expiresAt": "2030-07-15T12:00:00Z",
                "items": [],
            }
        },
    )
    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )
    assert reason is None and validated == bundle
    payload = cast(dict[str, object], bundle["payload"])
    continuity = cast(dict[str, object], payload["x-hol-custom-extension-continuity"])
    continuity["revision"] = 2
    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )
    assert validated is None and reason == "payload_hash_mismatch"


def test_sync_receipts_consumes_signed_custom_extension_continuity_in_production_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    identity = UnlistedCliIdentity(
        cli_id="local-cli.release-tool-12345678",
        name="release-tool",
        kind="executable",
        identity_hash="a" * 64,
        example_label="release-tool",
    )
    continuity = {
        "schemaVersion": "guard.custom-extension-continuity.v1",
        "revision": 1,
        "observedAt": "2026-08-25T15:00:00Z",
        "expiresAt": "2030-08-25T15:00:00Z",
        "items": [
            {
                "cliId": identity.cli_id,
                "identityHash": identity.identity_hash,
                "settings": {"state": "blocked", "commands": {"deploy": "block"}},
            }
        ],
    }
    bundle = _signed_bundle(
        private_key,
        verification_key,
        payload_base={
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "policy.continuity", "name": "Continuity", "revision": 1},
            "spec": {"defaults": {"mode": "prompt", "defaultAction": "warn"}, "rules": []},
        },
        payload_extensions={"x-hol-custom-extension-continuity": continuity},
    )
    store = GuardStore(tmp_path / "guard-home")
    store.record_local_cli_observation(identity, seen_at="2026-08-25T15:00:00Z", help_status="ok")
    store.replace_local_cli_commands(
        identity.cli_id,
        (LocalCliCommand("deploy", "deploy", "deploy", "Deploy safely"),),
    )
    store.set_sync_payload("policy_bundle_keyring", {"keys": [verification_key.to_dict()]}, "2026-08-25T15:00:00Z")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, "2026-08-25T15:00:00Z")
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        "GUARD_EXTENSION_FIRST_CONTROLS_UI",
    ):
        monkeypatch.setenv(name, "true")

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            del exc_type, exc, traceback
            return False

        def read(self) -> bytes:
            return json.dumps(
                {"syncedAt": "2026-08-25T16:00:00Z", "receiptsStored": 0, "policyBundle": bundle}
            ).encode()

    stub_authenticated_urlopen(monkeypatch, lambda request, timeout: _Response())
    monkeypatch.setattr(guard_runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(guard_runner, "sync_guard_events", lambda _store, auth_context=None: 0)
    summary = guard_runner.sync_receipts(
        store,
        auth_context={
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "test-token",
            "dpop_key_material": None,
        },
    )
    grant = store.read_local_cli_grant(identity.cli_id)
    remote_policies_stored = summary["remote_policies_stored"]
    assert isinstance(remote_policies_stored, int) and remote_policies_stored >= 0
    assert grant is not None and grant["state"] == "blocked"
    assert store.get_sync_payload("policy_bundle_ack") == {}
    assert store.read_local_cli_command_states(identity.cli_id) == {"deploy": "block"}
    state = store.get_sync_payload("custom_extension_continuity")
    assert isinstance(state, dict)
    state_items = state.get("items")
    assert isinstance(state_items, dict)
    identity_state = state_items.get(identity.cli_id)
    assert isinstance(identity_state, dict) and identity_state["status"] == "applied"

    policy_before = store.get_sync_payload("policy_bundle")
    acknowledgement_before = store.get_sync_payload("policy_bundle_ack")
    changed_continuity = {
        **continuity,
        "observedAt": "2026-08-25T15:30:00Z",
        "expiresAt": "2030-08-25T15:30:00Z",
    }
    conflicting_bundle = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=9,
        payload_base={
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "policy.continuity", "name": "Continuity", "revision": 2},
            "spec": {"defaults": {"mode": "prompt", "defaultAction": "warn"}, "rules": []},
        },
        payload_extensions={"x-hol-custom-extension-continuity": changed_continuity},
    )

    class _ConflictingResponse(_Response):
        def read(self) -> bytes:
            return json.dumps(
                {
                    "syncedAt": "2026-08-25T16:30:00Z",
                    "receiptsStored": 0,
                    "policyBundle": conflicting_bundle,
                }
            ).encode()

    stub_authenticated_urlopen(monkeypatch, lambda request, timeout: _ConflictingResponse())
    with pytest.raises(CustomExtensionContinuityError, match="revision payload changed"):
        guard_runner.sync_receipts(
            store,
            auth_context={
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "access_token": "test-token",
                "dpop_key_material": None,
            },
        )
    assert store.get_sync_payload("policy_bundle") == policy_before
    assert store.get_sync_payload("policy_bundle_ack") == acknowledgement_before


@pytest.mark.parametrize(
    ("protected_authority", "negotiated", "expected_error"),
    [
        (False, True, "requires protected extension authority"),
        (True, False, "capability was not negotiated"),
        (True, True, None),
    ],
)
def test_production_sync_enforces_v2_authority_and_effective_negotiation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protected_authority: bool,
    negotiated: bool,
    expected_error: str | None,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    store = GuardStore(tmp_path / "guard-home")
    if protected_authority:
        store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            key=None,
        )
    identity = UnlistedCliIdentity(
        cli_id="local-cli.release-tool-v2-12345678",
        name="release-tool-v2",
        kind="executable",
        identity_hash="b" * 64,
        example_label="release-tool-v2",
    )
    store.record_local_cli_observation(identity, seen_at="2026-08-25T15:00:00Z", help_status="ok")
    device_id = cast(str, store.get_device_metadata()["installation_id"])

    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    continuity = {
        "schemaVersion": "guard.custom-extension-continuity.v2",
        "revision": 1,
        "observedAt": "2026-08-25T15:00:00Z",
        "expiresAt": "2030-08-25T15:00:00Z",
        "items": [
            {
                "identityHash": digest(
                    f"guard.custom-extension-continuity.v1:workspace-alpha:{identity.identity_hash}"
                ),
                "deviceIdentityHashes": [
                    digest(f"guard.custom-extension-continuity.v1:device:workspace-alpha:{device_id}")
                ],
                "state": "blocked",
            }
        ],
    }
    bundle = _signed_bundle(
        private_key,
        verification_key,
        payload_base={
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "policy.continuity-v2", "name": "Continuity v2", "revision": 1},
            "spec": {"defaults": {"mode": "prompt", "defaultAction": "warn"}, "rules": []},
        },
        payload_extensions={"x-hol-custom-extension-continuity": continuity},
    )
    store.set_sync_payload("policy_bundle_keyring", {"keys": [verification_key.to_dict()]}, "2026-08-25T15:00:00Z")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, "2026-08-25T15:00:00Z")
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        "GUARD_EXTENSION_FIRST_CONTROLS_UI",
    ):
        monkeypatch.setenv(name, "true")

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            del exc_type, exc, traceback
            return False

        def read(self) -> bytes:
            payload: dict[str, object] = {
                "syncedAt": "2026-08-25T16:00:00Z",
                "receiptsStored": 0,
                "policyBundle": bundle,
            }
            if negotiated:
                payload["managedControlsCapabilities"] = ["custom-extension-continuity.v2"]
            return json.dumps(payload).encode()

    stub_authenticated_urlopen(monkeypatch, lambda request, timeout: _Response())
    monkeypatch.setattr(guard_runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(guard_runner, "sync_guard_events", lambda _store, auth_context=None: 0)

    def invoke() -> dict[str, object]:
        return guard_runner.sync_receipts(
            store,
            auth_context={
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "access_token": "test-token",
                "dpop_key_material": None,
            },
        )

    if expected_error is not None:
        with pytest.raises(CustomExtensionContinuityError, match=expected_error):
            invoke()
        assert store.read_local_cli_grant(identity.cli_id) is None
        assert store.get_sync_payload("policy_bundle") is None
    else:
        invoke()
        grant = store.read_local_cli_grant(identity.cli_id)
        assert grant is not None and grant["state"] == "blocked"
        assert store.get_sync_payload("policy_bundle") == bundle
