"""Atomic policy-bundle and custom Extension continuity regressions."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.custom_extension_continuity import (
    prepare_verified_custom_extension_continuity,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_custom_extension_continuity import CustomExtensionContinuityMutation
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring
from tests.test_policy_bundle_activation_atomicity import (
    _WORKSPACE_ID,
    _activate_bundle,
    _signed_bundle,
)


def _continuity_mutation(store: GuardStore) -> tuple[UnlistedCliIdentity, CustomExtensionContinuityMutation]:
    identity = UnlistedCliIdentity(
        cli_id="local-cli.atomic-continuity-12345678",
        name="atomic-continuity",
        kind="executable",
        identity_hash="c" * 64,
        example_label="atomic-continuity",
    )
    store.record_local_cli_observation(identity, seen_at="2026-08-27T12:00:00Z", help_status="ok")
    mutation, _state = prepare_verified_custom_extension_continuity(
        store,
        {
            "payload": {
                "x-hol-custom-extension-continuity": {
                    "schemaVersion": "guard.custom-extension-continuity.v1",
                    "revision": 1,
                    "observedAt": "2026-08-27T12:00:00Z",
                    "expiresAt": "2026-08-28T12:00:00Z",
                    "items": [
                        {
                            "cliId": identity.cli_id,
                            "identityHash": identity.identity_hash,
                            "settings": {"state": "blocked", "commands": {}},
                        }
                    ],
                }
            }
        },
        now="2026-08-27T12:00:00Z",
    )
    assert mutation is not None
    return identity, mutation


def _activate_with_continuity(
    store: GuardStore,
    bundle: dict[str, object],
    mutation: CustomExtensionContinuityMutation,
    *,
    now: str,
    capabilities: frozenset[str] = frozenset(),
) -> dict[str, object] | None:
    device = store.get_device_metadata()
    return store.apply_policy_bundle_authority(
        build_policy_bundle_decisions(
            bundle,
            device_id=device["installation_id"],
            device_name=device["device_label"],
        ),
        now,
        policy_bundle=bundle,
        policy_bundle_keyring=policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID),
        cloud_exceptions=[],
        policy_bundle_ack={"status": "synced"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        managed_controls_negotiated_capabilities=capabilities,
        custom_extension_continuity=mutation,
        remote_write_authorized=True,
    )


def test_activation_rejection_after_continuity_preflight_writes_neither_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity, mutation = _continuity_mutation(store)
    newer = _signed_bundle(
        rollout_state="enforcing",
        bundle_version="policy-2026-08-27.2",
        issued_at="2026-08-27T13:00:00Z",
    )
    older = _signed_bundle(
        rollout_state="enforcing",
        bundle_version="policy-2026-08-27.1",
        issued_at="2026-08-27T12:00:00Z",
    )
    assert _activate_bundle(store, newer, "2026-08-27T13:00:00Z") is not None
    policy_before = store.get_sync_payload("policy_bundle")

    assert _activate_with_continuity(store, older, mutation, now="2026-08-27T14:00:00Z") is None
    assert store.get_sync_payload("policy_bundle") == policy_before
    assert store.get_sync_payload("custom_extension_continuity") is None
    assert store.read_local_cli_grant(identity.cli_id) is None


def test_policy_and_continuity_roll_back_together_on_continuity_commit_fault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity, mutation = _continuity_mutation(store)
    bundle = _signed_bundle(
        rollout_state="enforcing",
        bundle_version="policy-2026-08-27.1",
        issued_at="2026-08-27T12:00:00Z",
    )

    def fail_after_continuity(stage: str) -> None:
        if stage == "after_event":
            raise ValueError("injected continuity failure")

    monkeypatch.setattr(store, "_custom_extension_continuity_transaction_boundary", fail_after_continuity)
    assert _activate_with_continuity(store, bundle, mutation, now="2026-08-27T12:00:00Z") is None
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert store.get_sync_payload("custom_extension_continuity") is None
    assert store.read_local_cli_grant(identity.cli_id) is None


def test_atomic_commit_rechecks_v2_authority_and_negotiated_capability(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity, base_mutation = _continuity_mutation(store)
    mutation = replace(
        base_mutation,
        requires_protected_extension_authority=True,
        required_negotiated_capability="custom-extension-continuity.v2",
    )
    bundle = _signed_bundle(
        rollout_state="enforcing",
        bundle_version="policy-2026-08-27.1",
        issued_at="2026-08-27T12:00:00Z",
    )
    capability = frozenset({"custom-extension-continuity.v2"})

    assert (
        _activate_with_continuity(
            store,
            bundle,
            mutation,
            now="2026-08-27T12:00:00Z",
            capabilities=capability,
        )
        is None
    )
    assert store.get_sync_payload("policy_bundle") is None
    store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        key=None,
    )
    assert _activate_with_continuity(store, bundle, mutation, now="2026-08-27T12:00:00Z") is None
    assert store.get_sync_payload("policy_bundle") is None
    assert (
        _activate_with_continuity(
            store,
            bundle,
            mutation,
            now="2026-08-27T12:00:00Z",
            capabilities=capability,
        )
        is not None
    )
    assert store.read_local_cli_grant(identity.cli_id) is not None
    assert store.get_sync_payload("custom_extension_continuity") is not None
