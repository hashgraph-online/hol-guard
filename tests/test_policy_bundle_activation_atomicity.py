"""Atomic activation and cached policy-bundle authority regressions."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.custom_extension_continuity import (
    prepare_verified_custom_extension_continuity,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import (
    synced_policy_bundle_validation,
    synced_policy_payload,
    validated_synced_policy_bundle,
)
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle

_WORKSPACE_ID = "workspace-1"
_INACTIVE_ARTIFACT_ID = "codex:project:inactive-signed-allow"


def _signed_bundle(
    *,
    rollout_state: str,
    bundle_version: str | None = None,
    issued_at: str = "2026-07-01T00:00:00Z",
) -> dict[str, object]:
    return sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": bundle_version or f"policy-2026-07-18.{rollout_state}",
            "bundleHash": "",
            "issuedAt": issued_at,
            "expiresAt": None,
            "verifier": {
                "algorithm": "rsa-pss-sha256",
                "keyId": "test-only-placeholder",
                "signature": None,
            },
            "rolloutState": rollout_state,
            "policyDefaults": {
                "mode": "observe",
                "defaultAction": "allow",
                "unknownPublisherAction": "allow",
                "changedHashAction": "allow",
                "newNetworkDomainAction": "allow",
                "subprocessAction": "allow",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": [
                {
                    "ruleId": "inactive-exact-allow",
                    "action": "allow",
                    "reason": "An inactive rollout must never authorize this artifact.",
                    "artifactId": _INACTIVE_ARTIFACT_ID,
                    "scope": {
                        "agents": [],
                        "devices": [],
                        "ecosystems": [],
                        "environments": [],
                        "harnesses": ["codex"],
                        "locations": [],
                    },
                }
            ],
            "cloudExceptions": [],
            "acknowledgements": [],
        },
        workspace_id=_WORKSPACE_ID,
    )


def _sorted_policy_rows(store: GuardStore) -> list[dict[str, object]]:
    return sorted(store.list_policy_decisions(), key=lambda row: str(row["decision_id"]))


def _activate_bundle(store: GuardStore, bundle: dict[str, object], now: str) -> dict[str, object] | None:
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
        policy_bundle_ack={
            "bundleHash": bundle["bundleHash"],
            "bundleVersion": bundle["bundleVersion"],
            "deviceId": device["installation_id"],
            "status": "synced",
        },
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )


def test_apply_policy_bundle_authority_rolls_back_every_authority_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    prior_now = "2026-07-17T00:00:00Z"
    prior_state: dict[str, dict[str, object] | list[object]] = {
        "cloud_exceptions": [{"id": "prior-exception", "effect": "allow"}],
        "policy": {"defaultAction": "block"},
        "policy_bundle": {"bundleVersion": "prior-bundle"},
        "policy_bundle_ack": {"bundleVersion": "prior-bundle", "status": "synced"},
        "policy_bundle_acceptance_checkpoint": {
            "bundleHash": "sha256:prior-bundle",
            "bundleVersion": "prior-bundle",
            "issuedAt": prior_now,
            "payloadHash": "prior-payload",
            "workspaceId": _WORKSPACE_ID,
        },
        "policy_bundle_keyring": {"keys": [{"keyId": "prior-key"}]},
        "policy_bundle_last_error": {"reason": "prior-error"},
        "policy_bundle_last_good": {"bundleVersion": "prior-last-good"},
        "team_policy_pack": {"rules": [{"id": "prior-team-rule"}]},
    }
    for state_key, payload in prior_state.items():
        store.set_sync_payload(state_key, payload, prior_now)

    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id="codex:project:prior-policy-bundle-block",
                reason="Prior signed authority.",
                owner="prior-bundle-rule",
                source="policy-bundle",
            ),
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:prior-team-allow",
                reason="Prior upgrade-era row.",
                source="team-policy",
            ),
        ],
        prior_now,
        remote_write_authorized=True,
    )
    rows_before = _sorted_policy_rows(store)
    state_before = {state_key: store.get_sync_payload(state_key) for state_key in prior_state}

    original_replace = store._replace_remote_policy_rows_locked  # pyright: ignore[reportPrivateUsage]

    def replace_rows_and_arm_failure(
        connection: sqlite3.Connection,
        rows: Sequence[tuple[object, ...]],
    ) -> None:
        original_replace(connection, rows)
        # Fail only after apply_policy_bundle_authority has updated every
        # authority-bearing state key above. The last-good write is deliberately
        # ordered last when update_last_good=True, making this a mid-transaction
        # failure instead of a pre-write validation failure.
        _ = connection.execute(
            """
            create temp trigger inject_policy_bundle_activation_failure
            before insert on sync_state
            when new.state_key = 'policy_bundle_last_good'
            begin
              select raise(abort, 'injected policy bundle activation failure');
            end
            """
        )

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", replace_rows_and_arm_failure)

    with pytest.raises(sqlite3.IntegrityError, match="injected policy bundle activation failure"):
        store.apply_policy_bundle_authority(
            [
                PolicyDecision(
                    harness="codex",
                    scope="artifact",
                    action="allow",
                    artifact_id="codex:project:new-policy-bundle-allow",
                    reason="Authority that must be rolled back.",
                    owner="new-bundle-rule",
                    source="policy-bundle",
                )
            ],
            "2026-07-18T00:00:00Z",
            policy_bundle={
                "bundleHash": "sha256:new-bundle",
                "bundleVersion": "new-bundle",
                "issuedAt": "2026-07-18T00:00:00Z",
                "payloadHash": "new-payload",
                "workspaceId": _WORKSPACE_ID,
            },
            policy_bundle_keyring={"keys": [{"keyId": "new-key"}]},
            cloud_exceptions=[{"id": "new-exception", "effect": "allow"}],
            policy_bundle_ack={"bundleVersion": "new-bundle", "status": "synced"},
            policy_bundle_checkpoint={
                "bundleHash": "sha256:new-bundle",
                "bundleVersion": "new-bundle",
                "issuedAt": "2026-07-18T00:00:00Z",
                "payloadHash": "new-payload",
                "workspaceId": _WORKSPACE_ID,
            },
            update_last_good=True,
            policy_bundle_last_error={},
            remote_write_authorized=True,
        )

    assert _sorted_policy_rows(store) == rows_before
    assert {state_key: store.get_sync_payload(state_key) for state_key in prior_state} == state_before


def test_atomic_activation_cannot_replace_newer_checkpoint_with_older_signed_bundle(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    newer = _signed_bundle(
        rollout_state="enforcing",
        bundle_version="policy-2026-07-18.2",
        issued_at="2026-07-18T01:00:00Z",
    )
    older = _signed_bundle(
        rollout_state="enforcing",
        bundle_version="policy-2026-07-18.1",
        issued_at="2026-07-18T00:00:00Z",
    )
    assert _activate_bundle(store, newer, "2026-07-18T01:00:00Z") is not None
    rows_after_newer = _sorted_policy_rows(store)

    assert _activate_bundle(store, older, "2026-07-18T02:00:00Z") is None
    assert store.get_sync_payload("policy_bundle") == newer
    assert store.get_sync_payload("policy_bundle_last_good") == newer
    assert store.get_sync_payload("policy_bundle_acceptance_checkpoint") == (policy_bundle_acceptance_checkpoint(newer))
    assert _sorted_policy_rows(store) == rows_after_newer


def _continuity_mutation(store: GuardStore):
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


def test_activation_rejection_after_continuity_preflight_writes_neither_authority(
    tmp_path: Path,
) -> None:
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

    device = store.get_device_metadata()
    result = store.apply_policy_bundle_authority(
        build_policy_bundle_decisions(
            older,
            device_id=device["installation_id"],
            device_name=device["device_label"],
        ),
        "2026-08-27T14:00:00Z",
        policy_bundle=older,
        policy_bundle_keyring=policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID),
        cloud_exceptions=[],
        policy_bundle_ack={"status": "synced"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(older),
        update_last_good=True,
        custom_extension_continuity=mutation,
        remote_write_authorized=True,
    )

    assert result is None
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
    device = store.get_device_metadata()
    result = store.apply_policy_bundle_authority(
        build_policy_bundle_decisions(
            bundle,
            device_id=device["installation_id"],
            device_name=device["device_label"],
        ),
        "2026-08-27T12:00:00Z",
        policy_bundle=bundle,
        policy_bundle_keyring=policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID),
        cloud_exceptions=[],
        policy_bundle_ack={"status": "synced"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        custom_extension_continuity=mutation,
        remote_write_authorized=True,
    )

    assert result is None
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
    device = store.get_device_metadata()

    def activate(capabilities: frozenset[str]) -> dict[str, object] | None:
        return store.apply_policy_bundle_authority(
            build_policy_bundle_decisions(
                bundle,
                device_id=device["installation_id"],
                device_name=device["device_label"],
            ),
            "2026-08-27T12:00:00Z",
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

    capability = frozenset({"custom-extension-continuity.v2"})
    assert activate(capability) is None
    assert store.get_sync_payload("policy_bundle") is None
    store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        key=None,
    )
    assert activate(frozenset()) is None
    assert store.get_sync_payload("policy_bundle") is None
    assert activate(capability) is not None
    assert store.read_local_cli_grant(identity.cli_id) is not None
    assert store.get_sync_payload("custom_extension_continuity") is not None


@pytest.mark.parametrize(
    "corrupt_checkpoint",
    ["{", "[]", "{}"],
    ids=("invalid-json", "non-object", "empty-object"),
)
def test_atomic_activation_rejects_corrupt_existing_checkpoint_without_mutation(
    tmp_path: Path,
    corrupt_checkpoint: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    newer = _signed_bundle(
        rollout_state="enforcing",
        bundle_version="policy-2026-07-18.2",
        issued_at="2026-07-18T01:00:00Z",
    )
    older = _signed_bundle(
        rollout_state="enforcing",
        bundle_version="policy-2026-07-18.1",
        issued_at="2026-07-18T00:00:00Z",
    )
    assert _activate_bundle(store, newer, "2026-07-18T01:00:00Z") is not None
    rows_after_newer = _sorted_policy_rows(store)

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?",
            (corrupt_checkpoint, "policy_bundle_acceptance_checkpoint"),
        )

    assert _activate_bundle(store, older, "2026-07-18T02:00:00Z") is None
    assert store.get_sync_payload("policy_bundle") == newer
    assert store.get_sync_payload("policy_bundle_last_good") == newer
    assert _sorted_policy_rows(store) == rows_after_newer
    with sqlite3.connect(store.path) as connection:
        checkpoint_row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            ("policy_bundle_acceptance_checkpoint",),
        ).fetchone()
    assert checkpoint_row == (corrupt_checkpoint,)


@pytest.mark.parametrize("source", ["cloud-sync", "team-policy"])
def test_upgrade_era_unsigned_remote_allow_cannot_resolve_or_be_claimed(
    tmp_path: Path,
    source: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = f"codex:project:legacy-{source}-allow"
    artifact_hash = f"hash-{source}"
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                reason="Unsigned upgrade-era remote authority.",
                source=source,
            )
        ],
        "2026-07-18T00:00:00Z",
        remote_write_authorized=True,
    )

    lookup = store.resolve_policy_decision_lookup(
        "codex",
        artifact_id,
        artifact_hash,
        now="2026-07-18T00:01:00Z",
        consume_one_shot=False,
    )
    assert lookup["decision"] is None
    assert (
        store.resolve_policy(
            "codex",
            artifact_id,
            artifact_hash,
            now="2026-07-18T00:01:00Z",
        )
        is None
    )

    stored_row = _sorted_policy_rows(store)[0]
    claim_candidate = {
        **stored_row,
        "_approval_authority_revision": lookup["authority_revision"],
    }
    assert (
        store.claim_approval_reuse_decision(
            claim_candidate,
            now="2026-07-18T00:01:00Z",
        )
        is False
    )
    assert _sorted_policy_rows(store) == [stored_row]


@pytest.mark.parametrize("rollout_state", ["draft", "simulated", "pending_approval"])
def test_signed_inactive_cached_bundle_cannot_enforce_defaults_or_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rollout_state: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: _WORKSPACE_ID)
    bundle = _signed_bundle(rollout_state=rollout_state)
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID),
        "2026-07-18T00:00:00Z",
    )
    store.set_sync_payload("policy_bundle", bundle, "2026-07-18T00:00:00Z")

    device = store.get_device_metadata()
    decisions = build_policy_bundle_decisions(
        bundle,
        device_id=device["installation_id"],
        device_name=device["device_label"],
    )
    assert len(decisions) == 1
    assert decisions[0].artifact_id == _INACTIVE_ARTIFACT_ID
    assert decisions[0].action == "allow"
    store.replace_remote_policies(
        decisions,
        "2026-07-18T00:00:00Z",
        remote_write_authorized=True,
    )

    assert synced_policy_bundle_validation(store) == (None, "inactive_rollout_state")
    assert validated_synced_policy_bundle(store) is None
    assert synced_policy_payload(store) is None

    lookup = store.resolve_policy_decision_lookup(
        "codex",
        _INACTIVE_ARTIFACT_ID,
        now="2026-07-18T00:01:00Z",
        consume_one_shot=False,
    )
    assert lookup["decision"] is None
    assert (
        store.resolve_policy(
            "codex",
            _INACTIVE_ARTIFACT_ID,
            now="2026-07-18T00:01:00Z",
        )
        is None
    )

    stored_row = _sorted_policy_rows(store)[0]
    claim_candidate = {
        **stored_row,
        "_approval_authority_revision": lookup["authority_revision"],
    }
    assert (
        store.claim_approval_reuse_decision(
            claim_candidate,
            now="2026-07-18T00:01:00Z",
        )
        is False
    )
    assert _sorted_policy_rows(store) == [stored_row]
