"""Focused regressions for signed policy-bundle trust and rollback handling."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import policy_bundle_trusted_keys as trusted_keys_module
from codex_plugin_scanner.guard.memory_pattern_fingerprint import (
    build_exact_shell_command_memory_artifact_id,
)
from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_parser import (
    policy_bundle_acceptance_checkpoint,
    policy_bundle_rejection_message,
    validated_policy_bundle_payload,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    POLICY_BUNDLE_KEY_PURPOSE,
    load_policy_bundle_verification_keys,
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.runtime.runner import (
    _policy_bundle_is_version_downgrade,  # pyright: ignore[reportPrivateUsage]
)
from codex_plugin_scanner.guard.runtime.supply_chain_bundle import (
    load_supply_chain_verification_keys,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import synced_policy_bundle_validation
from tests.guard_review_signing_helpers import review_verification_keys
from tests.policy_bundle_signing_helpers import (
    TEST_POLICY_BUNDLE_WORKSPACE_ID,
    policy_bundle_test_keyring,
    policy_bundle_test_verification_key,
    sign_policy_bundle,
)

_SYNCED_AT = "2026-07-18T00:00:00Z"
_VALIDATION_NOW = 1_784_419_200.0


def _unsigned_policy_bundle(
    *,
    bundle_version: str = "policy-2026-07-18.1",
    issued_at: str = _SYNCED_AT,
    rollout_state: str = "enforcing",
) -> dict[str, object]:
    return {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": bundle_version,
        "bundleHash": "",
        "issuedAt": issued_at,
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": "replaced-by-signing-helper",
            "signature": None,
        },
        "rolloutState": rollout_state,
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "warn",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "warn",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [
            {
                "ruleId": "block-package-request",
                "action": "block",
                "reason": "Block an explicitly governed package request.",
                "matcherFamilies": ["package-request"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": [],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            }
        ],
        "acknowledgements": [],
    }


@pytest.mark.parametrize(
    "malformed_expiry",
    ["", "not-an-iso-timestamp", 0, [], {}],
    ids=("empty", "invalid-timestamp", "integer", "list", "mapping"),
)
def test_malformed_rule_expiry_is_rejected_as_invalid_rules(malformed_expiry: object) -> None:
    signing_key = policy_bundle_test_verification_key()
    unsigned_bundle = _unsigned_policy_bundle()
    rules = cast(list[object], unsigned_bundle["rules"])
    rule = rules[0]
    assert isinstance(rule, dict)
    rule["expiresAt"] = malformed_expiry
    signed_bundle = sign_policy_bundle(unsigned_bundle, key=signing_key)

    validated, reason = validated_policy_bundle_payload(
        signed_bundle,
        trusted_verification_keys=(signing_key,),
        anchored_verification_keys=(signing_key,),
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        now=_VALIDATION_NOW,
    )

    assert validated is None
    assert reason == "invalid_rules"


def test_policy_keyring_excludes_supply_chain_key_across_persistence_and_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        trusted_keys_module,
        "managed_policy_bundle_verification_keys",
        lambda: (False, ()),
    )
    policy_key = policy_bundle_test_verification_key()
    signed_bundle = sign_policy_bundle(_unsigned_policy_bundle(), key=policy_key)

    unrelated_public_key = review_verification_keys()[0]
    supply_chain_keyring: dict[str, object] = {
        "workspace_id": TEST_POLICY_BUNDLE_WORKSPACE_ID,
        "keys": [
            {
                "fingerprintSha256": unrelated_public_key["fingerprintSha256"],
                "keyId": "unrelated-supply-chain-key",
                "publicKeyPem": unrelated_public_key["publicKeyPem"],
                "state": "active",
                "validUntil": None,
            }
        ],
    }
    assert len(load_supply_chain_verification_keys(supply_chain_keyring)) == 1

    validated, reason, persistable_keys = validate_synced_policy_bundle(
        signed_bundle,
        stored_keyring=policy_bundle_test_keyring(),
        supply_chain_keyring=supply_chain_keyring,
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        now=_VALIDATION_NOW,
    )

    assert reason is None
    assert validated is not None
    assert persistable_keys == (policy_key,)
    assert {key.purpose for key in persistable_keys} == {POLICY_BUNDLE_KEY_PURPOSE}
    assert {key.workspace_id for key in persistable_keys} == {TEST_POLICY_BUNDLE_WORKSPACE_ID}

    persisted_keyring = policy_bundle_keyring_payload(
        persistable_keys,
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )
    guard_home = tmp_path / "guard-home"
    GuardStore(guard_home).set_sync_payload(
        "policy_bundle_keyring",
        persisted_keyring,
        _SYNCED_AT,
    )

    reloaded_keyring = GuardStore(guard_home).get_sync_payload("policy_bundle_keyring")
    strictly_reloaded_keys = load_policy_bundle_verification_keys(
        reloaded_keyring,
        require_keyring_contract=True,
    )
    assert strictly_reloaded_keys == (policy_key,)
    assert all(key.purpose == POLICY_BUNDLE_KEY_PURPOSE for key in strictly_reloaded_keys)
    assert all(key.workspace_id == TEST_POLICY_BUNDLE_WORKSPACE_ID for key in strictly_reloaded_keys)

    revalidated, second_reason, second_persistable_keys = validate_synced_policy_bundle(
        validated,
        stored_keyring=reloaded_keyring,
        supply_chain_keyring=supply_chain_keyring,
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        now=_VALIDATION_NOW,
    )

    assert second_reason is None
    assert revalidated == validated
    assert second_persistable_keys == (policy_key,)


@pytest.mark.parametrize(
    ("accepted_issued_at", "candidate_issued_at"),
    [
        ("2026-07-18T12:00:00Z", "2026-07-18T11:59:59"),
        ("2026-07-18T12:00:00", "2026-07-18T11:59:59Z"),
    ],
    ids=("accepted-z-candidate-naive", "accepted-naive-candidate-z"),
)
def test_mixed_z_and_naive_older_issued_at_is_a_downgrade(
    accepted_issued_at: str,
    candidate_issued_at: str,
) -> None:
    accepted: dict[str, object] = {
        "bundleHash": "sha256:accepted",
        "bundleVersion": "policy-v2",
        "issuedAt": accepted_issued_at,
    }
    candidate: dict[str, object] = {
        "bundleHash": "sha256:candidate",
        "bundleVersion": "policy-v3",
        "issuedAt": candidate_issued_at,
    }

    assert _policy_bundle_is_version_downgrade(accepted, candidate) is True


def test_same_issued_at_v2_to_v1_is_a_downgrade() -> None:
    accepted: dict[str, object] = {
        "bundleHash": "sha256:accepted-v2",
        "bundleVersion": "policy-v2",
        "issuedAt": "2026-07-18T12:00:00Z",
    }
    candidate: dict[str, object] = {
        "bundleHash": "sha256:candidate-v1",
        "bundleVersion": "policy-v1",
        "issuedAt": "2026-07-18T12:00:00Z",
    }

    assert _policy_bundle_is_version_downgrade(accepted, candidate) is True


def test_same_core_hash_with_distinct_signed_payload_is_unordered() -> None:
    accepted = sign_policy_bundle(_unsigned_policy_bundle())
    candidate_source = _unsigned_policy_bundle()
    candidate_source["acknowledgements"] = [
        {
            "deviceId": "device-newer-or-older",
            "status": "synced",
        }
    ]
    candidate = sign_policy_bundle(candidate_source)

    assert accepted["bundleHash"] == candidate["bundleHash"]
    assert accepted["payloadHash"] != candidate["payloadHash"]
    assert _policy_bundle_is_version_downgrade(accepted, candidate) is True


def test_cached_bundle_older_than_acceptance_checkpoint_is_not_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        trusted_keys_module,
        "managed_policy_bundle_verification_keys",
        lambda: (False, ()),
    )
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(
        "oauth_local_credentials",
        {"workspace_id": TEST_POLICY_BUNDLE_WORKSPACE_ID},
        _SYNCED_AT,
    )
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), _SYNCED_AT)
    older_source = _unsigned_policy_bundle(
        bundle_version="policy-2026-07-18.1",
        issued_at="2026-07-18T00:00:00Z",
    )
    older_source["rules"] = [
        {
            "ruleId": "captured-old-allow",
            "action": "allow",
            "reason": "This captured rule must not return as authority.",
            "artifactId": "codex:project:captured-old-allow",
            "scope": {"harnesses": ["codex"]},
        }
    ]
    older = sign_policy_bundle(older_source)
    newer = sign_policy_bundle(
        _unsigned_policy_bundle(
            bundle_version="policy-2026-07-18.2",
            issued_at="2026-07-18T01:00:00Z",
        )
    )
    store.set_sync_payload("policy_bundle", older, _SYNCED_AT)
    store.set_sync_payload(
        "policy_bundle_acceptance_checkpoint",
        policy_bundle_acceptance_checkpoint(newer),
        _SYNCED_AT,
    )
    store.replace_remote_policies(
        build_policy_bundle_decisions(
            older,
            device_id=store.get_device_metadata()["installation_id"],
            device_name=store.get_device_metadata()["device_label"],
        ),
        _SYNCED_AT,
        remote_write_authorized=True,
    )

    validated, reason = synced_policy_bundle_validation(store, now=_VALIDATION_NOW)

    assert validated is None
    assert reason == "bundle_version_downgrade"
    assert (
        store.resolve_policy(
            "codex",
            "codex:project:captured-old-allow",
            "sha256:captured-old-allow",
            now="2026-07-18T02:00:00Z",
        )
        is None
    )


def test_conflicting_artifact_aliases_materialize_no_permission() -> None:
    rule: dict[str, object] = {
        "ruleId": "conflicting-artifact-aliases",
        "action": "allow",
        "reason": "Conflicting aliases are not independent grants.",
        "artifactId": "codex:project:allowed-a",
        "matcher": {"artifactId": "codex:project:allowed-b"},
        "scope": {"harnesses": ["codex"]},
    }
    source = _unsigned_policy_bundle()
    source["rules"] = [rule]
    bundle = sign_policy_bundle(source)

    assert build_policy_bundle_decisions(bundle, device_id="device-1", device_name="Device") == []


def test_command_identity_does_not_materialize_advertised_artifact_permission() -> None:
    rule: dict[str, object] = {
        "ruleId": "command-with-artifact-label",
        "action": "allow",
        "reason": "Only the narrower command fingerprint is authority.",
        "artifactId": "codex:project:allowed-a",
        "matcher": {"command": "printf safe", "tool": "bash"},
        "scope": {"harnesses": ["codex"]},
    }
    source = _unsigned_policy_bundle()
    source["rules"] = [rule]
    bundle = sign_policy_bundle(source)

    decisions = build_policy_bundle_decisions(bundle, device_id="device-1", device_name="Device")

    assert len(decisions) == 1
    assert decisions[0].artifact_id == build_exact_shell_command_memory_artifact_id("printf safe")
    assert decisions[0].artifact_id != "codex:project:allowed-a"


@pytest.mark.parametrize(
    "rule",
    [
        {
            "ruleId": "conflicting-command-aliases",
            "action": "allow",
            "reason": "Conflicting command aliases cannot select one permission.",
            "matcher": {"command": "printf matcher", "tool": "bash"},
            "scope": {"command": "printf scope", "harnesses": ["codex"]},
        },
        {
            "ruleId": "malformed-browser-selector",
            "action": "allow",
            "reason": "Malformed browser scope cannot become a broad artifact grant.",
            "artifactId": "codex:project:browser-constrained",
            "browserIntent": {"unexpected": "browser.navigation"},
            "scope": {"harnesses": ["codex"]},
        },
        {
            "ruleId": "matcher-identity-intersection",
            "action": "allow",
            "reason": "Two matcher identity domains cannot be broadened.",
            "matcher": {
                "artifactId": "codex:project:matcher-artifact",
                "command": "printf matcher",
                "tool": "bash",
            },
            "scope": {"harnesses": ["codex"]},
        },
        {
            "ruleId": "malformed-artifact-alias",
            "action": "allow",
            "reason": "Malformed aliases cannot disappear into a valid grant.",
            "artifactId": "codex:project:valid-alias",
            "matcher": {"artifactId": {}},
            "scope": {"harnesses": ["codex"]},
        },
    ],
    ids=(
        "command-aliases",
        "malformed-browser-selector",
        "matcher-identity-intersection",
        "malformed-artifact-alias",
    ),
)
def test_valid_signed_unrepresentable_rule_materializes_no_permission(
    rule: dict[str, object],
) -> None:
    signing_key = policy_bundle_test_verification_key()
    source = _unsigned_policy_bundle()
    source["rules"] = [rule]
    signed_bundle = sign_policy_bundle(source, key=signing_key)
    validated, reason = validated_policy_bundle_payload(
        signed_bundle,
        trusted_verification_keys=(signing_key,),
        anchored_verification_keys=(signing_key,),
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        now=_VALIDATION_NOW,
    )

    assert reason is None
    assert validated is not None
    assert build_policy_bundle_decisions(validated, device_id="device-1", device_name="Device") == []


@pytest.mark.parametrize(
    "matcher_families",
    [["tool-action", "future-narrow"], "tool-action"],
    ids=("mixed-known-unknown", "malformed-scalar"),
)
def test_invalid_explicit_matcher_families_cannot_fall_back_to_broad_family(
    matcher_families: object,
) -> None:
    rule: dict[str, object] = {
        "ruleId": "invalid-explicit-families",
        "action": "allow",
        "reason": "Unknown or malformed explicit selectors fail closed.",
        "artifactType": "tool_action_request",
        "matcherFamilies": matcher_families,
        "scope": {"harnesses": ["codex"]},
    }
    signing_key = policy_bundle_test_verification_key()
    source = _unsigned_policy_bundle()
    source["rules"] = [rule]
    signed_bundle = sign_policy_bundle(source, key=signing_key)

    validated, reason = validated_policy_bundle_payload(
        signed_bundle,
        trusted_verification_keys=(signing_key,),
        anchored_verification_keys=(signing_key,),
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        now=_VALIDATION_NOW,
    )

    assert validated is None
    assert reason == "invalid_rules"
    assert build_policy_bundle_decisions(signed_bundle, device_id="device-1", device_name="Device") == []


def test_inactive_rollout_rejection_has_actionable_remediation() -> None:
    assert policy_bundle_rejection_message("inactive_rollout_state") == (
        "The authenticated policy bundle is not active for local enforcement. "
        "Approve or publish the rollout in Guard Cloud, then sync again."
    )


def test_policy_keyring_wrapper_cannot_be_serialized_without_workspace() -> None:
    with pytest.raises(ValueError, match="workspaceId"):
        policy_bundle_keyring_payload((), workspace_id=None)


def test_live_managed_anchor_validates_without_persisting_managed_key_locally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed_key = policy_bundle_test_verification_key()
    signed_bundle = sign_policy_bundle(_unsigned_policy_bundle(), key=managed_key)
    monkeypatch.setattr(
        trusted_keys_module,
        "managed_policy_bundle_verification_keys",
        lambda: (True, (managed_key,)),
    )

    validated, reason, persistable_keys = validate_synced_policy_bundle(
        signed_bundle,
        stored_keyring=policy_bundle_keyring_payload(
            (),
            workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        ),
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        now=_VALIDATION_NOW,
    )

    assert reason is None
    assert validated == signed_bundle
    assert persistable_keys == ()


@pytest.mark.parametrize(
    "legacy_provenance",
    [
        {
            "contractVersion": "guard-managed-policy-keyring-provenance.v1",
            "keyringSha256": "0" * 64,
            "managedPolicyContentHash": "1" * 64,
            "workspaceId": TEST_POLICY_BUNDLE_WORKSPACE_ID,
        },
        {"malformed": True},
        [],
    ],
    ids=("valid-marker", "malformed-marker", "wrong-type-marker"),
)
def test_absent_managed_source_quarantines_legacy_shared_anchor(
    legacy_provenance: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_or_substituted_key = policy_bundle_test_verification_key()
    signed_bundle = sign_policy_bundle(_unsigned_policy_bundle(), key=legacy_or_substituted_key)
    monkeypatch.setattr(
        trusted_keys_module,
        "managed_policy_bundle_verification_keys",
        lambda: (False, ()),
    )

    validated, reason, persistable_keys = validate_synced_policy_bundle(
        signed_bundle,
        stored_keyring=policy_bundle_test_keyring(key=legacy_or_substituted_key),
        managed_keyring_provenance=legacy_provenance,
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        now=_VALIDATION_NOW,
    )

    assert validated is None
    assert reason == "trusted_key_unavailable"
    assert persistable_keys == ()
