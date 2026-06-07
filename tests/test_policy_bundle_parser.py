"""Policy bundle parser contract tests (HGC071-HGC075)."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.policy_bundle_parser import (
    computed_policy_bundle_hash,
    validated_policy_bundle_payload,
)
from codex_plugin_scanner.guard.store import GuardStore


def _guard_store(tmp_path: Path) -> GuardStore:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return GuardStore(guard_home)


def _sample_policy_bundle(*, bundle_hash: str | None = None) -> dict[str, object]:
    bundle: dict[str, object] = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-04-19.1",
        "bundleHash": bundle_hash or "",
        "issuedAt": "2026-04-19T00:00:10+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "sha256",
            "keyId": "guard-policy-bundle-v1",
            "signature": None,
        },
        "rolloutState": "enforcing",
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
                "ruleId": "pkg-block",
                "action": "block",
                "reason": "Block risky package installs before execution.",
                "matcherFamilies": ["package-request"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": ["npm"],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            }
        ],
        "acknowledgements": [],
    }
    if bundle_hash is None:
        bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    return bundle


def test_hgc071_valid_policy_bundle_parses() -> None:
    bundle = _sample_policy_bundle()

    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert reason is None
    assert validated_bundle is not None
    assert validated_bundle["bundleVersion"] == "policy-2026-04-19.1"
    assert validated_bundle["bundleHash"] == computed_policy_bundle_hash(bundle)
    assert validated_bundle["rules"] == bundle["rules"]


def test_hgc072_invalid_schema_rejected() -> None:
    bundle = _sample_policy_bundle()
    del bundle["rules"]

    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert validated_bundle is None
    assert reason == "missing_required_field"


def test_hgc073_tampered_hash_rejected() -> None:
    bundle = _sample_policy_bundle(bundle_hash="sha256:tampered")

    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert validated_bundle is None
    assert reason == "bundle_hash_mismatch"


def test_hgc073_missing_core_key_raises_for_hash() -> None:
    bundle = _sample_policy_bundle()
    del bundle["rules"]

    try:
        computed_policy_bundle_hash(bundle)
    except ValueError as exc:
        assert "missing_policy_bundle_key:rules" in str(exc)
    else:
        raise AssertionError("expected ValueError for missing policy bundle key")


def test_hgc074_persists_active_cloud_policy_version_in_guard_store(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    store = GuardStore(home)
    bundle = _sample_policy_bundle()
    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert reason is None
    assert validated_bundle is not None

    store.set_sync_payload("policy_bundle", validated_bundle, "2026-04-19T00:00:10+00:00")

    reopened = GuardStore(home)
    persisted = reopened.get_sync_payload("policy_bundle")

    assert isinstance(persisted, dict)
    assert persisted["bundleVersion"] == validated_bundle["bundleVersion"]


def test_hgc075_preserves_last_known_good_policy_on_invalid_update(tmp_path: Path) -> None:
    store = _guard_store(tmp_path)
    now = "2026-04-19T00:00:10+00:00"
    valid_bundle = _sample_policy_bundle()
    validated_bundle, reason = validated_policy_bundle_payload(valid_bundle)

    assert reason is None
    assert validated_bundle is not None

    store.set_sync_payload("policy_bundle", validated_bundle, now)
    store.set_sync_payload("policy_bundle_last_good", validated_bundle, now)

    invalid_bundle = dict(valid_bundle)
    del invalid_bundle["rules"]
    rejected_bundle, rejection_reason = validated_policy_bundle_payload(invalid_bundle)

    assert rejected_bundle is None
    assert rejection_reason == "missing_required_field"

    store.set_sync_payload(
        "policy_bundle_last_error",
        {"reason": rejection_reason or "invalid_policy_bundle"},
        now,
    )

    assert store.get_sync_payload("policy_bundle_last_good") == validated_bundle
    assert store.get_sync_payload("policy_bundle") == validated_bundle
    assert store.get_sync_payload("policy_bundle_last_error") == {
        "reason": "missing_required_field",
    }


def test_hgc075_updates_last_known_good_on_valid_replacement(tmp_path: Path) -> None:
    store = _guard_store(tmp_path)
    now = "2026-04-19T00:00:10+00:00"
    first_bundle = _sample_policy_bundle()
    first_validated, first_reason = validated_policy_bundle_payload(first_bundle)

    assert first_reason is None
    assert first_validated is not None

    store.set_sync_payload("policy_bundle", first_validated, now)
    store.set_sync_payload("policy_bundle_last_good", first_validated, now)

    replacement_bundle = _sample_policy_bundle()
    replacement_bundle["bundleVersion"] = "policy-2026-04-20.1"
    replacement_bundle["bundleHash"] = computed_policy_bundle_hash(replacement_bundle)
    replacement_validated, replacement_reason = validated_policy_bundle_payload(replacement_bundle)

    assert replacement_reason is None
    assert replacement_validated is not None

    store.set_sync_payload("policy_bundle", replacement_validated, now)
    store.set_sync_payload("policy_bundle_last_good", replacement_validated, now)

    assert store.get_sync_payload("policy_bundle") == replacement_validated
    assert store.get_sync_payload("policy_bundle_last_good") == replacement_validated
