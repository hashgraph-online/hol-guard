"""Upload vs application outcomes, empty publication, and isolation regressions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.synced_policy import cached_policy_bundle_validation
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import validate_synced_policy_bundle
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    validate_policy_bundle_v2_transition,
    validated_policy_bundle_v2_payload,
)
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import (
    TEST_POLICY_BUNDLE_WORKSPACE_ID,
    policy_bundle_test_keyring,
    sign_policy_bundle,
)
from tests.support.network import stub_authenticated_urlopen
from tests.test_guard_runtime import _seed_guard_cloud
from tests.test_policy_bundle_activation_atomicity import _activate_bundle, _signed_bundle
from tests.test_policy_bundle_delivery_runtime import _Response
from tests.test_policy_bundle_v2 import _signed_bundle as _signed_v2_bundle
from tests.test_policy_bundle_v2 import _verification_key
from tests.test_policy_bundle_v2_runtime_admission import (
    _generic_v2_payload,
    _seed_v2_admission_store,
    _sync_signed_v2_bundle,
)
from tests.test_synced_policy import _MemorySyncStore
from cryptography.hazmat.primitives.asymmetric import rsa


def _v1_bundle(*, rules: list[dict[str, object]] | None = None, version: str = "policy-2026-07-18.live") -> dict[str, object]:
    bundle = _signed_bundle(rollout_state="enforcing", bundle_version=version)
    if rules is not None:
        unsigned = dict(bundle)
        unsigned["rules"] = rules
        unsigned["bundleHash"] = ""
        return sign_policy_bundle(unsigned, workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID)
    return bundle


def _stub_http(monkeypatch: pytest.MonkeyPatch, response: dict[str, object]) -> None:
    stub_authenticated_urlopen(monkeypatch, lambda request, timeout: _Response(response))
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 0)


def test_successful_upload_with_tampered_policy_retains_last_good(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID)
    live = _v1_bundle()
    keyring = policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID)
    store.set_sync_payload("policy_bundle_keyring", keyring, "2026-07-18T00:00:00Z")
    assert _activate_bundle(store, live, "2026-07-18T00:00:00Z") is not None
    tampered = dict(live)
    tampered["rules"] = [*list(live["rules"]), {"ruleId": "forged", "action": "allow"}]
    _stub_http(
        monkeypatch,
        {"syncedAt": "2026-07-18T00:01:00Z", "receiptsStored": 0, "policyBundle": tampered},
    )

    summary = runner.sync_receipts(store)

    assert summary["receipt_upload_status"] == "success"
    assert summary["policy_validation_status"] == "rejected"
    assert summary["policy_application_status"] == "retained"
    assert store.get_sync_payload("policy_bundle")["bundleVersion"] == live["bundleVersion"]
    assert store.get_sync_payload("policy_bundle_ack")["status"] != "applied"
    assert store.get_sync_payload("policy_bundle_ack")["bundleVersion"] == live["bundleVersion"]


def test_omitted_and_malformed_policy_bundle_cannot_erase_valid_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID)
    live = _v1_bundle()
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID),
        "2026-07-18T00:00:00Z",
    )
    assert _activate_bundle(store, live, "2026-07-18T00:00:00Z") is not None
    retained_hash = live["bundleHash"]
    _stub_http(monkeypatch, {"syncedAt": "2026-07-18T00:01:00Z", "receiptsStored": 0})
    omitted = runner.sync_receipts(store)
    assert omitted["policy_validation_status"] == "omitted"
    assert omitted["policy_application_status"] == "retained"
    assert store.get_sync_payload("policy_bundle")["bundleHash"] == retained_hash

    _stub_http(
        monkeypatch,
        {"syncedAt": "2026-07-18T00:02:00Z", "receiptsStored": 0, "policyBundle": None},
    )
    null_summary = runner.sync_receipts(store)
    assert null_summary["policy_validation_status"] == "rejected"
    assert store.get_sync_payload("policy_bundle")["bundleHash"] == retained_hash

    _stub_http(
        monkeypatch,
        {"syncedAt": "2026-07-18T00:03:00Z", "receiptsStored": 0, "policyBundle": {}},
    )
    empty_object = runner.sync_receipts(store)
    assert empty_object["policy_validation_status"] == "rejected"
    assert store.get_sync_payload("policy_bundle")["bundleHash"] == retained_hash


def test_signed_empty_publication_applies_and_acks_new_revision(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    live = _v1_bundle(version="policy-2026-07-18.1")
    empty = _v1_bundle(rules=[], version="policy-2026-07-18.2")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID),
        "2026-07-18T00:00:00Z",
    )
    assert _activate_bundle(store, live, "2026-07-18T00:00:00Z") is not None
    assert _activate_bundle(store, empty, "2026-07-18T00:01:00Z") is not None
    assert store.get_sync_payload("policy_bundle")["bundleVersion"] == empty["bundleVersion"]
    assert store.get_sync_payload("policy_bundle_ack")["bundleVersion"] == empty["bundleVersion"]
    assert [row for row in store.list_policy_decisions() if row["source"] == "policy-bundle"] == []


def test_stale_older_payload_cannot_resurrect_after_empty_publication(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    live = _v1_bundle(version="policy-2026-07-18.1")
    empty = _v1_bundle(rules=[], version="policy-2026-07-18.2")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID),
        "2026-07-18T00:00:00Z",
    )
    assert _activate_bundle(store, live, "2026-07-18T00:00:00Z") is not None
    assert _activate_bundle(store, empty, "2026-07-18T00:01:00Z") is not None
    retry = _activate_bundle(store, live, "2026-07-18T00:02:00Z")
    assert retry is None or store.get_sync_payload("policy_bundle")["bundleVersion"] == empty["bundleVersion"]
    assert store.get_sync_payload("policy_bundle")["bundleHash"] == empty["bundleHash"]


def test_future_dated_v2_is_rejected_with_stable_code_and_last_good_kept() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_v2_bundle(private_key, verification_key)
    now = datetime(2026, 7, 15, 11, 54, tzinfo=timezone.utc)
    rejected, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=now,
    )
    assert rejected is None
    assert reason == "bundle_not_yet_valid"
    last_good = _v1_bundle()
    store = _MemorySyncStore(
        {
            "policy_bundle": last_good,
            "policy_bundle_last_good": last_good,
            "policy_bundle_keyring": policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID),
        }
    )
    retained, last_error = cached_policy_bundle_validation(store, last_good)
    assert retained is not None
    assert last_error is None


def test_fresh_omitted_policy_reports_no_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID)
    _stub_http(monkeypatch, {"syncedAt": "2026-07-18T00:01:00Z", "receiptsStored": 0})

    summary = runner.sync_receipts(store)

    assert summary["policy_validation_status"] == "omitted"
    assert summary["policy_application_status"] == "no_authority"
    assert store.get_sync_payload("policy_bundle") in (None, {})


def test_v2_fallback_commit_is_not_reported_as_applied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", raising=False)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    bundle = _signed_v2_bundle(
        private_key,
        verification_key,
        payload_base=_generic_v2_payload(
            rule_id="rule.fallback",
            artifact_id="command:fallback",
        ),
    )
    store = _seed_v2_admission_store(tmp_path, verification_key)
    summary = _sync_signed_v2_bundle(store, monkeypatch, bundle, synced_at="2026-07-15T12:01:00Z")
    assert summary["policy_validation_status"] == "accepted"
    assert summary["policy_application_status"] == "fallback"
    ack = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(ack, dict)
    assert ack.get("status") != "applied"
    assert "deliveryId" not in ack


def test_v2_canonical_lane_reports_applied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    bundle = _signed_v2_bundle(
        private_key,
        verification_key,
        payload_base=_generic_v2_payload(
            rule_id="rule.applied",
            artifact_id="command:applied",
        ),
    )
    store = _seed_v2_admission_store(tmp_path, verification_key)
    summary = _sync_signed_v2_bundle(store, monkeypatch, bundle, synced_at="2026-07-15T12:01:00Z")
    assert summary["policy_application_status"] == "applied"
    ack = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(ack, dict)
    assert ack["status"] == "applied"
    assert "deliveryId" not in ack


def test_sync_summary_has_a_single_advisories_stored_key() -> None:
    source = Path(runner.__file__).read_text(encoding="utf-8")
    assert source.count('"advisories_stored":') == 1


def test_workspace_b_cannot_adopt_workspace_a_keys() -> None:
    live = _v1_bundle()
    validated, reason, _keys = validate_synced_policy_bundle(
        live,
        stored_keyring=policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID),
        expected_workspace_id="workspace-b",
    )
    assert validated is None
    assert reason == "wrong_workspace"


def test_same_version_substitution_and_unsigned_rollback_are_rejected() -> None:
    assert (
        validate_policy_bundle_v2_transition(
            {"bundleVersion": 8, "bundleHash": "sha256:" + "b" * 64},
            current_bundle_version=8,
            current_bundle_hash="sha256:" + "a" * 64,
        )
        == "bundle_version_conflict"
    )
    assert (
        validate_policy_bundle_v2_transition(
            {"bundleVersion": 7, "bundleHash": "sha256:" + "a" * 64},
            current_bundle_version=8,
            current_bundle_hash="sha256:" + "a" * 64,
        )
        == "bundle_downgrade_rejected"
    )
