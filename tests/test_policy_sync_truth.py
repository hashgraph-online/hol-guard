"""Actual sync and Cloud runtime projections distinguish application evidence."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from codex_plugin_scanner.guard.policy_canonical_rollout import canonical_runtime_posture
from codex_plugin_scanner.guard.runtime import runner
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import _generic_v2_payload, _seed_v2_admission_store, _sync_receipts


@pytest.mark.parametrize(
    "include_bundle,value,expected",
    [(True, None, "rejected"), (True, {}, "rejected"), (False, None, "no_authority")],
)
def test_first_sync_cannot_claim_missing_authority_was_retained(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    include_bundle: bool,
    value: dict[str, object] | None,
    expected: str,
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store = _seed_v2_admission_store(tmp_path, _verification_key(key, workspace_id="workspace-alpha"))
    summary = _sync_receipts(
        store,
        monkeypatch,
        synced_at="2026-07-15T12:01:00Z",
        include_policy_bundle=include_bundle,
        policy_bundle=value,
    )
    assert not store.get_sync_payload("policy_bundle")
    assert summary["policy_application_status"] == expected


def test_canonical_disabled_sync_is_unverified_even_when_storage_commits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "0")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification = _verification_key(key, workspace_id="workspace-alpha")
    bundle = _signed_bundle(
        key, verification, payload_base=_generic_v2_payload(rule_id="rule.one", artifact_id="command:one")
    )
    store = _seed_v2_admission_store(tmp_path, verification)
    summary = _sync_receipts(store, monkeypatch, synced_at="2026-07-15T12:01:00Z", policy_bundle=bundle)
    stored, acknowledgement = store.get_sync_payload("policy_bundle"), store.get_sync_payload("policy_bundle_ack")
    assert isinstance(stored, dict) and stored["bundleHash"] == bundle["bundleHash"]
    assert isinstance(acknowledgement, dict) and acknowledgement["status"] == "received"
    assert summary["policy_application_status"] == "fallback"


def test_posture_uses_active_v2_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    posture = canonical_runtime_posture(
        device_id="device-one",
        workspace_id="workspace-alpha",
        contract_version=POLICY_BUNDLE_V2_CONTRACT,
    )
    assert posture["selected_enforcement_lane"] == "canonical"


def test_cloud_payload_uses_active_bundle_and_preserves_rollout_percentage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "100")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification = _verification_key(key, workspace_id="workspace-alpha")
    bundle = _signed_bundle(
        key, verification, payload_base=_generic_v2_payload(rule_id="rule.one", artifact_id="command:one")
    )
    store = _seed_v2_admission_store(tmp_path, verification)
    _sync_receipts(store, monkeypatch, synced_at="2026-07-15T12:01:00Z", policy_bundle=bundle)
    payload = runner._cloud_runtime_session_payload(store, runner._local_guard_runtime_session())
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict) and acknowledgement["status"] == "received"
    assert payload["canonicalPolicyEnforcement"] is True
    assert payload["selectedEnforcementLane"] == "unverified"
    assert payload["canonicalIncompatibilityReason"] == "native_policy_publication_pending"
    assert payload["canonicalRolloutPercentage"] == 100


@pytest.mark.parametrize(
    "field,value",
    [
        ("workspaceId", "workspace-other"),
        ("deviceId", "device-other"),
        ("bundleHash", "sha256:" + "f" * 64),
    ],
)
def test_receipt_upload_does_not_reuse_generic_ack_for_another_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification = _verification_key(key, workspace_id="workspace-alpha")
    bundle = _signed_bundle(
        key, verification, payload_base=_generic_v2_payload(rule_id="rule.one", artifact_id="command:one")
    )
    store = _seed_v2_admission_store(tmp_path, verification)
    _sync_receipts(store, monkeypatch, synced_at="2026-07-15T12:01:00Z", policy_bundle=bundle)
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict)
    ack = dict(acknowledgement)
    ack[field] = value
    store.set_sync_payload("policy_bundle_ack", ack, "2026-07-15T12:02:00Z")
    context = runner._receipt_sync_context(store, local_guard_online_at="2026-07-15T12:03:00Z")
    assert "policyBundleAcknowledgementV2" not in context


def test_empty_store_never_advertises_an_active_canonical_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store = _seed_v2_admission_store(tmp_path, _verification_key(key, workspace_id="workspace-alpha"))
    local = runner._local_guard_runtime_session(store=store)
    assert local["selected_enforcement_lane"] == "legacy"
    wire = runner._cloud_runtime_session_payload(store, local)
    assert wire["selectedEnforcementLane"] == "legacy"
