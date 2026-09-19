"""Real receipt-sync outcomes for rejected fresh policy and retained authority."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring
from tests.test_policy_bundle_activation_atomicity import _activate_bundle, _signed_bundle
from tests.test_policy_bundle_v2_runtime_admission import _sync_receipts

_NOW = "2026-09-18T00:00:00Z"


def _store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-1"}, _NOW)
    store.set_sync_payload(
        "policy_bundle_keyring", policy_bundle_test_keyring(workspace_id="workspace-1"), _NOW
    )
    return store


def _rejected_input(kind: str) -> dict[str, object] | None:
    if kind == "null":
        return None
    if kind == "empty":
        return {}
    bundle = deepcopy(_signed_bundle(rollout_state="enforcing"))
    defaults = bundle["policyDefaults"]
    assert isinstance(defaults, dict)
    defaults["defaultAction"] = "block"
    return bundle


@pytest.mark.parametrize("kind", ["null", "empty", "tampered"])
def test_fresh_rejected_policy_reports_rejection_after_successful_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    store = _store(tmp_path)

    summary = _sync_receipts(
        store, monkeypatch, synced_at=_NOW, policy_bundle=_rejected_input(kind)
    )

    reason = store.get_sync_payload("policy_bundle_last_error")
    assert isinstance(reason, dict) and isinstance(reason.get("reason"), str)
    assert reason["reason"]
    assert summary["receipt_upload_status"] == "success"
    assert summary["policy_validation_status"] == "rejected"
    assert summary["policy_rejection_reason"] == reason["reason"]
    assert not store.get_sync_payload("policy_bundle")
    assert not store.get_sync_payload("policy_bundle_ack")
    assert not store.get_sync_payload("policy_bundle_last_good")
    assert store.list_policy_decisions() == []
    assert store.get_sync_payload("sync_summary") == summary
    assert summary["policy_application_status"] == "rejected"


def test_fresh_omission_stays_no_authority_without_inventing_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)

    summary = _sync_receipts(store, monkeypatch, synced_at=_NOW, include_policy_bundle=False)

    assert summary["receipt_upload_status"] == "success"
    assert summary["policy_validation_status"] == "omitted"
    assert summary["policy_application_status"] == "no_authority"
    assert summary["policy_rejection_reason"] is None
    assert not store.get_sync_payload("policy_bundle")
    assert not store.get_sync_payload("policy_bundle_ack")


@pytest.mark.parametrize("kind", ["null", "empty", "tampered"])
def test_rejected_refresh_retains_authenticated_existing_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    store = _store(tmp_path)
    live = _signed_bundle(rollout_state="enforcing")
    assert _activate_bundle(store, live, _NOW) is not None
    original_rows = store.list_policy_decisions()
    assert original_rows

    summary = _sync_receipts(
        store, monkeypatch, synced_at=_NOW, policy_bundle=_rejected_input(kind)
    )

    assert summary["receipt_upload_status"] == "success"
    assert summary["policy_validation_status"] == "rejected"
    assert summary["policy_application_status"] == "retained"
    assert summary["policy_rejection_reason"]
    assert store.get_sync_payload("policy_bundle")["bundleHash"] == live["bundleHash"]
    assert store.get_sync_payload("policy_bundle_last_good")["bundleHash"] == live["bundleHash"]
    assert [
        {key: value for key, value in row.items() if key != "decision_id"}
        for row in store.list_policy_decisions()
    ] == [
        {key: value for key, value in row.items() if key != "decision_id"} for row in original_rows
    ]
    ack = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(ack, dict) and ack["bundleHash"] == live["bundleHash"]
    assert store.get_sync_payload("sync_summary") == summary


def test_fresh_valid_signed_policy_still_reports_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    live = _signed_bundle(rollout_state="enforcing")

    summary = _sync_receipts(store, monkeypatch, synced_at=_NOW, policy_bundle=live)

    assert summary["receipt_upload_status"] == "success"
    assert summary["policy_validation_status"] == "accepted"
    assert summary["policy_application_status"] == "applied"
    assert summary["policy_rejection_reason"] is None
    assert store.get_sync_payload("policy_bundle")["bundleHash"] == live["bundleHash"]
    assert store.get_sync_payload("sync_summary") == summary
