"""Real signed sync, source binding and application fences.

HTTP replies and the resident transport are controlled for these component
tests. Native execution and installed default readiness are separate proofs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard import native_policy_bundle_sync
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.native_policy_application import controlled_policy_publisher
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import (
    _generic_v2_payload,
    _seed_v2_admission_store,
    _sync_receipts,
)


def _source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, shape: str) -> tuple[GuardStore, dict[str, Any]]:
    for name in (
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_BINARY",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "HOL_GUARD_PYTHON_ORACLE",
        "HOL_GUARD_TEST_MODE",
        "HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT",
    ):
        monkeypatch.delenv(name, raising=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification = _verification_key(key, workspace_id="workspace-alpha")
    payload: dict[str, Any] = _generic_v2_payload(rule_id="synthetic-rule", artifact_id="codex:project:Shell")
    if shape == "defaults":
        payload["spec"]["rules"] = []
        payload["spec"]["defaults"] = {"mode": "enforce", "defaultAction": "block"}
    elif shape == "off-target":
        payload["spec"]["rules"][0]["match"]["devices"] = ["different-device"]
    else:
        assert shape == "scoped"
    bundle = _signed_bundle(key, verification, payload_base=payload)
    store = _seed_v2_admission_store(tmp_path, verification)
    return store, bundle


def _publisher(
    store: GuardStore, monkeypatch: pytest.MonkeyPatch, *, reply: str = "accepted"
) -> NativePolicySnapshotPublisher:
    publisher = controlled_policy_publisher(store, reply=reply)
    monkeypatch.setattr(native_policy_bundle_sync, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    return publisher


@pytest.mark.parametrize("shape", ["scoped", "defaults", "off-target"])
def test_generic_application_requires_current_native_source_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    store, bundle = _source(tmp_path, monkeypatch, shape=shape)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    publisher = _publisher(store, monkeypatch)
    try:
        summary = _sync_receipts(store, monkeypatch, synced_at="2026-09-18T16:00:00Z", policy_bundle=bundle)
        assert summary["policy_application_status"] == "applied", summary
        assert publisher.is_ready() and publisher.current_snapshot_binding() is not None
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["status"] == "applied"
        assert ack["bundleHash"] == bundle["bundleHash"] and ack["bundleVersion"] == bundle["bundleVersion"]
        acceptance = store.get_sync_payload("native_policy_bundle_ack_acceptance")
        assert isinstance(acceptance, dict) and acceptance["ack"] == ack
        assert acceptance["binding"] == publisher.current_snapshot_binding()
        materialization = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
        assert isinstance(materialization, dict) and materialization["bundleHash"] == bundle["bundleHash"]
        if shape != "scoped":
            assert not store.list_policy_decisions()
        context = runner._receipt_sync_context(store, local_guard_online_at="2026-09-18T16:01:00Z")
        assert context["policyBundleAcknowledgementV2"] == ack
    finally:
        publisher.close()


@pytest.mark.parametrize("shape", ["scoped", "defaults"])
@pytest.mark.parametrize("reply", ["different-source", "timeout"])
def test_unaccepted_generic_source_remains_received(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str, reply: str
) -> None:
    store, bundle = _source(tmp_path, monkeypatch, shape=shape)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    publisher = _publisher(store, monkeypatch, reply=reply)
    try:
        summary = _sync_receipts(store, monkeypatch, synced_at="2026-09-18T16:00:00Z", policy_bundle=bundle)
        assert summary["policy_application_status"] == "unverified"
        assert summary["policy_rejection_reason"] == "native_policy_publication_pending"
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["status"] == "received"
        assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
    finally:
        publisher.close()


@pytest.mark.parametrize("canonical", [None, "0"])
def test_disabled_canonical_lane_preserves_fallback_without_native_application(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, canonical: str | None
) -> None:
    store, bundle = _source(tmp_path, monkeypatch, shape="scoped")
    if canonical is not None:
        monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", canonical)
    publisher = _publisher(store, monkeypatch)
    try:
        summary = _sync_receipts(store, monkeypatch, synced_at="2026-09-18T16:00:00Z", policy_bundle=bundle)
        assert summary["policy_application_status"] == "fallback"
        assert summary["policy_rejection_reason"] == "canonical_enforcement_disabled"
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["status"] == "received"
        assert not store.list_policy_decisions()
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
    finally:
        publisher.close()
