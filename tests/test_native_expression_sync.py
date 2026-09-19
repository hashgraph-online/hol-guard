"""Real signed sync/store paths; HTTP and resident availability are controlled fixtures."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _status
from tests.support.network import stub_authenticated_urlopen
from tests.test_native_policy_snapshot_v4_publication import _ack
from tests.test_policy_bundle_staging import _NOW, _apply, _fixture, _generic

_AUTH: dict[str, object] = {
    "sync_url": "https://hol.org/api/guard/receipts/sync",
    "access_token": "synthetic-test-token",
    "dpop_key_material": None,
}


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def _transport(monkeypatch: pytest.MonkeyPatch, response: dict[str, object]):
    requests: list[dict[str, object]] = []

    def exchange(request, timeout=None):
        if request.full_url.endswith("/api/guard/receipts/sync"):
            requests.append(json.loads(request.data))
            return _Response({"syncedAt": _NOW, "receiptsStored": 0, **response})
        return _Response({"accepted": 0, "rejected": 0, "statuses": []})

    stub_authenticated_urlopen(monkeypatch, exchange)
    return requests


def _publisher(store: GuardStore, *, accepts: Callable[[], bool] = lambda: False) -> NativePolicySnapshotPublisher:
    (store.guard_home / "config.toml").write_text('mode = "enforce"\ndefault_action = "warn"\n', encoding="utf-8")
    status = _status()
    assert status.capabilities is not None
    status.capabilities.features += (*SCOPED_PUBLISH_FEATURES, "policy-command-expressions-v1")

    def client(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        if not accepts():
            return json.dumps({"status": "rejected"}).encode()
        directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
        directory.mkdir(parents=True, exist_ok=True)
        generation = directory / "generation-00000000000000000003.json"
        if not generation.exists():
            generation.write_text("{}")
        return json.dumps(_ack(snapshot)).encode()

    return NativePolicySnapshotPublisher(store=store, status_provider=lambda: status, client_request=client)


@pytest.mark.parametrize("path", ["incoming", "current", "last_good"])
@pytest.mark.parametrize("generic", [False, True])
def test_signed_expression_source_remains_received_without_native_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    generic: bool,
) -> None:
    store, bundle, keyring = _fixture(tmp_path, generic=generic)
    store.set_sync_payload("policy_bundle_keyring", keyring, _NOW)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    if path != "incoming":
        assert _apply(store, bundle, keyring, [_generic()] if generic else []) is not None
    if path == "last_good":
        store.set_sync_payload("policy_bundle", {}, _NOW)
    requests = _transport(monkeypatch, {"policyBundle": bundle} if path == "incoming" else {})
    publisher = _publisher(store)
    try:
        result = runner.sync_receipts(store, auth_context=_AUTH)
    finally:
        publisher.close()
    assert len(requests) == 1
    assert store.get_sync_payload("policy_bundle") == bundle
    assert store.get_sync_payload("policy_bundle_last_good") == bundle
    materialized = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
    assert isinstance(materialized, dict)
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict) and acknowledgement["status"] == "received"
    assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
    assert {row["owner"] for row in store.list_policy_decisions()} == ({"generic.rule"} if generic else set())
    assert result["policy_application_status"] == ("unverified" if path == "incoming" else "retained")


@pytest.mark.parametrize("generic", [False, True])
def test_same_source_retry_promotes_only_after_actual_publisher_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    generic: bool,
) -> None:
    store, bundle, keyring = _fixture(tmp_path, generic=generic)
    store.set_sync_payload("policy_bundle_keyring", keyring, _NOW)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    acceptance = Event()
    publisher = _publisher(store, accepts=acceptance.is_set)
    requests = _transport(monkeypatch, {"policyBundle": bundle})
    try:
        first = runner.sync_receipts(store, auth_context=_AUTH)
        received = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(received, dict) and received["status"] == "received"
        assert first["policy_application_status"] == "unverified"
        assert first["policy_rejection_reason"] == "native_policy_publication_pending"
        assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
        materialized = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
        assert isinstance(materialized, dict)
        acceptance.set()
        second = runner.sync_receipts(store, auth_context=_AUTH)
        applied = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(applied, dict) and applied["status"] == "applied", (second, publisher.last_error)
        assert applied["bundleHash"] == bundle["bundleHash"]
        assert applied["bundleVersion"] == bundle["bundleVersion"]
        assert second["policy_application_status"] == "applied"
        assert isinstance(store.get_sync_payload("native_policy_bundle_ack_acceptance"), dict)
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == materialized
        third = runner.sync_receipts(store, auth_context=_AUTH)
        assert third["policy_application_status"] == "applied", (third, publisher.last_error)
        assert store.get_sync_payload("policy_bundle_ack") == applied
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == materialized
        assert len(requests) == 3
        acceptance.clear()
        fourth = runner.sync_receipts(store, auth_context=_AUTH)
        assert fourth["policy_application_status"] == "unverified"
        assert fourth["policy_rejection_reason"] == "native_policy_publication_pending"
        assert store.get_sync_payload("policy_bundle_ack") == applied
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == materialized
    finally:
        publisher.close()


def test_last_good_recovery_replaces_unrelated_historical_ack_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.policy_bundle_generic_ack import generic_policy_bundle_acknowledgement

    store, last_good, keyring = _fixture(tmp_path / "last-good", generic=False)
    assert _apply(store, last_good, keyring, []) is not None
    _, current, _ = _fixture(tmp_path / "current", generic=False)
    assert current["bundleHash"] != last_good["bundleHash"]
    prior_ack = generic_policy_bundle_acknowledgement(
        device_id=store.get_or_create_installation_id(),
        policy_bundle=current,
        synced_at=_NOW,
        applied=True,
    )
    assert isinstance(prior_ack, dict)
    # Model corruption of a previously distinct signed current source. The original
    # last-good source remains genuinely signed, scoped and trusted.
    verifier = current["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = "invalid"
    store.set_sync_payload("policy_bundle", current, _NOW)
    store.set_sync_payload("policy_bundle_ack", prior_ack, _NOW)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    _transport(monkeypatch, {})
    acceptance = Event()
    publisher = _publisher(store, accepts=acceptance.is_set)
    try:
        result = runner.sync_receipts(store, auth_context=_AUTH)
        assert store.get_sync_payload("policy_bundle") == last_good
        acknowledgement = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(acknowledgement, dict)
        assert acknowledgement["bundleHash"] == last_good["bundleHash"], (acknowledgement, result)
        assert acknowledgement["status"] == "received"
        assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
        materialized = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
        acceptance.set()
        recovered = runner.sync_receipts(store, auth_context=_AUTH)
        applied = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(applied, dict) and applied["status"] == "applied", (recovered, publisher.last_error)
        assert applied["bundleHash"] == last_good["bundleHash"]
        assert applied["bundleVersion"] == last_good["bundleVersion"]
        assert isinstance(store.get_sync_payload("native_policy_bundle_ack_acceptance"), dict)
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == materialized
    finally:
        publisher.close()


@pytest.mark.parametrize("mode,canonical", [("off", "1"), ("shadow", "1"), ("auto", "0")])
def test_unavailable_expression_lane_does_not_stage_or_acknowledge_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    canonical: str,
) -> None:
    store, bundle, keyring = _fixture(tmp_path, generic=False)
    store.set_sync_payload("policy_bundle_keyring", keyring, _NOW)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", canonical)
    monkeypatch.setenv("HOL_GUARD_NATIVE", mode)
    _transport(monkeypatch, {"policyBundle": bundle})
    result = runner.sync_receipts(store, auth_context=_AUTH)
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
    assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
    assert result["policy_validation_status"] == "rejected"
    assert result["policy_rejection_reason"] == "canonical_compile_command_expression_native_lane_unavailable"


@pytest.mark.parametrize(
    "changes",
    [
        {"match.commands.conditions.0.caseSensitive": False},
        {"match.commands.conditions.0.operator": "regex", "match.devices": ["different-device"]},
        {
            "match.commands.conditions.0.operator": "regex",
            "lifetime.mode": "until",
            "lifetime.expiresAt": "2020-01-01T00:00:00Z",
        },
    ],
)
def test_complete_signed_expression_is_validated_before_target_or_expiry_filtering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    store, bundle, keyring = _fixture(tmp_path, changes=changes)
    store.set_sync_payload("policy_bundle_keyring", keyring, _NOW)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    _transport(monkeypatch, {"policyBundle": bundle})
    result = runner.sync_receipts(store, auth_context=_AUTH)
    assert store.get_sync_payload("policy_bundle") is None
    assert store.list_policy_decisions() == []
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
    assert result["policy_validation_status"] == "rejected"
    assert str(result["policy_rejection_reason"]).startswith("canonical_compile_")
