"""Real managed compiler and signed ACK fences; resident transport is controlled."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_bundle_sync
from codex_plugin_scanner.guard.mdm import policy
from codex_plugin_scanner.guard.native_managed_configuration import MANAGED_CONFIGURATION_FEATURE
from codex_plugin_scanner.guard.native_policy_bundle_acceptance import capture_accepted_policy_bundle
from codex_plugin_scanner.guard.native_policy_bundle_ack import commit_native_policy_bundle_acknowledgement
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    load_policy_bundle_verification_keys,
    policy_bundle_keyring_payload,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _status
from tests.test_current_native_policy_posture import _accepted, _machine_cache
from tests.test_native_generic_sync_resident import _source
from tests.test_native_policy_snapshot_v4_publication import _ack
from tests.test_policy_bundle_v2_runtime_admission import _sync_receipts


def _publisher(store: GuardStore, cache: Path) -> tuple[NativePolicySnapshotPublisher, list[int]]:
    status = _status()
    status.capabilities.features += (*SCOPED_PUBLISH_FEATURES, MANAGED_CONFIGURATION_FEATURE)
    pushed_cache_times: list[int] = []

    def client(**kwargs: Any) -> bytes:
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        pushed_cache_times.append(cache.stat().st_mtime_ns)
        resident = store.guard_home / "native-runtime" / "resident-v3-synthetic"
        resident.mkdir(parents=True, exist_ok=True)
        generation = resident / "generation-00000000000000000003.json"
        if not generation.exists():
            generation.write_text("{}")
        return json.dumps(_ack(snapshot)).encode()

    return NativePolicySnapshotPublisher(
        store=store, status_provider=lambda: status, client_request=client
    ), pushed_cache_times


def test_managed_publication_refreshes_before_capture_and_observes_without_rewriting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = _machine_cache(tmp_path, monkeypatch)
    store = GuardStore(tmp_path / "guard")
    (store.guard_home / "config.toml").write_text('mode="enforce"\ndefault_action="allow"\n')
    publisher, pushed = _publisher(store, cache)
    try:
        for _ in range(2):
            prior = cache.stat().st_mtime_ns
            publisher._publish_once()
            assert publisher.is_ready(), publisher.last_error
            assert publisher.current_snapshot_binding() is not None
            assert pushed[-1] != prior  # Normal initial compilation still refreshes the cache.
            assert cache.stat().st_mtime_ns == pushed[-1]  # Final capture does not.
            before = cache.stat()
            store.set_sync_payload("synthetic_heartbeat", {"value": 1}, "2026-09-18T00:00:00Z")
            assert not publisher._policy_input_changed({str(store.path)})
            assert publisher.is_ready()
            assert cache.stat() == before
        assert len(pushed) == 2
    finally:
        publisher.close()


@pytest.mark.parametrize("shape", ["defaults", "scoped"])
@pytest.mark.parametrize("anchored", [False, True])
def test_signed_sync_with_managed_authority_earns_ack_without_observer_cache_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str, anchored: bool
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    cache = _machine_cache(tmp_path, monkeypatch)
    store, _, bundle = _source(tmp_path, shape)
    if anchored:
        machine_policy, _ = policy._read_windows_policy()
        assert isinstance(machine_policy, dict)
        machine_policy["policyBundleKeyring"] = policy_bundle_keyring_payload(
            load_policy_bundle_verification_keys(store.get_sync_payload("policy_bundle_keyring")),
            workspace_id=store.get_cloud_workspace_id(),
        )
    publisher, pushed = _publisher(store, cache)
    monkeypatch.setattr(publisher, "start", publisher._publish_once)
    commit = native_policy_bundle_sync.commit_native_policy_bundle_acknowledgement
    observations: list[bool] = []

    def observed_commit(*args: Any, **kwargs: Any) -> dict[str, object] | None:
        before = cache.stat()
        result = commit(*args, **kwargs)
        observations.append(cache.stat() == before)
        return result

    monkeypatch.setattr(native_policy_bundle_sync, "commit_native_policy_bundle_acknowledgement", observed_commit)
    try:
        result = _sync_receipts(store, monkeypatch, synced_at="2026-09-18T16:00:00Z", policy_bundle=bundle)
        if not anchored:
            assert result["policy_validation_status"] == "rejected"
            assert result["policy_application_status"] == "rejected"
            assert store.get_sync_payload("policy_bundle_ack") is None
            assert not observations and not publisher.is_ready()
            return
        assert result["policy_application_status"] == "applied", result
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["status"] == "applied"
        assert ack["bundleHash"] == bundle["bundleHash"] and ack["bundleVersion"] == bundle["bundleVersion"]
        assert publisher.is_ready() and pushed and observations == [True]
    finally:
        publisher.close()


@pytest.mark.parametrize("mutation", ["config", "cache", "withdrawal"])
def test_managed_change_during_publication_confirmation_cannot_open_ready_barrier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    cache = _machine_cache(tmp_path, monkeypatch)
    store = GuardStore(tmp_path / "guard")
    publisher, _ = _publisher(store, cache)
    confirm = publisher._confirm_resident_fingerprint

    def confirm_then_change(*args: Any, **kwargs: Any) -> Any:
        result = confirm(*args, **kwargs)
        if mutation == "config":
            (store.guard_home / "config.toml").write_text('mode="enforce"\nsubprocess_action="block"\n')
        elif mutation == "cache":
            cache.write_text("{}")
        else:
            cache.unlink()
        return result

    monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", confirm_then_change)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
    finally:
        publisher.close()


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("mutation", ["none", "config", "resident", "epoch", "expiry", "native_mode", "canonical"])
def test_ack_rechecks_source_and_lane_after_each_final_resident_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retained: bool, mutation: str
) -> None:
    store, publisher, _, bundle = _accepted(tmp_path, monkeypatch, shape="defaults")
    try:
        prior = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(prior, dict)
        if not retained:
            prior = {**prior, "status": "received"}
            store.set_sync_payload("policy_bundle_ack", prior, "2026-09-18T16:00:01Z")
        record = store.get_sync_payload("native_policy_bundle_ack_acceptance")
        token = capture_accepted_policy_bundle(
            publisher, bundle=bundle, installation_id=store.get_or_create_installation_id()
        )
        assert token is not None
        confirm = publisher._confirm_resident_fingerprint
        confirmations: list[bool] = []

        def confirm_then_change(*args: Any, **kwargs: Any) -> Any:
            result = confirm(*args, **kwargs)
            confirmations.append(True)
            if len(confirmations) == (1 if retained else 2):
                if mutation == "config":
                    (store.guard_home / "config.toml").write_text('mode="enforce"\nsubprocess_action="block"\n')
                elif mutation == "resident":
                    path = store.guard_home / "native-runtime" / "resident-v3-synthetic"
                    (path / "generation-00000000000000000004.json").write_text("{}")
                elif mutation == "epoch":
                    publisher.request_publish()
                elif mutation == "expiry":
                    monkeypatch.setattr(publisher, "_wall_clock", lambda: token.expires_at_ms / 1000 + 1)
                elif mutation == "native_mode":
                    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
                elif mutation == "canonical":
                    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "0")
            return result

        monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", confirm_then_change)
        result = commit_native_policy_bundle_acknowledgement(publisher, token)
        assert len(confirmations) == (1 if retained else 2)
        if mutation == "none":
            assert result is not None and result["status"] == "applied"
            assert store.get_sync_payload("policy_bundle_ack") == result
        else:
            assert result is None
            assert store.get_sync_payload("policy_bundle_ack") == prior
            assert store.get_sync_payload("native_policy_bundle_ack_acceptance") == record
    finally:
        publisher.close()
