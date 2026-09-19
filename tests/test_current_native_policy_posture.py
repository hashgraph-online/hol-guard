"""Current signed/native authority is independent of configured or historical state.

Signed admission, publication and source capture are real. HTTP and resident ACK
transport are controlled; these tests do not certify an installed native lane.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_application as application
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.runtime import policy_runtime_posture as posture
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _status
from tests.test_native_generic_sync_resident import _source
from tests.test_native_policy_snapshot_v4_publication import _ack
from tests.test_policy_bundle_v2_runtime_admission import _sync_receipts


def _accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, shape: str, mode: str = "enforce"
) -> tuple[GuardStore, NativePolicySnapshotPublisher, SimpleNamespace, dict[str, Any]]:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    store, _, bundle = _source(tmp_path, shape, mode=mode)
    status = _status()
    status.capabilities.features += (*SCOPED_PUBLISH_FEATURES, "pre-tool-generic-authority-v1")

    def client(**kwargs: Any) -> bytes:
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
        directory.mkdir(parents=True, exist_ok=True)
        generation = directory / "generation-00000000000000000003.json"
        if not generation.exists():
            generation.write_text("{}")
        return json.dumps(_ack(snapshot)).encode()

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status, client_request=client)
    # Keep the real source/publisher/ACK paths deterministic without a worker race.
    monkeypatch.setattr(publisher, "start", publisher._publish_once)
    summary = _sync_receipts(store, monkeypatch, synced_at="2026-09-18T16:00:00Z", policy_bundle=bundle)
    assert summary["policy_application_status"] == "applied", summary
    assert publisher.is_ready()
    return store, publisher, status, bundle


@pytest.mark.parametrize("shape", ["defaults", "scoped"])
@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_current_application_keeps_mode_distinct_and_does_not_write_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str, mode: str
) -> None:
    store, publisher, _, _ = _accepted(tmp_path, monkeypatch, shape=shape, mode=mode)
    try:
        ack = store.get_sync_payload("policy_bundle_ack")
        materialization = store.get_sync_payload("policy_bundle_materialization")
        monkeypatch.setattr(publisher, "start", lambda: pytest.fail("posture cannot start publication"))
        monkeypatch.setattr(publisher, "_client_request", lambda **_: pytest.fail("posture cannot push a snapshot"))
        local = posture.local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert local["configured_enforcement_lane"] == "canonical"
        assert local["selected_enforcement_lane"] == "canonical"
        assert local["canonical_policy_application_status"] == "current"
        assert local["canonical_policy_application_mode"] == mode
        assert "canonical_incompatibility_reason" not in local
        wire = runner._cloud_runtime_session_payload(store, {"selectedEnforcementLane": "legacy"})
        assert wire["selectedEnforcementLane"] == "canonical"
        assert store.get_sync_payload("policy_bundle_ack") == ack
        assert store.get_sync_payload("policy_bundle_materialization") == materialization
    finally:
        publisher.close()


@pytest.mark.parametrize("shape", ["defaults", "scoped"])
@pytest.mark.parametrize(
    "mutation", ["closed", "republish", "resident", "runtime", "feature", "mode", "source", "signer", "config"]
)
def test_historical_applied_ack_never_supplies_current_native_application(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str, mutation: str
) -> None:
    store, publisher, status, bundle = _accepted(tmp_path, monkeypatch, shape=shape)
    try:
        ack = store.get_sync_payload("policy_bundle_ack")
        if mutation == "closed":
            publisher.close()
        elif mutation == "republish":
            publisher.request_publish()
        elif mutation == "resident":
            directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
            (directory / "generation-00000000000000000004.json").write_text("{}")
        elif mutation == "runtime":
            status.identity.sha256 = "f" * 64
        elif mutation == "feature":
            status.capabilities.features = tuple(x for x in status.capabilities.features if x != "hook-envelope-v3")
        elif mutation == "mode":
            monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
        elif mutation == "source":
            with store._connect() as connection:
                connection.execute("delete from sync_state where state_key = 'policy_bundle'")
        elif mutation == "signer":
            store.set_sync_payload("policy_bundle_keyring", {"keys": []}, "2026-09-18T16:00:00Z")
        else:
            (store.guard_home / "config.toml").write_text('mode="enforce"\nsubprocess_action="block"\n')
        current, reason = application.current_native_policy_application(
            publisher, bundle=bundle, installation_id=store.get_or_create_installation_id()
        )
        assert current is None and reason is not None
        assert store.get_sync_payload("policy_bundle_ack") == ack
        wire = runner._cloud_runtime_session_payload(store, {"selectedEnforcementLane": "canonical"})
        assert wire["selectedEnforcementLane"] == "unverified"
        assert wire["canonicalIncompatibilityReason"] in {
            "native_policy_publication_pending",
            "native_policy_consumer_unavailable",
            "native_policy_authority_changed",
            "native_policy_authority_unavailable",
        }
    finally:
        publisher.close()


def test_current_observation_cannot_promote_received_or_repair_a_historical_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, publisher, _, _ = _accepted(tmp_path, monkeypatch, shape="defaults")
    try:
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict)
        received = {**ack, "status": "received"}
        store.set_sync_payload("policy_bundle_ack", received, "2026-09-18T16:00:00Z")
        current = posture.local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] == "canonical"
        assert current["canonical_policy_application_status"] == "current"
        assert store.get_sync_payload("policy_bundle_ack") == received
    finally:
        publisher.close()


@pytest.mark.parametrize(
    "feature",
    [
        "policy-snapshot-resident-generation-v1",
        "native-policy-in-memory-v1",
        "native-resident-client-v1",
        "policy-snapshot-v4",
        "policy-scoped-authority-v1",
        "hook-envelope-v3",
        "pre-tool-generic-authority-v1",
        "rule_digest",
    ],
)
def test_current_runtime_must_still_support_the_accepted_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, feature: str
) -> None:
    store, publisher, status, _ = _accepted(tmp_path, monkeypatch, shape="defaults")
    try:
        if feature == "rule_digest":
            status.capabilities.rule_digest = "f" * 64
        else:
            status.capabilities.features = tuple(value for value in status.capabilities.features if value != feature)
        current = posture.local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] == "unverified"
        assert current["configured_enforcement_lane"] == "canonical"
        assert current["canonical_incompatibility_reason"] == "native_policy_consumer_unavailable"
    finally:
        publisher.close()


def _machine_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from codex_plugin_scanner.guard.mdm import contracts, policy

    # The registry response and administrator context are controlled. The
    # default managed loader, cache writer and configuration compiler are real.
    # An independent privileged-source probe covers the native Unix reader.
    paths = SimpleNamespace(policy_path=None, state_root=tmp_path / "machine-state")
    machine_policy = {
        "schemaVersion": "hol-guard-mdm-policy.v1",
        "settings": {"default_action": "block"},
        "lockedSettings": ["default_action"],
    }
    monkeypatch.setattr(policy, "platform", SimpleNamespace(system=lambda: "Windows"))
    monkeypatch.setattr(policy, "_read_windows_policy", lambda: (machine_policy, "synthetic-machine-registry"))
    monkeypatch.setattr(policy, "_administrator_context", lambda _system: True)
    monkeypatch.setattr(policy, "default_machine_paths", lambda **_: paths)
    monkeypatch.setattr(contracts, "default_machine_paths", lambda **_: paths)
    state = policy.load_managed_policy()
    assert state.status == "active"
    return paths.state_root / "managed-policy-cache.json"


def test_observation_preserves_machine_cache_and_refuses_new_managed_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.mdm import policy
    from codex_plugin_scanner.guard.native_managed_capture import configuration_origin

    store, publisher, _, bundle = _accepted(tmp_path, monkeypatch, shape="defaults")
    cache = _machine_cache(tmp_path, monkeypatch)
    before, metadata = cache.read_bytes(), cache.stat()
    ack = store.get_sync_payload("policy_bundle_ack")
    try:
        with policy.managed_policy_cache_read_only():
            config = publisher._compiled_effective_policy()
        origin = configuration_origin(config)
        assert origin is not None
        effective = origin.to_mapping()["effective_policy"]
        assert isinstance(effective, dict) and effective["default_action"] == "block"
        current, reason = application.current_native_policy_application(
            publisher, bundle=bundle, installation_id=store.get_or_create_installation_id()
        )
        assert current is None and reason is not None
        after = cache.stat()
        assert cache.read_bytes() == before
        assert (after.st_ino, after.st_mtime_ns, after.st_size) == (
            metadata.st_ino,
            metadata.st_mtime_ns,
            metadata.st_size,
        )
        assert store.get_sync_payload("policy_bundle_ack") == ack
        current = posture.local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] == "unverified"
        assert cache.read_bytes() == before and cache.stat().st_mtime_ns == metadata.st_mtime_ns
    finally:
        publisher.close()


def test_nested_read_only_scopes_restore_cache_writes_after_exceptions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.mdm import policy

    cache = _machine_cache(tmp_path, monkeypatch)
    before = cache.stat()
    with policy.managed_policy_cache_read_only():
        with pytest.raises(RuntimeError, match="synthetic"), policy.managed_policy_cache_read_only():
            assert policy.load_managed_policy().status == "active"
            raise RuntimeError("synthetic")
        assert policy.load_managed_policy().status == "active"
        assert cache.stat() == before
    assert policy.load_managed_policy().status == "active"
    assert cache.stat().st_mtime_ns != before.st_mtime_ns


def test_read_only_scope_does_not_disable_independent_publisher_thread_cache_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.mdm import policy

    cache = _machine_cache(tmp_path, monkeypatch)
    before = cache.stat()
    with policy.managed_policy_cache_read_only():
        with ThreadPoolExecutor(max_workers=1) as executor:
            assert executor.submit(policy.load_managed_policy).result().status == "active"
        after_thread = cache.stat()
        assert after_thread.st_mtime_ns != before.st_mtime_ns
        assert policy.load_managed_policy().status == "active"
        assert cache.stat() == after_thread


def test_rollout_withdrawal_during_observation_refreshes_configured_posture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, publisher, _, _ = _accepted(tmp_path, monkeypatch, shape="defaults")
    confirm = publisher._confirm_resident_fingerprint

    def withdraw(*args: Any):
        result = confirm(*args)
        monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "0")
        return result

    try:
        monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", withdraw)
        current = posture.local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] == "unverified"
        assert current["configured_enforcement_lane"] == "unverified"
        assert current["canonical_incompatibility_reason"] == "canonical_enforcement_disabled"
        assert current["canonical_policy_enforcement_enabled"] is False
        assert current["canonical_rollout_percentage"] == 0
        assert "canonical_policy_enforcement" not in current
    finally:
        publisher.close()


@pytest.mark.parametrize(
    "mutation", ["source", "source_revert", "config", "resident", "epoch", "feature", "expiry", "rollout"]
)
def test_final_observation_fence_follows_resident_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    store, publisher, status, bundle = _accepted(tmp_path, monkeypatch, shape="defaults")
    confirm = publisher._confirm_resident_fingerprint
    ack = store.get_sync_payload("policy_bundle_ack")

    def change_after_confirm(*args: Any):
        result = confirm(*args)
        if mutation in {"source", "source_revert"}:
            with store._connect() as connection:
                connection.execute("delete from sync_state where state_key = 'policy_bundle'")
            if mutation == "source_revert":
                store.set_sync_payload("policy_bundle", bundle, "2026-09-18T16:00:00Z")
        elif mutation == "config":
            (store.guard_home / "config.toml").write_text('mode="observe"\ndefault_action="review"\n')
        elif mutation == "resident":
            directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
            (directory / "generation-00000000000000000004.json").write_text("{}")
        elif mutation == "epoch":
            publisher.request_publish()
        elif mutation == "feature":
            status.capabilities.features = ()
        elif mutation == "rollout":
            monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "0")
        else:
            monkeypatch.setattr(publisher, "_wall_clock", lambda: 10**11)
        return result

    try:
        monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", change_after_confirm)
        current, reason = application.current_native_policy_application(
            publisher, bundle=bundle, installation_id=store.get_or_create_installation_id()
        )
        assert current is None and reason is not None
        assert store.get_sync_payload("policy_bundle_ack") == ack
    finally:
        publisher.close()


@pytest.mark.parametrize("flag", [None, "", "0", "off", "invalid", "25"])
def test_explicit_rollout_controls_cannot_be_overridden_by_current_native_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str | None
) -> None:
    store, publisher, _, _ = _accepted(tmp_path, monkeypatch, shape="defaults")
    try:
        if flag is None:
            monkeypatch.delenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT")
        else:
            monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", flag)
        actual = posture.local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert actual["canonical_rollout_percentage"] == (25 if flag == "25" else 0)
        if actual["canonical_policy_enforcement_enabled"]:
            assert actual["selected_enforcement_lane"] == "canonical"
        else:
            assert actual["selected_enforcement_lane"] == "unverified"
            assert actual["canonical_incompatibility_reason"] == "canonical_enforcement_disabled"
    finally:
        publisher.close()
