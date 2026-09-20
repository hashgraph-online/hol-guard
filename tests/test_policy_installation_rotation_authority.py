"""Installation changes invalidate derived policy proof in the same transaction."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config_mutation
from codex_plugin_scanner.guard import native_policy_snapshot as native_publication
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_bundle_acceptance import capture_accepted_policy_bundle
from codex_plugin_scanner.guard.native_policy_bundle_ack import commit_native_policy_bundle_acknowledgement
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import activate_managed_bundle, managed_bundle
from tests.native_policy_retirement_test_fixtures import authenticated_retirement_peer
from tests.native_policy_snapshot_test_fixtures import _ack as v3_ack
from tests.native_policy_snapshot_test_fixtures import _status
from tests.test_canonical_policy_row_authority import _NOW, _activated_store, _reapply_current
from tests.test_generic_policy_native_application import _publisher, _source
from tests.test_native_policy_snapshot_v4_barrier import _resident
from tests.test_native_policy_snapshot_v4_publication import _ack as v4_ack
from tests.test_policy_bundle_v2_runtime_admission import _sync_signed_v2_bundle


def test_rotation_drops_old_device_proof_and_preserves_signed_and_local_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _activated_store(tmp_path)
    store.upsert_policy(
        PolicyDecision(
            harness="codex", scope="artifact", artifact_id="synthetic-local", action="block", source="local"
        ),
        _NOW,
    )
    preserved_keys = ("policy_bundle", "policy_bundle_last_good", "policy_bundle_keyring", "policy_bundle_checkpoint")
    before = {key: store.get_sync_payload(key) for key in preserved_keys}
    old_id = store.get_or_create_installation_id()
    old_binding = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
    assert isinstance(old_binding, dict) and old_binding["deviceId"] == old_id
    store.set_sync_payload("native_policy_bundle_ack_acceptance", {"oldDevice": old_id}, _NOW)
    notifications = []
    from codex_plugin_scanner.guard import native_policy_snapshot_rotation as rotation

    notify = rotation.notify_native_policy_mutation_before_deadline

    def observe_notification(lookup, *, guard_home, deadline_monotonic, require_source_authority=False):
        notify(
            lookup,
            guard_home=guard_home,
            deadline_monotonic=deadline_monotonic,
            require_source_authority=require_source_authority,
        )
        notifications.append(((guard_home,), {"require_source_authority": require_source_authority}))

    monkeypatch.setattr(rotation, "notify_native_policy_mutation_before_deadline", observe_notification)

    new_id = store.rotate_installation_id(_NOW)["installation_id"]

    assert new_id != old_id
    assert {key: store.get_sync_payload(key) for key in preserved_keys} == before
    assert [(row["artifact_id"], row["action"], row["source"]) for row in store.list_policy_decisions()] == [
        ("synthetic-local", "block", "local")
    ]
    for key in ("policy_bundle_ack", POLICY_BUNDLE_MATERIALIZATION_KEY, "native_policy_bundle_ack_acceptance"):
        assert store.get_sync_payload(key) is None
    assert notifications == [((store.guard_home,), {"require_source_authority": True})]
    assert _reapply_current(store, "2026-09-17T00:01:00Z") is not None
    assert all(row["source"] == "local" for row in store.list_policy_decisions())


def test_rotation_failure_rolls_back_identity_and_all_derived_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _activated_store(tmp_path)
    keys = ("policy_bundle", "policy_bundle_ack", POLICY_BUNDLE_MATERIALIZATION_KEY)
    before = {key: store.get_sync_payload(key) for key in keys}
    old_id, rows = store.get_or_create_installation_id(), store.list_policy_decisions()
    notifications = []
    monkeypatch.setattr(config_mutation, "notify_native_policy_mutation", lambda *a, **k: notifications.append((a, k)))
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "create trigger refuse_rotation before delete on policy_decisions "
            "begin select raise(abort, 'synthetic refusal'); end"
        )

    with pytest.raises(sqlite3.IntegrityError, match="synthetic refusal"):
        store.rotate_installation_id(_NOW)

    assert store.get_or_create_installation_id() == old_id
    assert store.list_policy_decisions() == rows
    assert {key: store.get_sync_payload(key) for key in keys} == before
    assert notifications == []


def test_direct_identity_tampering_does_not_authorize_materialization_rebinding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _activated_store(tmp_path)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(bundle, dict)
    before_binding = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
    before_rows = store.list_policy_decisions()
    with sqlite3.connect(store.path) as connection:
        connection.execute("update guard_devices set installation_id = 'unapproved-installation'")

    summary = _sync_signed_v2_bundle(store, monkeypatch, bundle, synced_at="2026-09-17T00:01:00Z")
    assert summary["policy_application_status"] == "retained"
    assert summary["policy_rejection_reason"] == "policy_bundle_materialization_unavailable"
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == before_binding
    assert store.list_policy_decisions() == before_rows


def test_rotation_preserves_existing_authenticated_managed_control_layers(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "managed")
    bundle = managed_bundle()
    assert activate_managed_bundle(store, bundle)
    before = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert before.layers
    with store._connect() as connection:
        managed_before = [
            tuple(row)
            for row in connection.execute(
                "select state_key, payload_json from sync_state "
                "where state_key like 'managed_controls_%' order by state_key"
            )
        ]
    assert managed_before

    store.rotate_installation_id(_NOW)

    assert store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY) == before
    assert store.get_sync_payload("policy_bundle") == bundle
    assert store.get_sync_payload("policy_bundle_ack") is None
    with store._connect() as connection:
        managed_after = [
            tuple(row)
            for row in connection.execute(
                "select state_key, payload_json from sync_state "
                "where state_key like 'managed_controls_%' order by state_key"
            )
        ]
    assert managed_after == managed_before


@pytest.mark.parametrize("local_config", [False, True])
@pytest.mark.parametrize("scoped_capability", [False, True])
def test_empty_installation_rotation_does_not_invent_required_policy_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, local_config: bool, scoped_capability: bool
) -> None:
    store = GuardStore(tmp_path / "empty")
    if local_config:
        (store.guard_home / "config.toml").write_text('mode = "observe"\n', encoding="utf-8")
    old_id = store.get_or_create_installation_id()
    status = _status()
    assert status.capabilities is not None
    if scoped_capability:
        status.capabilities.features += tuple(SCOPED_PUBLISH_FEATURES)
    snapshots = []

    def client(**kwargs):
        payload = kwargs["payload"]
        snapshot = json.loads(payload)["request"]["snapshot"]
        snapshots.append(snapshot)
        _resident(store.guard_home)
        if "source_input_digest" in snapshot:
            return json.dumps(v4_ack(snapshot)).encode()
        return v3_ack(payload, resident_generation=3)

    with closing(
        NativePolicySnapshotPublisher(store=store, status_provider=lambda: status, client_request=client)
    ) as publisher:
        publisher._publish_once()
        assert publisher.is_ready()
        assert len(snapshots) == 1
        assert publisher.current_snapshot_binding() is not None
        assert not publisher._source_authority_required
        assert not publisher._source_memory_required

        retirement = authenticated_retirement_peer(store, monkeypatch)
        assert store.rotate_installation_id(_NOW)["installation_id"] != old_id
        assert retirement == ["policy_snapshot_observe", "policy_snapshot_withdraw"]
        assert not publisher.is_ready()
        assert publisher._source_authority_required

        publisher._publish_once()
        assert publisher.is_ready()
        assert len(snapshots) == 2
        assert publisher.current_snapshot_binding() is not None
        assert not publisher._source_authority_required
        assert not publisher._source_memory_required
        assert snapshots[0]["mode"] == snapshots[1]["mode"]
        assert all("source_input_digest" not in snapshot for snapshot in snapshots)
        assert store.get_sync_payload("policy_bundle") is None


@pytest.mark.parametrize("shape", ["scoped", "defaults", "off-target"])
def test_prior_native_acceptance_cannot_survive_installation_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    store, bundle = _source(tmp_path, monkeypatch, shape=shape)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    with closing(_publisher(store, monkeypatch)) as publisher:
        # Register the real publisher so rotation uses the ordinary mutation
        # notification, rather than a test callback that merely reports it.
        monkeypatch.setitem(
            native_publication._PUBLISHERS, native_publication._publisher_key(store.guard_home), {publisher}
        )
        initial = _sync_signed_v2_bundle(store, monkeypatch, bundle, synced_at=_NOW)
        assert initial["policy_application_status"] == "applied"
        old_id = store.get_or_create_installation_id()
        old = capture_accepted_policy_bundle(publisher, bundle=bundle, installation_id=old_id)
        assert old is not None
        old_epoch = old.epoch

        retirement = authenticated_retirement_peer(store, monkeypatch)
        new_id = store.rotate_installation_id(_NOW)["installation_id"]
        assert retirement == ["policy_snapshot_observe", "policy_snapshot_withdraw"]

        assert new_id != old_id and publisher._epoch > old_epoch
        assert capture_accepted_policy_bundle(publisher, bundle=bundle, installation_id=old_id) is None
        assert commit_native_policy_bundle_acknowledgement(publisher, old) is None
        assert store.get_sync_payload("policy_bundle_ack") is None
        assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
        fresh = GuardStore(store.guard_home)
        if shape == "scoped":
            with pytest.raises(NativePolicySnapshotError, match="native_policy_authority_materialization_unavailable"):
                read_native_policy_authority_inputs(fresh, now=time.time())
        else:
            inputs = read_native_policy_authority_inputs(fresh, now=time.time())
            assert inputs.sources[0]["device_id"] == new_id
            assert inputs.sources[0]["materialized_at"] is None
        after = _sync_signed_v2_bundle(store, monkeypatch, bundle, synced_at="2026-09-17T00:01:00Z")
        assert after["policy_application_status"] == "applied"
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["deviceId"] == new_id and ack["status"] == "applied"
        current = capture_accepted_policy_bundle(publisher, bundle=bundle, installation_id=new_id)
        assert current is not None and current != old
        assert commit_native_policy_bundle_acknowledgement(publisher, old) is None
        assert store.get_sync_payload("policy_bundle_ack") == ack


def test_materialization_cleanup_failure_rolls_back_owned_rows_and_native_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _activated_store(tmp_path)
    store.upsert_policy(
        PolicyDecision(
            harness="codex", scope="artifact", artifact_id="synthetic-local", action="block", source="local"
        ),
        _NOW,
    )
    old_id = store.get_or_create_installation_id()
    store.set_sync_payload("native_policy_bundle_ack_acceptance", {"oldDevice": old_id}, _NOW)
    with store._connect() as connection:
        before_rows = [tuple(row) for row in connection.execute("select * from policy_decisions order by decision_id")]
        before_sync = [tuple(row) for row in connection.execute("select * from sync_state order by state_key")]
        connection.execute(
            "create trigger refuse_materialization_cleanup before delete on sync_state "
            "when old.state_key = 'policy_bundle_materialization' "
            "begin select raise(abort, 'synthetic_rotation_failure'); end"
        )
    replacement = store._replace_remote_policy_rows_locked
    removed_rows = []

    def observe_owned_cleanup(connection, rows):
        replacement(connection, rows)
        removed_rows.append([row["source"] for row in connection.execute("select source from policy_decisions")])

    notifications = []
    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", observe_owned_cleanup)
    monkeypatch.setattr(config_mutation, "notify_native_policy_mutation", lambda *a, **k: notifications.append((a, k)))
    with pytest.raises(sqlite3.IntegrityError, match="synthetic_rotation_failure"):
        store.rotate_installation_id(_NOW)

    assert removed_rows == [["local"]]
    assert notifications == []
    assert store.get_or_create_installation_id() == old_id
    with store._connect() as connection:
        assert [
            tuple(row) for row in connection.execute("select * from policy_decisions order by decision_id")
        ] == before_rows
        assert [tuple(row) for row in connection.execute("select * from sync_state order by state_key")] == before_sync
