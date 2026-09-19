"""Frozen native inputs retain complete authenticated built-in control state."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
)
from codex_plugin_scanner.guard.native_policy_authority_read import (
    _capture_native_policy_authority_inputs,
    read_native_policy_authority_inputs,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from tests.native_managed_source_support import PERMISSION, managed_store
from tests.test_canonical_policy_row_authority import _ARTIFACT, _NOW

_TIME = datetime.fromisoformat(_NOW.replace("Z", "+00:00")).timestamp()


def test_actual_managed_capture_preserves_disable_dominance_and_independent_revisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = managed_store(tmp_path, monkeypatch)
    result = read_native_policy_authority_inputs(store, now=_TIME)
    managed = result.authority.managed
    assert managed is not None
    assert managed.revision == 1 and managed.managed_revision == 1
    assert [(item.target_id, item.state) for item in managed.controls] == [(PERMISSION, "disabled")]
    assert result.authority.rows[0].artifact_id == _ARTIFACT
    assert result.authority.rows[0].action.value == "block"
    source = next(item for item in result.sources if item["kind"] == "managed-controls")
    assert source["revision"] == 1 and source["managed_revision"] == 1
    assert source["catalog_digest"] == managed.catalog_digest
    effective_digest = source["effective_digest"]
    assert isinstance(effective_digest, str) and len(effective_digest) == 64
    assert result.expires_at_ms is not None
    visible = json.dumps(result.sources) + repr(result) + repr(managed)
    assert "PRIVATE KEY" not in visible and "snapshot_mac" not in visible and "authentication" not in visible


def test_actual_local_controls_survive_without_a_managed_cloud_activation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=False)
    result = read_native_policy_authority_inputs(store, now=_TIME)
    assert result.authority.managed is not None
    assert result.authority.managed.managed_revision == 0
    assert [(item.target_id, item.state) for item in result.authority.managed.controls] == [(PERMISSION, "enabled")]


@pytest.mark.parametrize("cloud", [False, True])
def test_authenticated_controls_require_the_managed_capture_consumer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cloud: bool,
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=cloud)
    before = read_native_policy_authority_inputs(store, now=_TIME)
    managed = before.authority.managed
    assert managed is not None
    assert managed.managed_revision == int(cloud)
    assert [(item.target_id, item.state) for item in managed.controls] == [
        (PERMISSION, "disabled" if cloud else "enabled")
    ]
    with pytest.raises(NativePolicySnapshotError, match=r"^native_policy_authority_managed_consumer_required$"):
        _capture_native_policy_authority_inputs(store, now=_TIME, managed=None)
    after = read_native_policy_authority_inputs(store, now=_TIME)
    assert after.input_digest == before.input_digest
    assert after.authority.managed == managed
    assert after.sources == before.sources


def test_signed_global_lockdown_cannot_disappear_from_frozen_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = managed_store(tmp_path, monkeypatch, lockdown=True)
    result = read_native_policy_authority_inputs(store, now=_TIME)
    assert result.authority.managed is not None and result.authority.managed.global_lockdown


@pytest.mark.parametrize("mutation", ["local-mac", "managed-mac", "revision-mac", "missing-active", "missing-local"])
def test_missing_or_tampered_managed_authority_refuses_the_whole_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    store = managed_store(tmp_path, monkeypatch)
    if mutation in {"local-mac", "missing-local"}:
        with store._connect() as connection:
            connection.execute(
                "delete from extension_control_authority_snapshot"
                if mutation == "missing-local"
                else "update extension_control_authority_snapshot set snapshot_mac = 'invalid'"
            )
    elif mutation == "missing-active":
        with store._connect() as connection:
            connection.execute("delete from sync_state where state_key = ?", (MANAGED_CONTROLS_ACTIVE_STATE_KEY,))
    else:
        name = MANAGED_CONTROLS_ACTIVE_STATE_KEY if mutation == "managed-mac" else MANAGED_CONTROLS_REVISION_STATE_KEY
        payload = store.get_sync_payload(name)
        assert isinstance(payload, dict)
        authentication = payload.get("authentication")
        assert isinstance(authentication, dict)
        authentication["mac"] = "0" * 64
        store.set_sync_payload(name, payload, _NOW)
    with pytest.raises(NativePolicySnapshotError, match="managed"):
        read_native_policy_authority_inputs(store, now=_TIME)


@pytest.mark.parametrize("unsupported", ["targeted", "custom"])
def test_unrepresented_signed_semantics_are_not_reduced_to_control_layers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsupported: str,
) -> None:
    store = managed_store(tmp_path, monkeypatch, **{unsupported: True})
    with pytest.raises(NativePolicySnapshotError, match="semantics_unsupported"):
        read_native_policy_authority_inputs(store, now=_TIME)


def test_managed_clear_retains_the_independent_epoch_and_local_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = managed_store(tmp_path, monkeypatch)
    before = read_native_policy_authority_inputs(store, now=_TIME)
    store.clear_policy_bundle_authority(_NOW, policy_bundle_last_error={"reason": "synthetic-clear"})
    after = read_native_policy_authority_inputs(store, now=_TIME)
    assert after.authority.managed is not None
    assert after.authority.managed.revision == 1 and after.authority.managed.managed_revision == 2
    assert [(item.target_id, item.state) for item in after.authority.managed.controls] == [(PERMISSION, "enabled")]
    assert after.authority.rows == ()
    assert after.input_digest != before.input_digest


def test_local_revision_change_invalidates_input_without_relabeling_the_managed_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_guard_extension_control_authority import _commit

    store = managed_store(tmp_path, monkeypatch)
    before = read_native_policy_authority_inputs(store, now=_TIME)
    _commit(store, revision=1, key="synthetic-second-local-change")
    after = read_native_policy_authority_inputs(store, now=_TIME)
    assert after.authority.managed is not None
    assert after.authority.managed.revision == 2 and after.authority.managed.managed_revision == 1
    assert after.input_digest != before.input_digest


def test_managed_signed_source_expiry_refuses_the_whole_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = managed_store(tmp_path, monkeypatch)
    before = read_native_policy_authority_inputs(store, now=_TIME)
    assert before.expires_at_ms is not None
    with pytest.raises(NativePolicySnapshotError, match="bundle_unavailable"):
        read_native_policy_authority_inputs(store, now=before.expires_at_ms / 1000 + 1)


def test_unrelated_commit_and_revert_does_not_invalidate_coherent_authority_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_policy_authority_read as reader

    store = managed_store(tmp_path, monkeypatch)
    before = reader.read_native_policy_authority_inputs(store, now=_TIME)
    original = reader._capture_native_policy_authority_inputs

    def changed_and_restored(*args, **kwargs):
        store.set_sync_payload("synthetic_capture_marker", {"value": True}, _NOW)
        with store._connect() as connection:
            connection.execute("delete from sync_state where state_key = 'synthetic_capture_marker'")
        return original(*args, **kwargs)

    monkeypatch.setattr(reader, "_capture_native_policy_authority_inputs", changed_and_restored)
    after = reader.read_native_policy_authority_inputs(store, now=_TIME)
    assert after == before
    assert store.get_sync_payload("synthetic_capture_marker") is None


def test_secret_anchor_change_after_the_database_capture_refuses_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_policy_authority_read as reader

    store = managed_store(tmp_path, monkeypatch)
    original = reader._capture_native_policy_authority_inputs

    def revoke_after_read(*args, **kwargs):
        result = original(*args, **kwargs)
        store._secret_store().delete_secret(store._anchor_ref())
        return result

    monkeypatch.setattr(reader, "_capture_native_policy_authority_inputs", revoke_after_read)
    with pytest.raises(NativePolicySnapshotError, match="managed_unavailable"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)
