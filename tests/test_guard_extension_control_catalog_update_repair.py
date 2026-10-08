from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
    build_managed_controls_revision_state,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth, AuthorityPhase
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_extension_control_clear_catalog_migration import (
    _activate_under_catalog,
    _description_only_catalog_variant,
)
from tests.test_guard_extension_control_authority import (
    MemorySecretStore,
    _commit,
    _store,
    _upgraded_registry,
)


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def test_catalog_upgrade_keeps_protection_when_managed_activation_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    legacy = _description_only_catalog_variant()
    assert legacy.catalog_digest != BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    _activate_under_catalog(store, legacy, monkeypatch, preserve_local_controls=True)
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict)
    assert active["catalogDigest"] == legacy.catalog_digest

    upgraded = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert upgraded.health is AuthorityHealth.PROTECTED
    assert upgraded.catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert upgraded.layers
    local_layers = tuple(layer for layer in upgraded.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
    assert local_layers
    preserved = [
        control
        for layer in local_layers
        for control in layer.controls
        if control.target.kind is ControlTargetKind.EXTENSION
        and control.target.target_id == legacy.extensions[0].extension_id
    ]
    assert preserved
    assert all(control.state is ControlState.DISABLED for control in preserved)
    assert all(layer.catalog_digest == upgraded.catalog_digest for layer in upgraded.layers)
    leftover = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(leftover, dict)
    assert leftover["catalogDigest"] == legacy.catalog_digest


def test_stale_managed_activation_with_invalid_mac_still_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    legacy = _description_only_catalog_variant()
    _activate_under_catalog(store, legacy, monkeypatch, preserve_local_controls=True)
    with store._connect() as connection:
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            (MANAGED_CONTROLS_ACTIVE_STATE_KEY,),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row["payload_json"]))
        assert isinstance(payload, dict)
        authentication = payload.get("authentication")
        assert isinstance(authentication, dict)
        authentication["mac"] = "0" * 64
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?",
            (json.dumps(payload, allow_nan=False), MANAGED_CONTROLS_ACTIVE_STATE_KEY),
        )

    tampered = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert tampered.health is AuthorityHealth.TAMPERED


def test_stale_managed_activation_revision_mismatch_still_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    legacy = _description_only_catalog_variant()
    _activate_under_catalog(store, legacy, monkeypatch, preserve_local_controls=True)
    key = store._authority_key(required=True)
    assert key is not None
    mismatched = build_managed_controls_revision_state(99, authority_key=key)
    with store._connect() as connection:
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?",
            (json.dumps(mismatched, allow_nan=False), MANAGED_CONTROLS_REVISION_STATE_KEY),
        )

    tampered = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert tampered.health is AuthorityHealth.TAMPERED


def test_catalog_upgrade_resumes_anchored_pending_migration_without_repair(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    _commit(store)
    original = store._write_and_verify_anchor
    interrupted = False

    def interrupt_after_anchor(anchor, *, key):
        nonlocal interrupted
        original(anchor, key=key)
        if not interrupted and anchor.phase is AuthorityPhase.ANCHORED:
            interrupted = True
            raise RuntimeError("injected catalog migration interrupt")

    store._write_and_verify_anchor = interrupt_after_anchor  # pyright: ignore[reportAttributeAccessIssue]
    upgraded_registry = _upgraded_registry()
    first = store.read_extension_control_authority_for_registry(upgraded_registry)
    assert first.health is AuthorityHealth.DEGRADED_UNACKNOWLEDGED
    with store._connect() as connection:
        pending = connection.execute(
            "select phase, catalog_digest from extension_control_authority_transition order by revision desc limit 1"
        ).fetchone()
    assert pending is not None
    assert pending["phase"] == AuthorityPhase.PREPARED.value
    assert pending["catalog_digest"] == upgraded_registry.catalog_digest

    resumed = store.read_extension_control_authority_for_registry(upgraded_registry)

    assert resumed.health is AuthorityHealth.PROTECTED
    assert resumed.catalog_digest == upgraded_registry.catalog_digest
    assert resumed.revision == 2
    with store._connect() as connection:
        committed = connection.execute(
            "select phase from extension_control_authority_transition where revision = 2"
        ).fetchone()
        snapshot = connection.execute(
            "select catalog_digest from extension_control_authority_snapshot where singleton = 1"
        ).fetchone()
    assert committed["phase"] == AuthorityPhase.COMMITTED.value
    assert snapshot["catalog_digest"] == upgraded_registry.catalog_digest
    with store._connect() as connection:
        event = connection.execute(
            "select payload_json from guard_events where event_name = ? order by event_id desc limit 1",
            ("extension_control_authority_catalog_migrated",),
        ).fetchone()
    assert event is not None
    payload = json.loads(event["payload_json"])
    assert payload["previous_revision"] == 1
    assert payload["revision"] == 2
    assert payload["catalog_digest"] == upgraded_registry.catalog_digest


def test_catalog_upgrade_records_migrated_event_on_later_protected_read(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    _commit(store)
    original_anchor = store._write_and_verify_anchor
    interrupted = False

    def interrupt_after_anchor(anchor, *, key):
        nonlocal interrupted
        original_anchor(anchor, key=key)
        if not interrupted and anchor.phase is AuthorityPhase.ANCHORED:
            interrupted = True
            raise RuntimeError("injected catalog migration interrupt")

    store._write_and_verify_anchor = interrupt_after_anchor  # pyright: ignore[reportAttributeAccessIssue]
    upgraded_registry = _upgraded_registry()
    first = store.read_extension_control_authority_for_registry(upgraded_registry)
    assert first.health is AuthorityHealth.DEGRADED_UNACKNOWLEDGED

    original_record = store._record_catalog_migrated_event_once
    attempts = 0

    def fail_first_record(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("injected catalog event failure")
        return original_record(*args, **kwargs)

    store._record_catalog_migrated_event_once = fail_first_record  # pyright: ignore[reportAttributeAccessIssue]
    second = store.read_extension_control_authority_for_registry(upgraded_registry)
    assert second.health is AuthorityHealth.DEGRADED_UNACKNOWLEDGED

    recovered = store.read_extension_control_authority_for_registry(upgraded_registry)
    assert recovered.health is AuthorityHealth.PROTECTED
    assert recovered.catalog_digest == upgraded_registry.catalog_digest
    with store._connect() as connection:
        events = connection.execute(
            "select payload_json from guard_events where event_name = ?",
            ("extension_control_authority_catalog_migrated",),
        ).fetchall()
    assert len(events) == 1
    assert json.loads(events[0]["payload_json"])["revision"] == 2
