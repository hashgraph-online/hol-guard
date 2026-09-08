from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState
from tests.test_guard_extension_control_authority import (
    MemorySecretStore,
    _commit_enabled_permission,
    _store,
)


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _drift_container_runtime_fingerprint(store) -> None:
    original = store._catalog_target_manifest

    @staticmethod
    def drifted(registry):
        manifest = dict(original(registry))
        target = "extension:command.container-runtime"
        if target not in manifest:
            target = next(iter(manifest))
        manifest[target] = "0" * 64
        return manifest

    store._catalog_target_manifest = drifted


def test_same_digest_fingerprint_drift_keeps_protection(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore())
    protected = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert protected.health is AuthorityHealth.PROTECTED
    _drift_container_runtime_fingerprint(store)

    refreshed = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert refreshed.health is AuthorityHealth.PROTECTED
    persisted = store._load_catalog_manifest(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        key=store._authority_key(required=True),
    )
    assert persisted is not None
    assert persisted["extension:command.container-runtime"] == "0" * 64


def test_catalog_manifest_mac_tamper_still_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore())
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    with store._connect() as connection:
        connection.execute(
            "update extension_control_catalog_manifest set record_mac = ? where catalog_digest = ?",
            ("0" * 64, BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest),
        )

    tampered = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert tampered.health is AuthorityHealth.TAMPERED


def test_same_digest_fingerprint_drift_retires_changed_enabled_control(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore())
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    permission_id = "command.container-runtime.permission.compose-destructive-cleanup"
    _commit_enabled_permission(store, permission_id, key="enable-before-fingerprint-drift")
    enabled = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert any(
        control.target.target_id == permission_id and control.state is ControlState.ENABLED
        for layer in enabled.layers
        for control in layer.controls
    )
    original = store._catalog_target_manifest

    @staticmethod
    def drifted(registry):
        manifest = dict(original(registry))
        manifest[f"permission:{permission_id}"] = "0" * 64
        return manifest

    store._catalog_target_manifest = drifted
    refreshed = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert refreshed.health is AuthorityHealth.PROTECTED
    remaining = [
        control for layer in refreshed.layers for control in layer.controls if control.target.target_id == permission_id
    ]
    assert remaining == [] or all(control.state is not ControlState.ENABLED for control in remaining)
    again = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert again.health is AuthorityHealth.PROTECTED
    assert again.revision == refreshed.revision


def test_failed_manifest_replace_does_not_duplicate_migration(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore())
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    permission_id = "command.container-runtime.permission.compose-destructive-cleanup"
    _commit_enabled_permission(store, permission_id, key="enable-before-replace-failure")
    original = store._catalog_target_manifest

    @staticmethod
    def drifted(registry):
        manifest = dict(original(registry))
        manifest[f"permission:{permission_id}"] = "0" * 64
        return manifest

    store._catalog_target_manifest = drifted
    original_write = store._write_catalog_manifest
    attempts = 0

    def fail_first_replace(*args, replace: bool = False, **kwargs):
        nonlocal attempts
        if replace:
            attempts += 1
            if attempts == 1:
                raise RuntimeError("injected catalog manifest replace failure")
        return original_write(*args, replace=replace, **kwargs)

    store._write_catalog_manifest = fail_first_replace
    interrupted = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert interrupted.health is AuthorityHealth.DEGRADED_UNACKNOWLEDGED
    with store._connect() as connection:
        snapshot_revision = connection.execute(
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ).fetchone()[0]
    recovered = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert recovered.health is AuthorityHealth.PROTECTED
    assert recovered.revision == snapshot_revision
    with store._connect() as connection:
        migrated = connection.execute(
            "select count(*) from guard_events where event_name = ?",
            ("extension_control_authority_catalog_migrated",),
        ).fetchone()[0]
    assert migrated == 1
