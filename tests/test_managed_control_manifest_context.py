"""Immutable managed source contracts, crash fences, and projection retries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY
from codex_plugin_scanner.guard.native_command_control_binding import load_native_command_program_metadata
from codex_plugin_scanner.guard.native_command_control_projection import read_control_projection
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_managed_control_manifest_context import (
    MANAGED_CONTROLS_MANIFEST_CONTEXT_STATE_KEY as CONTEXT_KEY,
)
from codex_plugin_scanner.guard.store_managed_control_manifest_context import (
    MANAGED_CONTROLS_SOURCE_MANIFEST_FIELD as SOURCE_FIELD,
)

from .managed_controls_activation_support import activate_managed_bundle, managed_bundle
from .test_guard_extension_control_authority import MemorySecretStore, _store
from .test_guard_extension_control_catalog_upgrade import _replace_active_managed_control
from .test_native_command_control_authority_publisher import _marker, _persist_native_floor
from .test_native_command_control_binding_publisher import _publish_ready, _publisher

PERMISSION = "command.container-runtime.permission.compose-destructive-cleanup"
TARGET = f"permission:{PERMISSION}"


@pytest.fixture(autouse=True)
def _allow_terminal_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _prepared(tmp_path: Path, *, legacy: bool = False) -> tuple[GuardStore, MemorySecretStore]:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    store.read_extension_control_authority_for_registry(REGISTRY)
    assert activate_managed_bundle(store, managed_bundle())
    _replace_active_managed_control(
        store,
        target_kind=ControlTargetKind.PERMISSION,
        target_id=PERMISSION,
        include_source_manifest=not legacy,
    )
    return store, secrets


def _state(view) -> ControlState:
    assert view.health is AuthorityHealth.PROTECTED
    return next(
        control.state
        for layer in view.layers
        if layer.kind is ControlLayerKind.SIGNED_CLOUD
        for control in layer.controls
        if control.target.target_id == PERMISSION
    )


def _drift(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    original = store._catalog_target_manifest

    def drifted(registry):
        return {**original(registry), TARGET: "0" * 64}

    monkeypatch.setattr(store, "_catalog_target_manifest", drifted)


def _delete_context(store: GuardStore) -> None:
    with store._connect() as connection:
        connection.execute("delete from sync_state where state_key = ?", (CONTEXT_KEY,))


def test_crash_after_manifest_replace_keeps_old_native_allow_closed_and_new_projection_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, secrets = _prepared(tmp_path)
    publisher = _publisher(store, monkeypatch)
    try:
        first = _publish_ready(publisher)
        prior_floor = _persist_native_floor(tmp_path, first)
        active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
        assert _state(store.read_extension_control_authority_for_registry(REGISTRY)) is ControlState.ENABLED
        _drift(store, monkeypatch)
        original_write = store._write_catalog_manifest

        def crash_after_replace(*args, replace=False, **kwargs):
            original_write(*args, replace=replace, **kwargs)
            if replace:
                raise KeyboardInterrupt("crash after durable replacement")

        monkeypatch.setattr(store, "_write_catalog_manifest", crash_after_replace)
        with pytest.raises(KeyboardInterrupt):
            store.read_extension_control_authority_for_registry(REGISTRY)
        marker = _marker(tmp_path)
        assert marker["phase"] == "closed" and marker["effective_digest"] is None
        assert marker["mutation_revision"] > prior_floor["authority"]["mutation_revision"]
        monkeypatch.setattr(store, "_write_catalog_manifest", original_write)

        restarted = GuardStore(tmp_path, prime_policy_integrity=False)
        restarted._extension_control_authority_secret_store = secrets
        monkeypatch.setattr(restarted, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "test"))
        _drift(restarted, monkeypatch)
        refreshed = restarted.read_extension_control_authority_for_registry(REGISTRY)
        assert _state(refreshed) is ControlState.DISABLED
        assert refreshed.revision == prior_floor["revision"] + 1
        assert _state(restarted.read_extension_control_authority_for_registry(REGISTRY)) is ControlState.DISABLED
        assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active
        second = _publish_ready(publisher)
        assert second["command_extensions"]["revision"] == refreshed.revision
        assert second["command_extensions"]["managed_revision"] == prior_floor["managed_revision"]
        assert second["command_extensions"]["effective_digest"] != prior_floor["effective_digest"]
    finally:
        publisher.close()


def test_crash_before_manifest_replace_reuses_the_completed_migration_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _prepared(tmp_path)
    before = store.read_extension_control_authority_for_registry(REGISTRY)
    _drift(store, monkeypatch)
    original_write = store._write_catalog_manifest

    def interrupt_replace(*args, replace=False, **kwargs):
        if replace:
            raise KeyboardInterrupt("crash before replacement")
        return original_write(*args, replace=replace, **kwargs)

    monkeypatch.setattr(store, "_write_catalog_manifest", interrupt_replace)
    with pytest.raises(KeyboardInterrupt):
        store.read_extension_control_authority_for_registry(REGISTRY)
    monkeypatch.setattr(store, "_write_catalog_manifest", original_write)
    refreshed = store.read_extension_control_authority_for_registry(REGISTRY)
    assert _state(refreshed) is ControlState.DISABLED
    assert refreshed.revision == before.revision + 1
    assert store.read_extension_control_authority_for_registry(REGISTRY).revision == refreshed.revision
    with store._connect() as connection:
        count = connection.execute(
            "select count(*) from guard_events where event_name = 'extension_control_authority_catalog_migrated'"
        ).fetchone()[0]
    assert count == 1


def test_deleted_context_reconstructs_original_source_after_mutable_manifest_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _prepared(tmp_path)
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert _state(store.read_extension_control_authority_for_registry(REGISTRY)) is ControlState.ENABLED
    _drift(store, monkeypatch)
    assert _state(store.read_extension_control_authority_for_registry(REGISTRY)) is ControlState.DISABLED
    _delete_context(store)
    assert _state(store.read_extension_control_authority_for_registry(REGISTRY)) is ControlState.DISABLED
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active
    context = store.get_sync_payload(CONTEXT_KEY)
    assert isinstance(context, dict) and isinstance(active, dict)
    assert json.loads(context["record"])["target_manifest"] == active[SOURCE_FIELD]


def test_legacy_activation_without_source_stays_clamped_when_context_is_deleted(tmp_path: Path) -> None:
    store, _ = _prepared(tmp_path, legacy=True)
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict) and SOURCE_FIELD not in active
    assert _state(store.read_extension_control_authority_for_registry(REGISTRY)) is ControlState.DISABLED
    _delete_context(store)
    assert _state(store.read_extension_control_authority_for_registry(REGISTRY)) is ControlState.DISABLED
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active


@pytest.mark.parametrize("tamper", ["mac", "oversized", "duplicate"])
def test_context_rejects_tampering_oversize_and_duplicate_fields(tmp_path: Path, tamper: str) -> None:
    store, _ = _prepared(tmp_path)
    store.read_extension_control_authority_for_registry(REGISTRY)
    wrapper = store.get_sync_payload(CONTEXT_KEY)
    assert isinstance(wrapper, dict)
    if tamper == "mac":
        wrapper["mac"] = "0" * 64
        encoded = json.dumps(wrapper)
    elif tamper == "oversized":
        encoded = " " * (512 * 1024 + 1)
    else:
        encoded = json.dumps(wrapper)[:-1] + ',"mac":"' + str(wrapper["mac"]) + '"}'
    with store._connect() as connection:
        connection.execute("update sync_state set payload_json = ? where state_key = ?", (encoded, CONTEXT_KEY))
    assert store.read_extension_control_authority_for_registry(REGISTRY).health is AuthorityHealth.TAMPERED


def test_context_write_failure_precedes_manifest_and_revision_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _prepared(tmp_path)
    before = store.read_extension_control_authority(catalog_digest=REGISTRY.catalog_digest)
    _drift(store, monkeypatch)

    def fail_fence():
        raise OSError("fence unavailable")

    monkeypatch.setattr(store, "_invalidate_native_extension_control_policy", fail_fence)
    assert (
        store.read_extension_control_authority_for_registry(REGISTRY).health is AuthorityHealth.DEGRADED_UNACKNOWLEDGED
    )
    assert store.get_sync_payload(CONTEXT_KEY) is None
    assert store.read_extension_control_authority(catalog_digest=REGISTRY.catalog_digest).revision == before.revision
    assert (
        store._load_catalog_manifest(REGISTRY.catalog_digest, key=store._authority_key(required=True))[TARGET]
        != "0" * 64
    )


def test_same_bundle_retry_preserves_source_contracts_and_acknowledgement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    bundle = managed_bundle()
    assert activate_managed_bundle(store, bundle)
    before = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(before, dict) and before[SOURCE_FIELD]
    original = store._catalog_target_manifest
    monkeypatch.setattr(store, "_catalog_target_manifest", lambda registry: dict.fromkeys(original(registry), "0" * 64))
    assert activate_managed_bundle(store, bundle)
    after = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(after, dict)
    assert after[SOURCE_FIELD] == before[SOURCE_FIELD]
    assert after["acknowledgement"] == before["acknowledgement"]


def test_unchanged_verified_context_and_projection_do_not_write_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _prepared(tmp_path)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "test"))
    metadata = load_native_command_program_metadata()
    binding, runtime = read_control_projection(store, metadata, None)

    def unexpected_write():
        pytest.fail("unchanged projection attempted a context/catalog mutation")

    monkeypatch.setattr(store, "_invalidate_native_extension_control_policy", unexpected_write)
    repeated, _ = read_control_projection(store, metadata, runtime)
    assert repeated == binding
