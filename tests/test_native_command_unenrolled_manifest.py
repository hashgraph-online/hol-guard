"""Absent controls retain their authenticated marker without compiling target rules."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_LAST_GOOD_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
)
from codex_plugin_scanner.guard.native_command_control_binding import read_native_command_control_binding
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.runtime.command_extensions import CommandSafetyExtensionRegistry
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_extension_control_authority import MemorySecretStore, _enroll, _store


def test_fresh_and_stable_unenrolled_projection_never_compiles_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path)
    store._extension_control_authority_secret_store = MemorySecretStore()
    original_lock = store._extension_control_authority_lock
    leases: list[bool] = []

    @contextmanager
    def observed_lock(*, shared: bool = False) -> Iterator[None]:
        with original_lock(shared=shared):
            leases.append(shared)
            yield

    def unexpected_compile(_registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
        pytest.fail("a proven absent authority has no target contracts to migrate")

    monkeypatch.setattr(store, "_extension_control_authority_lock", observed_lock)
    monkeypatch.setattr(store, "_catalog_target_manifest", unexpected_compile)
    first, runtime = read_native_command_control_binding(store)
    assert first["health"] == "unenrolled"
    assert first["revision"] == first["managed_revision"] == 0
    assert first["layers"] == []
    assert store._extension_control_last_catalog_digest == first["catalog_digest"]
    assert leases == [True, False]
    leases.clear()
    second, retained = read_native_command_control_binding(store, runtime)
    assert second == first and retained is runtime
    assert leases == [True]


@pytest.mark.parametrize(
    "residue",
    [
        MANAGED_CONTROLS_ACTIVE_STATE_KEY,
        MANAGED_CONTROLS_LAST_GOOD_STATE_KEY,
        MANAGED_CONTROLS_REVISION_STATE_KEY,
        "anchor",
        "key",
        "schema",
        "unavailable-secrets",
        "missing-table",
    ],
)
def test_uncertain_authority_retains_catalog_preparation_and_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, residue: str
) -> None:
    store = GuardStore(tmp_path)
    secrets = MemorySecretStore()
    store._extension_control_authority_secret_store = secrets
    if residue == "anchor":
        secrets.set_secret(store._anchor_ref(), "unverified-anchor")
    elif residue == "key":
        secrets.set_secret(store._key_ref(), base64.urlsafe_b64encode(b"k" * 32).decode("ascii"))
    elif residue == "unavailable-secrets":
        secrets.available = False
    else:
        with store._connect() as connection:
            if residue == "schema":
                connection.execute("update extension_control_schema_migration set version = 999 where singleton = 1")
            elif residue == "missing-table":
                connection.execute("drop table extension_control_authority_snapshot")
            else:
                connection.execute(
                    "insert into sync_state(state_key, payload_json, updated_at) values (?, ?, ?)",
                    (residue, '{"unverified":true}', "2026-01-01T00:00:00Z"),
                )
    original_lock = store._extension_control_authority_lock
    original_manifest = store._catalog_target_manifest
    held: list[bool] = []
    compilation_leases: list[tuple[bool, ...]] = []

    @contextmanager
    def observed_lock(*, shared: bool = False) -> Iterator[None]:
        with original_lock(shared=shared):
            held.append(shared)
            try:
                yield
            finally:
                held.pop()

    def observed_manifest(registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
        compilation_leases.append(tuple(held))
        return original_manifest(registry)

    monkeypatch.setattr(store, "_extension_control_authority_lock", observed_lock)
    monkeypatch.setattr(store, "_catalog_target_manifest", observed_manifest)
    if residue == "unavailable-secrets":
        with pytest.raises(RuntimeError, match="credential store unavailable"):
            read_native_command_control_binding(store)
    else:
        binding, _ = read_native_command_control_binding(store)
        assert binding["health"] == ("unenrolled" if residue == "missing-table" else "tampered")
    assert compilation_leases and compilation_leases[0] == ()


def test_enrollment_between_shared_and_exclusive_checks_never_publishes_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    store = _store(tmp_path, MemorySecretStore(), enroll=False)
    original_lock = store._extension_control_authority_lock
    original_manifest = store._catalog_target_manifest
    held: list[bool] = []
    manifest_leases: list[tuple[bool, ...]] = []
    enrolled = False

    @contextmanager
    def enroll_after_shared_release(*, shared: bool = False) -> Iterator[None]:
        nonlocal enrolled
        try:
            with original_lock(shared=shared):
                held.append(shared)
                try:
                    yield
                finally:
                    held.pop()
        finally:
            if shared and not held and not enrolled:
                enrolled = True
                _enroll(store)

    def observed_manifest(registry: CommandSafetyExtensionRegistry) -> dict[str, str]:
        manifest_leases.append(tuple(held))
        return original_manifest(registry)

    monkeypatch.setattr(store, "_extension_control_authority_lock", enroll_after_shared_release)
    monkeypatch.setattr(store, "_catalog_target_manifest", observed_manifest)
    binding, runtime = read_native_command_control_binding(store)
    assert enrolled and binding["health"] == "protected"
    assert manifest_leases and manifest_leases[0] == ()
    stable, _ = read_native_command_control_binding(store, runtime)
    assert stable == binding


def test_retained_protected_runtime_rejects_a_new_unenrolled_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    protected = _store(tmp_path / "protected", MemorySecretStore())
    binding, runtime = read_native_command_control_binding(protected)
    assert binding["health"] == "protected"
    absent = GuardStore(tmp_path / "absent")
    absent._extension_control_authority_secret_store = MemorySecretStore()
    with pytest.raises(NativePolicySnapshotError, match="native_command_control_authority_reused"):
        read_native_command_control_binding(absent, runtime)
