"""Stable daemon observations must coexist with a native process's read lease."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.daemon.extension_control_observation import read_observed_extension_control_authority
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHTTPServer
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityView
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_managed_source_support import managed_store
from tests.test_guard_extension_control_authority import _upgraded_registry
from tests.test_native_policy_authority_read_leases import _shared_lease_available

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX cross-process flock contract")


@pytest.mark.parametrize("cloud", [None, False, True])
@pytest.mark.parametrize("consumer", ["background", "dashboard"])
def test_stable_daemon_refresh_keeps_a_native_process_read_lease_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cloud: bool | None, consumer: str
) -> None:
    store = GuardStore(tmp_path / "guard") if cloud is None else managed_store(tmp_path, monkeypatch, cloud=cloud)
    before = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    runtime = ExtensionControlRuntime(before)
    original = store._read_extension_control_authority_locked
    observations: list[bool] = []

    def observe(
        catalog_digest: str,
        *,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> ExtensionControlAuthorityView:
        observations.append(_shared_lease_available(store))
        return original(catalog_digest, migration_registry=migration_registry, connection=connection)

    monkeypatch.setattr(store, "_read_extension_control_authority_locked", observe)
    if consumer == "background":
        # Exercise the actual method without creating an unrelated listener.
        host = object.__new__(_GuardDaemonHTTPServer)
        host.store, host.extension_control_runtime = store, runtime
        _ = host.refresh_extension_control_runtime()
    else:
        service = ExtensionControlApiService(store=store, registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY, runtime=runtime)
        _ = service.refresh()
    assert observations and all(observations)
    assert runtime.current().revision == before.revision
    assert runtime.current().managed_revision == before.managed_revision
    assert runtime.current().layers == before.layers


def test_real_catalog_migration_releases_the_shared_lease_before_its_exclusive_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=False)
    before = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    registry = _upgraded_registry()
    assert registry.catalog_digest != before.catalog_digest
    original = store._read_extension_control_authority_locked
    observations: list[bool] = []

    def observe(
        catalog_digest: str,
        *,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> ExtensionControlAuthorityView:
        observations.append(_shared_lease_available(store))
        return original(catalog_digest, migration_registry=migration_registry, connection=connection)

    monkeypatch.setattr(store, "_read_extension_control_authority_locked", observe)
    after = read_observed_extension_control_authority(store, registry)
    # The authenticated migration reader may recurse while inspecting the
    # old catalog. Every read after mutation preparation must retain EX.
    first_exclusive = observations.index(False)
    assert first_exclusive > 0 and all(observations[:first_exclusive])
    assert not any(observations[first_exclusive:])
    assert after.health == before.health
    assert after.catalog_digest == registry.catalog_digest
    assert after.revision == before.revision + 1
    assert [control for layer in after.layers for control in layer.controls] == [
        control for layer in before.layers for control in layer.controls
    ]
