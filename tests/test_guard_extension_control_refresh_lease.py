"""Periodic authority readers must not masquerade as live control mutations."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHttpServer
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    hold_command_control_authority_lock,
    require_command_control_mutation_lease,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityView
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("mutation_required", [False, True])
def test_refresh_shares_unchanged_authority_and_excludes_readers_only_for_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation_required: bool
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    initial = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    server = cast(
        _GuardDaemonHttpServer,
        cast(
            object,
            SimpleNamespace(
                store=store,
                extension_control_runtime=ExtensionControlRuntime(initial),
                _installed_authority_pending=False,
                _extension_control_on_core_registry=False,
            ),
        ),
    )
    read_locked = store._read_extension_control_authority_locked
    entered = threading.Event()
    release = threading.Event()
    attempts = 0

    def paused_read(
        catalog_digest: str,
        *,
        migration_registry: CommandSafetyExtensionRegistry | None = None,
        allow_migration: bool = True,
    ) -> ExtensionControlAuthorityView:
        nonlocal attempts
        attempts += 1
        if mutation_required:
            # This is the existing guard used before catalog migration and
            # authority recovery writes. A shared attempt must unwind first.
            require_command_control_mutation_lease(store.guard_home)
        view = read_locked(catalog_digest, migration_registry=migration_registry, allow_migration=allow_migration)
        entered.set()
        assert release.wait(timeout=5)
        return view

    monkeypatch.setattr(store, "_read_extension_control_authority_locked", paused_read)
    with ThreadPoolExecutor(max_workers=1) as executor:
        refresh = executor.submit(_GuardDaemonHttpServer.refresh_extension_control_runtime, server)
        try:
            assert entered.wait(timeout=5)
            # A separate thread and file descriptor exercise the actual OS
            # lease used by a native request, without reentrant ownership.
            if mutation_required:
                with (
                    pytest.raises(TimeoutError),
                    hold_command_control_authority_lock(store.guard_home, shared=True, timeout_seconds=0),
                ):
                    pass
            else:
                with hold_command_control_authority_lock(store.guard_home, shared=True, timeout_seconds=0):
                    pass
            with (
                pytest.raises(TimeoutError),
                hold_command_control_authority_lock(store.guard_home, timeout_seconds=0),
            ):
                pass
        finally:
            release.set()
        result = refresh.result(timeout=5)

    assert attempts == (2 if mutation_required else 1)
    assert result.health is initial.health
    assert result.revision == initial.revision
    # Both the read attempt and the exclusive fallback release their leases.
    with hold_command_control_authority_lock(store.guard_home, timeout_seconds=0):
        pass


@pytest.mark.parametrize("mutation_required", [False, True])
def test_busy_refresh_retains_the_installed_authority_even_during_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation_required: bool
) -> None:
    from codex_plugin_scanner.guard.native_command_control_authority_io import (
        NativeCommandControlAuthorityUnavailableError,
        NativeCommandControlMutationRequiredError,
    )

    store = GuardStore(tmp_path / "guard-home")
    initial = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    runtime = ExtensionControlRuntime(initial)
    installed = runtime.current()
    server = cast(
        _GuardDaemonHttpServer,
        cast(
            object,
            SimpleNamespace(
                store=store,
                extension_control_runtime=runtime,
                _installed_authority_pending=False,
                _extension_control_on_core_registry=False,
            ),
        ),
    )
    attempts = []

    def busy(registry, *, read_only=False):
        attempts.append((registry.catalog_digest, read_only))
        if mutation_required and read_only:
            raise NativeCommandControlMutationRequiredError()
        raise NativeCommandControlAuthorityUnavailableError(shared=read_only)

    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", busy)
    assert _GuardDaemonHttpServer.refresh_extension_control_runtime(server) is installed
    assert runtime.current() is installed
    assert attempts == [(initial.catalog_digest, True)] + (
        [(initial.catalog_digest, False)] if mutation_required else []
    )
    # Both failed attempts release their fences; a later real mutation can run.
    with hold_command_control_authority_lock(store.guard_home, timeout_seconds=0):
        pass


@pytest.mark.parametrize("tamper", [None, "floor", "stamp"])
def test_authenticated_startup_retains_its_floor_under_a_live_native_reader(
    tmp_path, monkeypatch, native_hook_force, tamper
):
    from codex_plugin_scanner.guard.catalog_delivery import lifecycle, lifecycle_store, preparation_authority
    from codex_plugin_scanner.guard.native_command_control_authority_store import _key
    from tests.native_activation_support import native, seed

    store = GuardStore(tmp_path / "guard-home")
    floor = seed(store)
    stamp = native("migrate", key=_key(store).hex(), floor=floor, stamp=None)["stamp"]
    backend = store._policy_integrity_secret_store
    if tamper == "floor":
        record = json.loads(floor)
        record["mac"] = "f" * 64
        floor = json.dumps(record)
        backend.set_secret(store._build_scoped_secret_ref(lifecycle_store.PREFIX), floor)
    elif tamper == "stamp":
        stamp = "invalid-enrollment-stamp"
    backend.set_secret(store._build_scoped_secret_ref(lifecycle_store.STAMP), stamp)
    monkeypatch.setattr(lifecycle, "invoke", native)
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", lambda: object())

    def unexpected_write(*args, **kwargs):
        pytest.fail("an authenticated retained migration must not rewrite protected state")

    monkeypatch.setattr(backend, "set_secret", unexpected_write)
    with (
        ThreadPoolExecutor(max_workers=1) as executor,
        hold_command_control_authority_lock(store.guard_home, shared=True),
    ):
        result = executor.submit(store.migrate_installed_command_pack_authority)
        if tamper is None:
            result.result(timeout=5)
        else:
            with pytest.raises(ValueError, match="pack_lifecycle_"):
                result.result(timeout=5)
    assert lifecycle_store.read(store) == floor
    assert backend.get_secret(store._build_scoped_secret_ref(lifecycle_store.STAMP)) == stamp
