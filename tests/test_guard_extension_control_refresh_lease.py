"""Periodic authority readers must not masquerade as live control mutations."""

from __future__ import annotations

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
        cast(object, SimpleNamespace(store=store, extension_control_runtime=ExtensionControlRuntime(initial))),
    )
    read_locked = store._read_extension_control_authority_locked
    entered = threading.Event()
    release = threading.Event()
    attempts = 0

    def paused_read(
        catalog_digest: str, *, migration_registry: CommandSafetyExtensionRegistry | None = None
    ) -> ExtensionControlAuthorityView:
        nonlocal attempts
        attempts += 1
        if mutation_required:
            # This is the existing guard used before catalog migration and
            # authority recovery writes. A shared attempt must unwind first.
            require_command_control_mutation_lease(store.guard_home)
        view = read_locked(catalog_digest, migration_registry=migration_registry)
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
