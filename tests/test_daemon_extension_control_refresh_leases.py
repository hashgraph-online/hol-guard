"""Routine daemon control refresh must coexist with independent native readers."""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHTTPServer
from codex_plugin_scanner.guard.native_command_control_authority import AUTHORITY_LOCK_NAME
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth, AuthorityPhase
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime

from .test_guard_extension_control_authority import MemorySecretStore, _commit, _store

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Independent POSIX native-reader lease contract")


@pytest.fixture(autouse=True)
def _allow_fixture_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _independent_shared_reader(home: Path) -> bool:
    import fcntl

    # Use a separately opened descriptor and the OS operation used by native
    # admission, not the production Python lock's thread-local bookkeeping.
    with (home / AUTHORITY_LOCK_NAME).open("r+b") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return True


def _observe_held_operation(
    operation: Callable[[], object], entered: threading.Event, release: threading.Event, home: Path
) -> tuple[bool, list[object]]:
    results: list[object] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            results.append(operation())
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        assert entered.wait(5.0), "real operation did not reach the retained authority lease"
        acquired = _independent_shared_reader(home)
    finally:
        release.set()
        worker.join(5.0)
    assert not worker.is_alive(), "real operation did not finish after release"
    assert errors == []
    assert len(results) == 1
    assert _independent_shared_reader(home), "completed operation retained its authority lease"
    return acquired, results


def test_unchanged_daemon_refresh_admits_independent_native_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    before = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert before.health is AuthorityHealth.PROTECTED and before.revision == 1 and before.layers
    runtime = ExtensionControlRuntime(before)
    initial = runtime.current()
    # The real method has only these two service dependencies; avoid starting
    # unrelated sockets, publisher and maintenance threads in this lock test.
    server = object.__new__(_GuardDaemonHTTPServer)
    server.store, server.extension_control_runtime = store, runtime
    entered, release = threading.Event(), threading.Event()
    original_read = store._read_extension_control_authority_locked

    def hold_verified_read(*args: Any, **kwargs: Any) -> Any:
        view = original_read(*args, **kwargs)
        assert view.health is AuthorityHealth.PROTECTED and view.revision == before.revision
        if not entered.is_set():
            entered.set()
            assert release.wait(5.0), "test did not release verified authority read"
        return view

    monkeypatch.setattr(store, "_read_extension_control_authority_locked", hold_verified_read)
    acquired, results = _observe_held_operation(
        lambda: _GuardDaemonHTTPServer.refresh_extension_control_runtime(server), entered, release, tmp_path
    )
    assert results == [initial]
    assert runtime.current() == initial
    assert store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY) == before
    assert acquired, "unchanged daemon refresh excluded an independent native shared reader"


def test_signed_control_mutation_still_excludes_independent_native_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    _commit(store)
    before = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert before.health is AuthorityHealth.PROTECTED and before.revision == 1 and before.layers
    entered, release = threading.Event(), threading.Event()
    original_anchor = store._write_and_verify_anchor

    def hold_anchored_mutation(anchor: Any, *, key: bytes) -> None:
        original_anchor(anchor, key=key)
        if anchor.phase is AuthorityPhase.ANCHORED:
            entered.set()
            assert release.wait(5.0), "test did not release authenticated control mutation"

    monkeypatch.setattr(store, "_write_and_verify_anchor", hold_anchored_mutation)
    acquired, results = _observe_held_operation(
        lambda: _commit(store, revision=before.revision, key="change-2"), entered, release, tmp_path
    )
    assert results == [None]
    after = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert after.health is AuthorityHealth.PROTECTED and after.revision == before.revision + 1
    assert after.layers == before.layers
    assert not acquired, "signed control mutation allowed an independent native shared reader"
