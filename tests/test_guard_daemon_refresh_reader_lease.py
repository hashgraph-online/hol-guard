"""Resident authority refresh must coexist with native evaluation readers."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHTTPServer
from codex_plugin_scanner.guard.native_command_control_authority import AUTHORITY_LOCK_NAME
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState, ResolverFailureCode
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore

from .test_guard_extension_control_authority import MemorySecretStore, _commit_enabled_permission, _store

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX native-reader flock interoperability witness")


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _resident(store: GuardStore) -> _GuardDaemonHTTPServer:
    # Exercise the real refresh method without unrelated socket or worker setup.
    server = object.__new__(_GuardDaemonHTTPServer)
    server.store = store
    initial = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert initial.health is AuthorityHealth.PROTECTED
    server.extension_control_runtime = ExtensionControlRuntime(initial)
    return server


@contextmanager
def _foreign_lease(guard_home: Path, *, shared: bool) -> Iterator[None]:
    import fcntl

    # A separately opened file description has no Python thread-local ownership,
    # matching a native reader's independent flock acquisition.
    with (guard_home / AUTHORITY_LOCK_NAME).open("rb") as handle:
        fcntl.flock(handle.fileno(), (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _trace_leases(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    *,
    after_shared_release: Callable[[], None] | None = None,
) -> list[bool]:
    calls: list[bool] = []

    @contextmanager
    def traced(*, shared: bool = False) -> Iterator[None]:
        calls.append(shared)
        try:
            # Bound only this fault witness; production keeps its existing wait.
            with hold_command_control_authority_lock(store.guard_home, shared=shared, timeout_seconds=0):
                yield
        finally:
            if shared and after_shared_release is not None:
                after_shared_release()

    monkeypatch.setattr(store, "_extension_control_authority_lock", traced)
    return calls


def _manifest_count(store: GuardStore) -> int:
    with store._connect() as connection:
        return int(connection.execute("select count(*) from extension_control_catalog_manifest").fetchone()[0])


def _remove_manifest(store: GuardStore) -> None:
    with store._connect() as connection:
        connection.execute("delete from extension_control_catalog_manifest")


def test_unchanged_refresh_coexists_with_native_shared_lease(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, MemorySecretStore())
    server = _resident(store)
    initial = server.extension_control_runtime.current()
    calls = _trace_leases(store, monkeypatch)

    with _foreign_lease(store.guard_home, shared=True):
        refreshed = server.refresh_extension_control_runtime()
        assert refreshed.health is AuthorityHealth.PROTECTED
        assert refreshed == initial
        assert calls == [True]
        with pytest.raises(BlockingIOError), _foreign_lease(store.guard_home, shared=False):
            pytest.fail("refresh revoked the independent native reader's shared lease")


def test_missing_manifest_releases_shared_lease_before_mutation_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, MemorySecretStore())
    server = _resident(store)
    _remove_manifest(store)
    released = []

    def after_shared_release() -> None:
        assert _manifest_count(store) == 0
        with _foreign_lease(store.guard_home, shared=False):
            released.append(True)

    calls = _trace_leases(store, monkeypatch, after_shared_release=after_shared_release)

    refreshed = server.refresh_extension_control_runtime()

    assert refreshed.health is AuthorityHealth.PROTECTED
    assert calls == [True, False]
    assert released == [True]
    assert _manifest_count(store) == 1


@pytest.mark.parametrize("failure", ["tampered_manifest", "unavailable_key"])
def test_untrusted_refresh_remains_fail_closed_without_exclusive_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    server = _resident(store)
    if failure == "tampered_manifest":
        with store._connect() as connection:
            connection.execute("update extension_control_catalog_manifest set record_mac = ?", ("0" * 64,))
        expected_health = AuthorityHealth.TAMPERED
        expected_failure = ResolverFailureCode.AUTHORITY_TAMPERED
    else:
        secrets.available = False
        expected_health = AuthorityHealth.DEGRADED_UNACKNOWLEDGED
        expected_failure = ResolverFailureCode.AUTHORITY_UNAVAILABLE
    calls = _trace_leases(store, monkeypatch)

    with _foreign_lease(store.guard_home, shared=True):
        refreshed = server.refresh_extension_control_runtime()

    assert refreshed.health is expected_health
    assert refreshed.authority_failure is expected_failure
    assert calls == [True]


def test_retry_reads_authority_committed_after_shared_lease_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    server = _resident(store)
    other = GuardStore(tmp_path, prime_policy_integrity=False)
    other._extension_control_authority_secret_store = secrets
    _remove_manifest(store)
    permission_id = "command.container-runtime.permission.compose-destructive-cleanup"
    committed = []

    def after_shared_release() -> None:
        with _foreign_lease(store.guard_home, shared=False):
            assert _manifest_count(store) == 0
        # A separate store can mutate in the gap. The retry must reread its
        # authenticated revision and controls, not reuse the first read's view.
        other.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        _commit_enabled_permission(other, permission_id, key="commit-between-refresh-leases")
        committed.append(True)

    calls = _trace_leases(store, monkeypatch, after_shared_release=after_shared_release)

    refreshed = server.refresh_extension_control_runtime()

    assert committed == [True]
    assert calls == [True, False]
    assert refreshed.health is AuthorityHealth.PROTECTED
    assert refreshed.revision == 1
    assert any(
        control.target.target_id == permission_id and control.state is ControlState.ENABLED
        for layer in refreshed.layers
        for control in layer.controls
    )
