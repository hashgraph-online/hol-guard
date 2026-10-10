"""Request-scoped native runtime status reuse.

A single daemon hook request probes ``native_runtime_status`` from several
review-path call sites, and every probe re-hashes the whole runtime binary.
``native_status_request_scope`` shares one validated status per request while
``stat()`` still shows the same size/mtime_ns; every new request re-validates.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_runtime as native_runtime_module
from codex_plugin_scanner.guard.native_runtime import (
    _REQUEST_STATUS,
    native_runtime_status,
    native_status_request_scope,
)


def _capabilities() -> native_runtime_module.NativeRuntimeCapabilities:
    return native_runtime_module.NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="0.0.0",
        rule_digest="b" * 64,
        build_sha="a" * 40,
        target="x86_64-unknown-linux-musl",
        features=(),
    )


def _identity_for(binary: Path) -> native_runtime_module.NativeRuntimeIdentity:
    metadata = binary.stat()
    return native_runtime_module.NativeRuntimeIdentity(
        path=binary.resolve(),
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    )


@pytest.fixture
def status_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[Path, list[Path]]]:
    """Hermetic ready-status probe: one tmp binary, counted validations."""

    binary = tmp_path / "hol-guard-runtime"
    binary.write_bytes(b"request-scope-runtime")
    binary.chmod(0o700)
    calls: list[Path] = []
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")

    def validate(candidate: Path) -> native_runtime_module.NativeRuntimeIdentity:
        calls.append(candidate)
        return _identity_for(candidate)

    monkeypatch.setattr(native_runtime_module, "_runtime_candidates", lambda: (binary,))
    monkeypatch.setattr(native_runtime_module, "_validate_binary", validate)
    monkeypatch.setattr(
        native_runtime_module,
        "_capabilities_for_identity",
        lambda *args, **kwargs: _capabilities(),
    )
    native_runtime_module._clear_capabilities_probe_state()
    yield binary, calls


def test_scope_validates_the_binary_once_for_repeated_status_calls(
    status_probe: tuple[Path, list[Path]],
) -> None:
    binary, calls = status_probe
    with native_status_request_scope():
        first = native_runtime_status()
        second = native_runtime_status()
    assert first.reason == "native_ready"
    assert second is first
    assert calls == [binary]


def test_scope_revalidates_when_the_binary_size_changes(
    status_probe: tuple[Path, list[Path]],
) -> None:
    binary, calls = status_probe
    with native_status_request_scope():
        first = native_runtime_status()
        binary.write_bytes(b"request-scope-runtime-longer")
        second = native_runtime_status()
    assert len(calls) == 2
    assert second is not first
    assert first.identity is not None
    assert second.identity is not None
    assert second.identity.size != first.identity.size


def test_scope_revalidates_when_the_binary_mtime_changes(
    status_probe: tuple[Path, list[Path]],
) -> None:
    binary, calls = status_probe
    with native_status_request_scope():
        first = native_runtime_status()
        metadata = binary.stat()
        os.utime(binary, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000))
        second = native_runtime_status()
    assert len(calls) == 2
    assert second is not first


def test_status_validates_each_call_outside_a_scope(
    status_probe: tuple[Path, list[Path]],
) -> None:
    binary, calls = status_probe
    assert native_runtime_status().reason == "native_ready"
    assert native_runtime_status().reason == "native_ready"
    assert calls == [binary, binary]


def test_scope_does_not_cache_unavailable_statuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing-runtime"
    calls: list[Path] = []

    def validate(candidate: Path) -> None:
        calls.append(candidate)
        return None

    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setattr(native_runtime_module, "_runtime_candidates", lambda: (missing,))
    monkeypatch.setattr(native_runtime_module, "_validate_binary", validate)
    with native_status_request_scope() as scope:
        assert native_runtime_status().reason == "native_unavailable"
        assert native_runtime_status().reason == "native_unavailable"
    assert len(calls) == 2
    assert scope == {}


def test_scope_does_not_cache_off_mode_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    with native_status_request_scope() as scope:
        assert native_runtime_status().reason == "native_disabled"
        assert native_runtime_status().reason == "native_disabled"
    assert scope == {}


def test_scope_resets_after_an_exception() -> None:
    with pytest.raises(RuntimeError, match="boom"), native_status_request_scope():
        raise RuntimeError("boom")
    assert _REQUEST_STATUS.get() is None


def test_nested_scopes_share_one_store() -> None:
    with native_status_request_scope() as outer, native_status_request_scope() as inner:
        assert inner is outer
    assert _REQUEST_STATUS.get() is None


def test_scope_does_not_leak_into_another_thread() -> None:
    observed: list[object] = []
    with native_status_request_scope():
        thread = threading.Thread(target=lambda: observed.append(_REQUEST_STATUS.get()))
        thread.start()
        thread.join()
    assert observed == [None]
    assert _REQUEST_STATUS.get() is None


def test_daemon_hook_dispatch_enters_the_request_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live ``POST /v1/hooks/<harness>`` runs its handler inside the scope."""
    from codex_plugin_scanner.guard.daemon import GuardDaemonServer
    from codex_plugin_scanner.guard.daemon import server as server_module
    from codex_plugin_scanner.guard.store import GuardStore

    observed: list[object] = []

    def record_scope(handler, payload, query, *, default_harness):
        del payload, query, default_harness
        observed.append(_REQUEST_STATUS.get())
        handler._write_json({"decision": "deny", "reason": "request-scope probe"})

    monkeypatch.setattr(
        server_module._GuardDaemonHandler,
        "_handle_runtime_hook",
        record_scope,
    )
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/hooks/pi",
            data=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"}).encode(),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": daemon._server.auth_token,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read())
    finally:
        daemon.stop()

    assert result["reason"] == "request-scope probe"
    assert len(observed) == 1
    assert isinstance(observed[0], dict)
    assert _REQUEST_STATUS.get() is None
