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
from codex_plugin_scanner.guard.native_runtime import native_runtime_status
from codex_plugin_scanner.guard.native_runtime_request_scope import (
    _REQUEST_STATUS,
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


def test_scope_recomputes_when_the_native_mode_changes(
    status_probe: tuple[Path, list[Path]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _binary, calls = status_probe
    with native_status_request_scope():
        first = native_runtime_status()
        monkeypatch.setenv("HOL_GUARD_NATIVE", "shadow")
        second = native_runtime_status()
    assert len(calls) == 2
    assert second is not first
    assert second.mode == "shadow"


def test_scope_recomputes_when_the_candidate_set_changes(
    status_probe: tuple[Path, list[Path]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary, calls = status_probe
    other = tmp_path / "other-runtime"
    other.write_bytes(b"other-runtime")
    other.chmod(0o700)
    with native_status_request_scope():
        first = native_runtime_status()
        monkeypatch.setattr(native_runtime_module, "_runtime_candidates", lambda: (other,))
        second = native_runtime_status()
        monkeypatch.setattr(native_runtime_module, "_runtime_candidates", lambda: (binary,))
        third = native_runtime_status()
    assert len(calls) == 2
    assert second is not first
    assert second.identity is not None
    assert second.identity.path == other.resolve()
    assert third is first


def test_scope_revalidates_when_the_candidate_path_repoints(
    status_probe: tuple[Path, list[Path]],
    tmp_path: Path,
) -> None:
    binary, calls = status_probe
    with native_status_request_scope():
        first = native_runtime_status()
        assert first.identity is not None
        # Swap the candidate for a symlink to a byte-identical, timestamp-
        # identical file: stat() cannot tell them apart, but the resolved
        # candidate path no longer matches the stored identity.
        target = tmp_path / "target-runtime"
        target.write_bytes(binary.read_bytes())
        target.chmod(0o700)
        metadata = binary.stat()
        os.utime(target, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        binary.unlink()
        binary.symlink_to(target)
        second = native_runtime_status()
    assert len(calls) == 2
    assert second is not first


def _manifest_json(
    binary: Path,
    *,
    package_version: str,
    rule_digest: str,
    source_sha: str,
) -> str:
    identity = _identity_for(binary)
    return json.dumps(
        {
            "schema": "hol-guard-native-runtime.v1",
            "protocol_version": 1,
            "package_version": package_version,
            "target": "x86_64-unknown-linux-musl",
            "platform_tag": "linux_x86_64",
            "source_sha": source_sha,
            "rule_digest": rule_digest,
            "runtime_sha256": identity.sha256,
            "runtime_size": identity.size,
        }
    )


def test_scope_hit_rechecks_the_bundled_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "hol-guard-runtime"
    binary.write_bytes(b"bundled-request-scope-runtime")
    binary.chmod(0o700)
    calls: list[Path] = []
    package_version = native_runtime_module._python_package_version() or "0.0.0"
    source_sha = "a" * 40

    def write_manifest(*, rule_digest: str = "b" * 64) -> None:
        manifest_path = binary.with_name("runtime-manifest.json")
        manifest_path.write_text(
            _manifest_json(
                binary,
                package_version=package_version,
                rule_digest=rule_digest,
                source_sha=source_sha,
            ),
            encoding="utf-8",
        )
        if os.name != "nt":
            manifest_path.chmod(0o600)

    write_manifest()

    def validate(candidate: Path) -> native_runtime_module.NativeRuntimeIdentity:
        calls.append(candidate)
        return _identity_for(candidate)

    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setattr(native_runtime_module, "_bundled_runtime_candidate", lambda: binary)
    monkeypatch.setattr(native_runtime_module, "_runtime_candidates", lambda: (binary,))
    monkeypatch.setattr(native_runtime_module, "_validate_binary", validate)
    monkeypatch.setattr(
        native_runtime_module,
        "_capabilities_for_identity",
        lambda *args, **kwargs: native_runtime_module.NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version=package_version,
            rule_digest="b" * 64,
            build_sha=source_sha,
            target="x86_64-unknown-linux-musl",
            features=(),
        ),
    )
    native_runtime_module._clear_capabilities_probe_state()

    with native_status_request_scope():
        first = native_runtime_status()
        assert first.manifest is not None
        # Manifest unchanged: the hit re-reads the small JSON and reuses.
        second = native_runtime_status()
        # A manifest-only rewrite leaves the binary untouched; the hit check
        # must recompute instead of serving the stale provenance.
        write_manifest(rule_digest="c" * 64)
        third = native_runtime_status()

    assert second is first
    assert len(calls) == 2
    assert third is not first
    assert third.reason == "native_manifest_rule_mismatch"
    assert third.manifest is not None


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
