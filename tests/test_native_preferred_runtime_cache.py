"""First-choice reuse must avoid fallback I/O without keeping changed authority."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import time
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_runtime as runtime
from codex_plugin_scanner.guard import native_runtime_process_cache as cache

pytestmark = pytest.mark.skipif(not cache._ENABLED, reason="process identity reuse is POSIX-only")


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    binary = tmp_path / "hol-guard-runtime"
    binary.write_bytes(b"preferred-native-runtime")
    binary.chmod(0o700)
    manifest = binary.with_name("runtime-manifest.json")
    value = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "0.0.0",
        "target": "test-native-target",
        "platform_tag": "test-native-platform",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "runtime_size": binary.stat().st_size,
    }
    manifest.write_text(json.dumps(value))
    manifest.chmod(0o600)
    calls = []

    def distribution(name):
        assert name == "hol-guard-runtime"
        calls.append(name)
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary))
    monkeypatch.setattr(cache, "_MIN_AGE_NS", 0)
    monkeypatch.setattr(runtime, "_bundled_runtime_candidate", lambda: binary)
    monkeypatch.setattr(runtime, "_python_package_version", lambda: "0.0.0")
    monkeypatch.setattr(importlib.metadata, "distribution", distribution)
    monkeypatch.setattr(
        runtime,
        "_capabilities_for_identity",
        lambda *args, **kwargs: runtime.NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0.0.0",
            rule_digest="b" * 64,
            build_sha="a" * 40,
            target="test-native-target",
            features=(),
        ),
    )
    runtime._clear_capabilities_probe_state()
    yield binary, manifest, value, calls
    runtime._clear_capabilities_probe_state()


def test_ready_first_choice_does_not_consult_unreadable_unused_distribution(artifact, monkeypatch):
    _binary, _manifest, _value, calls = artifact
    first = runtime.native_runtime_status()
    assert first.compatible and len(calls) == 1

    def unused_fallback(name):
        pytest.fail("ready first-choice status consulted lower-priority distribution metadata")

    monkeypatch.setattr(importlib.metadata, "distribution", unused_fallback)
    assert runtime.native_runtime_status() is first


def test_ready_first_choice_ignores_an_installed_lower_priority_distribution(artifact, monkeypatch):
    binary, _manifest, _value, calls = artifact
    fallback = binary.with_name("distribution-runtime")
    fallback.write_bytes(b"unused-distribution-runtime")
    fallback.chmod(0o700)

    def distribution(name):
        calls.append(name)
        return SimpleNamespace(files=["hol-guard-runtime"], locate_file=lambda entry: fallback)

    monkeypatch.setattr(importlib.metadata, "distribution", distribution)
    first = runtime.native_runtime_status()
    assert first.identity.path == binary and len(calls) == 1

    def unused_fallback(name):
        pytest.fail("ready first choice rescanned its installed lower-priority distribution")

    monkeypatch.setattr(importlib.metadata, "distribution", unused_fallback)
    assert runtime.native_runtime_status() is first


def test_same_size_binary_rewrite_with_restored_mtime_invalidates_first_choice(artifact):
    binary, _manifest, _value, calls = artifact
    first = runtime.native_runtime_status()
    before = binary.stat()
    binary.write_bytes(b"X" * before.st_size)
    os.utime(binary, ns=(before.st_atime_ns, before.st_mtime_ns))
    changed = runtime.native_runtime_status()
    assert changed is not first and not changed.compatible
    assert len(calls) == 2


def test_manifest_rewrite_with_restored_mtime_invalidates_first_choice(artifact):
    _binary, manifest, value, calls = artifact
    first = runtime.native_runtime_status()
    before = manifest.stat()
    manifest.write_text(json.dumps({**value, "source_sha": "c" * 40}))
    os.utime(manifest, ns=(before.st_atime_ns, before.st_mtime_ns))
    changed = runtime.native_runtime_status()
    assert changed is not first and not changed.compatible
    assert len(calls) == 2


def test_manifest_permission_change_invalidates_first_choice(artifact):
    _binary, manifest, _value, calls = artifact
    first = runtime.native_runtime_status()
    manifest.chmod(0o666)
    changed = runtime.native_runtime_status()
    assert changed is not first and not changed.compatible
    assert len(calls) == 2


def test_changed_override_recomputes_candidate_priority(artifact, monkeypatch):
    binary, _manifest, _value, calls = artifact
    first = runtime.native_runtime_status()
    other = binary.with_name("other-native-runtime")
    other.write_bytes(b"other-runtime")
    other.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(other))
    changed = runtime.native_runtime_status()
    assert changed is not first and changed.identity.path == other
    assert len(calls) == 2


def test_auto_mode_ignores_a_changed_override_instead_of_reusing_force(artifact, monkeypatch):
    binary, _manifest, _value, calls = artifact
    first = runtime.native_runtime_status()
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary.with_name("untrusted-other")))
    changed = runtime.native_runtime_status()
    assert changed is not first and changed.mode == "auto" and changed.identity.path == binary
    assert len(calls) == 1


def test_expired_deadline_does_not_reuse_ready_first_choice(artifact):
    _binary, _manifest, _value, calls = artifact
    assert runtime.native_runtime_status().compatible
    expired = runtime.native_runtime_status(deadline_monotonic=time.monotonic() - 1)
    assert not expired.available and not expired.compatible
    assert len(calls) == 2


def test_fresh_files_do_not_skip_candidate_discovery(artifact, monkeypatch):
    _binary, _manifest, _value, calls = artifact
    monkeypatch.setattr(cache, "_MIN_AGE_NS", time.time_ns())
    runtime.native_runtime_status()
    runtime.native_runtime_status()
    assert len(calls) == 2


def test_missing_primary_does_not_hide_a_later_primary_arrival(artifact, monkeypatch):
    binary, _manifest, _value, calls = artifact
    missing = binary.with_name("initially-missing-primary")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(missing))
    fallback = runtime.native_runtime_status()
    assert fallback.identity.path == binary
    missing.write_bytes(b"new-primary")
    missing.chmod(0o700)
    arrived = runtime.native_runtime_status()
    assert arrived.identity.path == missing and len(calls) == 2


def test_unsupported_process_cache_does_not_skip_discovery(artifact, monkeypatch):
    _binary, _manifest, _value, calls = artifact
    monkeypatch.setattr(cache, "_ENABLED", False)
    runtime.native_runtime_status()
    runtime.native_runtime_status()
    assert len(calls) == 2
