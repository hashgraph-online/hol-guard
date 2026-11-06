"""Publisher status must not enumerate unused fallback distributions."""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_runtime as runtime
from codex_plugin_scanner.guard import native_runtime_process_cache as process_cache
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_runtime_request_scope import native_status_request_scope
from codex_plugin_scanner.guard.native_runtime_status_share import share_verified_runtime_status


def identity(path: Path) -> runtime.NativeRuntimeIdentity:
    metadata = path.stat()
    return runtime.NativeRuntimeIdentity(
        path=path.resolve(),
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


@pytest.fixture
def preferred(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    binary, bundled = tmp_path / "preferred", tmp_path / "bundled"
    for path in (binary, bundled):
        path.write_bytes(b"verified-test-runtime")
        path.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary))
    monkeypatch.setattr(runtime, "_bundled_runtime_candidate", lambda: bundled)
    monkeypatch.setattr(process_cache, "_ENABLED", False)
    monkeypatch.setattr(runtime, "_is_bundled_candidate", lambda _path: False)
    capabilities = runtime.NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="0.0.0",
        rule_digest="b" * 64,
        build_sha="a" * 40,
        target="x86_64-unknown-linux-musl",
        features=(),
    )
    validations: list[Path] = []
    discoveries: list[str] = []

    def validate(path: Path):
        validations.append(path)
        return identity(path) if path.exists() else None

    def distribution(name: str):
        discoveries.append(name)
        raise runtime.importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(runtime, "_validate_binary", validate)
    monkeypatch.setattr(runtime, "_capabilities_for_identity", lambda *args, **kwargs: capabilities)
    monkeypatch.setattr(runtime.importlib.metadata, "distribution", distribution)
    runtime._clear_capabilities_probe_state()
    status = runtime.NativeRuntimeStatus(
        mode="force",
        available=True,
        compatible=True,
        reason="native_ready",
        identity=identity(binary),
        capabilities=capabilities,
    )
    yield SimpleNamespace(
        binary=binary, bundled=bundled, status=status, validations=validations, discoveries=discoveries
    )
    runtime._clear_capabilities_probe_state()


def test_sharing_first_choice_does_not_enumerate_fallbacks(preferred):
    with native_status_request_scope():
        share_verified_runtime_status(preferred.status)
    assert preferred.discoveries == []
    assert preferred.validations == []


def test_hook_publisher_share_is_consumed_without_discovery_or_second_hash(preferred):
    worker = SimpleNamespace(
        policy_snapshot_publisher=SimpleNamespace(
            current_runtime_status=lambda: preferred.status,
        )
    )
    with native_status_request_scope():
        assert HookWorker._native_runtime_status(worker) is preferred.status
        assert runtime.native_runtime_status() is preferred.status
        assert runtime.native_runtime_status() is preferred.status
    assert preferred.discoveries == []
    assert preferred.validations == []


def test_shared_choice_does_not_escape_its_request(preferred):
    with native_status_request_scope():
        share_verified_runtime_status(preferred.status)
        assert runtime.native_runtime_status() is preferred.status
    assert preferred.discoveries == []
    with native_status_request_scope():
        assert runtime.native_runtime_status() is not preferred.status
    assert preferred.discoveries == ["hol-guard-runtime"]
    assert preferred.validations == [preferred.binary]


def test_outside_scope_share_does_not_seed_a_global_cache(preferred):
    share_verified_runtime_status(preferred.status)
    assert preferred.discoveries == []
    with native_status_request_scope():
        assert runtime.native_runtime_status() is not preferred.status
    assert preferred.discoveries == ["hol-guard-runtime"]
    assert preferred.validations == [preferred.binary]


def test_changed_binary_requires_discovery_and_validation(preferred):
    with native_status_request_scope():
        share_verified_runtime_status(preferred.status)
        preferred.discoveries.clear()
        preferred.binary.write_bytes(b"replacement-runtime-with-new-size")
        current = runtime.native_runtime_status()
    assert current is not preferred.status
    assert current.identity == identity(preferred.binary)
    assert preferred.discoveries == ["hol-guard-runtime"]
    assert preferred.validations == [preferred.binary]


def test_removed_first_choice_falls_back_after_revalidation(preferred):
    with native_status_request_scope():
        share_verified_runtime_status(preferred.status)
        preferred.discoveries.clear()
        preferred.binary.unlink()
        current = runtime.native_runtime_status()
    assert current.identity == identity(preferred.bundled)
    assert preferred.discoveries == ["hol-guard-runtime"]
    assert preferred.validations == [preferred.binary, preferred.bundled]


def test_changed_override_cannot_reuse_the_old_publisher(preferred, monkeypatch):
    with native_status_request_scope():
        share_verified_runtime_status(preferred.status)
        preferred.discoveries.clear()
        monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(preferred.bundled))
        current = runtime.native_runtime_status()
    assert current.identity == identity(preferred.bundled)
    assert preferred.validations == [preferred.bundled]


def test_mode_change_cannot_reuse_force_status(preferred, monkeypatch):
    with native_status_request_scope():
        share_verified_runtime_status(preferred.status)
        preferred.discoveries.clear()
        monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
        current = runtime.native_runtime_status()
    assert current.mode == "auto" and current is not preferred.status
    assert current.identity == identity(preferred.bundled)
    assert preferred.discoveries == []


def test_changed_manifest_refuses_scoped_reuse(preferred, monkeypatch):
    manifest = runtime.NativeRuntimeManifest(
        schema="s",
        protocol_version=1,
        package_version="0.0.0",
        target="t",
        platform_tag="p",
        source_sha="a" * 40,
        rule_digest="b" * 64,
        runtime_sha256="c" * 64,
        runtime_size=preferred.status.identity.size,
    )
    status = dataclasses.replace(preferred.status, manifest=manifest)
    current_manifest = [manifest]
    monkeypatch.setattr(runtime, "_manifest_for_bundled_identity", lambda _identity: (current_manifest[0], None))
    with native_status_request_scope():
        share_verified_runtime_status(status)
        preferred.discoveries.clear()
        current_manifest[0] = dataclasses.replace(manifest, source_sha="d" * 40)
        assert runtime.native_runtime_status() is not status
    assert preferred.discoveries == ["hol-guard-runtime"]
    assert preferred.validations == [preferred.binary]


def test_fallback_publisher_cannot_displace_a_usable_first_choice(preferred):
    fallback = dataclasses.replace(preferred.status, identity=identity(preferred.bundled))
    with native_status_request_scope():
        share_verified_runtime_status(fallback)
        assert runtime.native_runtime_status().identity == identity(preferred.binary)
    assert preferred.validations == [preferred.binary]


@pytest.mark.parametrize(
    "change",
    [
        {"available": False},
        {"compatible": False},
        {"identity": None},
        {"mode": "auto"},
    ],
)
def test_unusable_publisher_never_seeds_the_scope(preferred, change):
    unusable = dataclasses.replace(preferred.status, **change)
    with native_status_request_scope():
        share_verified_runtime_status(unusable)
        assert runtime.native_runtime_status() is not unusable
    assert preferred.validations == [preferred.binary]


def test_automatic_bundled_publisher_keeps_request_reuse(preferred, monkeypatch):
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    status = dataclasses.replace(preferred.status, mode="auto", identity=identity(preferred.bundled))
    with native_status_request_scope():
        share_verified_runtime_status(status)
        assert runtime.native_runtime_status() is status
    assert preferred.discoveries == []
    assert preferred.validations == []


def test_relative_override_still_selects_bundled_publisher(preferred, monkeypatch):
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", "relative-runtime")
    status = dataclasses.replace(preferred.status, identity=identity(preferred.bundled))
    with native_status_request_scope():
        share_verified_runtime_status(status)
        assert runtime.native_runtime_status() is status
    assert preferred.discoveries == []
    assert preferred.validations == []
