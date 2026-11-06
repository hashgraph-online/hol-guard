"""The durable native runtime copy that frozen hook commands name."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime, native_runtime_durable
from codex_plugin_scanner.guard.adapters.native_hook_bridge import native_hook_bridge_executable
from codex_plugin_scanner.guard.native_runtime_durable import durable_hook_runtime, durable_runtime_path
from codex_plugin_scanner.guard.native_runtime_values import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)

_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode bits")
_FEATURE = "test-hook-bridge-v1"


def _bundled_runtime(tmp_path: Path, content: bytes = b"\x7fELF runtime bytes") -> NativeRuntimeIdentity:
    bundled = tmp_path / "_MEI1234" / "hol-guard-runtime"
    bundled.parent.mkdir(parents=True)
    bundled.write_bytes(content)
    return NativeRuntimeIdentity(
        path=bundled,
        size=len(content),
        mtime_ns=1,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def test_publishes_a_content_addressed_copy_under_the_guard_home(tmp_path: Path) -> None:
    identity = _bundled_runtime(tmp_path)
    guard_home = tmp_path / "guard-home"

    copy = durable_hook_runtime(identity, guard_home)

    assert copy == guard_home / "native-runtime" / identity.sha256 / "hol-guard-runtime"
    assert copy is not None
    assert copy.read_bytes() == identity.path.read_bytes()
    assert os.access(copy, os.X_OK)


def test_reuses_the_copy_after_the_bundle_is_gone(tmp_path: Path) -> None:
    identity = _bundled_runtime(tmp_path)
    guard_home = tmp_path / "guard-home"
    first = durable_hook_runtime(identity, guard_home)
    identity.path.unlink()

    assert durable_hook_runtime(identity, guard_home) == first


def test_a_tampered_copy_is_replaced_from_the_bundle(tmp_path: Path) -> None:
    identity = _bundled_runtime(tmp_path)
    guard_home = tmp_path / "guard-home"
    target = durable_runtime_path(identity, guard_home)
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x" * identity.size)

    assert durable_hook_runtime(identity, guard_home) == target
    assert target.read_bytes() == identity.path.read_bytes()


def test_a_tampered_copy_without_its_bundle_is_never_named(tmp_path: Path) -> None:
    identity = _bundled_runtime(tmp_path)
    guard_home = tmp_path / "guard-home"
    target = durable_runtime_path(identity, guard_home)
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x" * identity.size)
    identity.path.unlink()

    assert durable_hook_runtime(identity, guard_home) is None


@_POSIX_ONLY
def test_a_symlinked_copy_is_replaced_by_a_regular_file(tmp_path: Path) -> None:
    identity = _bundled_runtime(tmp_path)
    guard_home = tmp_path / "guard-home"
    target = durable_runtime_path(identity, guard_home)
    target.parent.mkdir(parents=True)
    target.symlink_to(identity.path)

    assert durable_hook_runtime(identity, guard_home) == target
    assert stat.S_ISREG(target.lstat().st_mode)


@_POSIX_ONLY
def test_a_symlinked_runtime_directory_is_refused(tmp_path: Path) -> None:
    identity = _bundled_runtime(tmp_path)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (guard_home / "native-runtime").symlink_to(elsewhere)

    assert durable_hook_runtime(identity, guard_home) is None
    assert not any(elsewhere.iterdir())


@_POSIX_ONLY
def test_a_group_writable_copy_is_republished_owner_only(tmp_path: Path) -> None:
    identity = _bundled_runtime(tmp_path)
    guard_home = tmp_path / "guard-home"
    target = durable_hook_runtime(identity, guard_home)
    assert target is not None
    target.chmod(0o775)

    assert durable_hook_runtime(identity, guard_home) == target
    assert stat.S_IMODE(target.stat().st_mode) & 0o022 == 0


@_POSIX_ONLY
def test_a_copy_without_its_exec_bit_is_republished_executable(tmp_path: Path) -> None:
    identity = _bundled_runtime(tmp_path)
    guard_home = tmp_path / "guard-home"
    target = durable_hook_runtime(identity, guard_home)
    assert target is not None
    target.chmod(0o600)

    assert durable_hook_runtime(identity, guard_home) == target
    assert os.access(target, os.X_OK)


def test_a_verified_copy_is_hashed_once_until_it_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _bundled_runtime(tmp_path)
    guard_home = tmp_path / "guard-home"
    target = durable_hook_runtime(identity, guard_home)
    assert target is not None
    hashed: list[Path] = []
    real_sha256 = native_runtime_durable._file_sha256

    def counting_sha256(path: Path) -> str:
        hashed.append(path)
        return real_sha256(path)

    monkeypatch.setattr(native_runtime_durable, "_file_sha256", counting_sha256)

    assert durable_hook_runtime(identity, guard_home) == target
    assert durable_hook_runtime(identity, guard_home) == target
    assert hashed == []

    target.write_bytes(b"tampered runtime bytes")

    assert durable_hook_runtime(identity, guard_home) == target
    assert target.read_bytes() == identity.path.read_bytes()
    assert hashed


def test_a_bundle_that_does_not_match_its_identity_is_never_published(tmp_path: Path) -> None:
    identity = _bundled_runtime(tmp_path)
    identity.path.write_bytes(b"\x7fELF swapped bytes!")
    guard_home = tmp_path / "guard-home"

    assert durable_hook_runtime(identity, guard_home) is None
    assert not durable_runtime_path(identity, guard_home).exists()


@pytest.mark.parametrize("digest", ["", "../" + "0" * 61, "A" * 64])
def test_an_unexpected_digest_never_names_a_path(tmp_path: Path, digest: str) -> None:
    identity = _bundled_runtime(tmp_path)
    forged = NativeRuntimeIdentity(path=identity.path, size=identity.size, mtime_ns=1, sha256=digest)

    assert durable_hook_runtime(forged, tmp_path / "guard-home") is None
    assert not (tmp_path / "guard-home").exists()


def _offer(monkeypatch: pytest.MonkeyPatch, identity: NativeRuntimeIdentity) -> None:
    status = NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ok",
        identity=identity,
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0",
            rule_digest="0" * 64,
            build_sha="0" * 40,
            target="test",
            features=(_FEATURE,),
        ),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda *, deadline_monotonic=None: status)


def test_a_frozen_build_names_the_durable_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _bundled_runtime(tmp_path)
    _offer(monkeypatch, identity)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    guard_home = tmp_path / "guard-home"

    assert native_hook_bridge_executable(_FEATURE, guard_home=guard_home) == durable_runtime_path(identity, guard_home)


def test_a_frozen_build_without_a_durable_copy_keeps_its_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _bundled_runtime(tmp_path)
    _offer(monkeypatch, identity)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    identity.path.write_bytes(b"\x7fELF swapped bytes!")

    assert native_hook_bridge_executable(_FEATURE, guard_home=tmp_path / "guard-home") is None


def test_a_source_install_names_the_validated_runtime_itself(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _bundled_runtime(tmp_path)
    _offer(monkeypatch, identity)
    monkeypatch.delattr(sys, "frozen", raising=False)

    assert native_hook_bridge_executable(_FEATURE, guard_home=tmp_path / "guard-home") == identity.path
    assert not (tmp_path / "guard-home").exists()
