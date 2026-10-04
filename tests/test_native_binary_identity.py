"""Native identity reuse must detect tampering, replacement and read races."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_binary_identity as identity


@pytest.fixture(autouse=True)
def empty_identity_cache():
    with identity._CACHE_LOCK:
        identity._IDENTITIES.clear()
    yield
    with identity._CACHE_LOCK:
        identity._IDENTITIES.clear()


def _binary(tmp_path: Path, name: str = "runtime") -> Path:
    path = tmp_path / name
    path.write_bytes(b"native-runtime-original")
    path.chmod(0o700)
    return path


def test_unchanged_binary_reuses_hash_only_when_cache_is_supported(monkeypatch, tmp_path):
    path = _binary(tmp_path)
    read = identity._read_digest
    calls = []

    def counted(*args):
        calls.append(args)
        return read(*args)

    monkeypatch.setattr(identity, "_read_digest", counted)
    monkeypatch.setattr(identity.time, "time_ns", lambda: path.stat().st_ctime_ns + identity._MIN_CACHE_AGE_NS)
    first = identity.validate_native_binary(path)
    second = identity.validate_native_binary(path)
    assert first is not None and first == second
    assert first.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(calls) == (1 if identity._CACHE_ENABLED else 2)


def test_uncached_platform_rehashes_every_time(monkeypatch, tmp_path):
    path = _binary(tmp_path)
    monkeypatch.setattr(identity, "_CACHE_ENABLED", False)
    assert identity.validate_native_binary(path) is not None
    monkeypatch.setattr(identity, "_read_digest", lambda *_: None)
    assert identity.validate_native_binary(path) is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX change-time invalidation")
def test_same_size_mutation_with_restored_mtime_invalidates_digest(tmp_path):
    path = _binary(tmp_path)
    metadata = path.stat()
    before = identity.validate_native_binary(path)
    path.write_bytes(b"native-runtime-modified")
    assert path.stat().st_size == metadata.st_size
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    after = identity.validate_native_binary(path)
    assert before is not None and after is not None
    assert after.sha256 != before.sha256
    assert after.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert not identity._IDENTITIES


def test_same_size_replacement_with_restored_mtime_invalidates_digest(tmp_path):
    path = _binary(tmp_path)
    metadata = path.stat()
    before = identity.validate_native_binary(path)
    replacement = _binary(tmp_path, "replacement")
    replacement.write_bytes(b"native-runtime-modified")
    os.utime(replacement, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    replacement.replace(path)
    after = identity.validate_native_binary(path)
    assert before is not None and after is not None
    assert after.sha256 != before.sha256


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_permissions_are_rechecked_after_cache_hit(tmp_path):
    path = _binary(tmp_path)
    assert identity.validate_native_binary(path) is not None
    path.chmod(0o722)
    assert identity.validate_native_binary(path) is None


@pytest.mark.skipif(os.name != "posix", reason="symlink support")
def test_replacing_cached_path_with_symlink_is_rejected(tmp_path):
    path = _binary(tmp_path)
    assert identity.validate_native_binary(path) is not None
    target = _binary(tmp_path, "target")
    path.unlink()
    path.symlink_to(target)
    assert identity.validate_native_binary(path) is None


def test_changed_file_during_hash_is_rejected(monkeypatch, tmp_path):
    path = _binary(tmp_path)
    read = identity._read_digest

    def mutate(*args):
        result = read(*args)
        path.write_bytes(b"changed during hash")
        return result

    monkeypatch.setattr(identity, "_read_digest", mutate)
    assert identity.validate_native_binary(path) is None
    assert not identity._IDENTITIES


def test_file_replaced_before_descriptor_open_is_rejected(monkeypatch, tmp_path):
    path = _binary(tmp_path)
    replacement = _binary(tmp_path, "replacement")
    opened = identity.os.open

    def swap(*args, **kwargs):
        replacement.replace(path)
        return opened(*args, **kwargs)

    monkeypatch.setattr(identity.os, "open", swap)
    assert identity.validate_native_binary(path) is None
    assert not identity._IDENTITIES


def test_descriptor_change_during_read_is_rejected(monkeypatch, tmp_path):
    path = _binary(tmp_path)
    read = identity.os.read
    mutated = False

    def mutate(*args):
        nonlocal mutated
        result = read(*args)
        if not mutated:
            mutated = True
            path.write_bytes(b"changed inside descriptor read")
        return result

    monkeypatch.setattr(identity.os, "read", mutate)
    assert identity.validate_native_binary(path) is None
    assert not identity._IDENTITIES


def test_missing_files_and_directories_are_rejected(tmp_path):
    assert identity.validate_native_binary(tmp_path) is None
    assert identity.validate_native_binary(tmp_path / "missing") is None


@pytest.mark.skipif(not identity._CACHE_ENABLED, reason="identity cache disabled")
def test_identity_cache_is_bounded(monkeypatch, tmp_path):
    monkeypatch.setattr(identity, "_MAX_IDENTITIES", 2)
    monkeypatch.setattr(identity, "_cacheable", lambda _: True)
    for index in range(3):
        assert identity.validate_native_binary(_binary(tmp_path, str(index))) is not None
    assert len(identity._IDENTITIES) == 2


@pytest.mark.parametrize("age", [0, 1, 1_999_999_999, -1])
def test_recent_or_future_change_time_never_enables_reuse(monkeypatch, tmp_path, age):
    path = _binary(tmp_path)
    metadata = path.stat()
    monkeypatch.setattr(identity, "_CACHE_ENABLED", True)
    monkeypatch.setattr(identity.time, "time_ns", lambda: metadata.st_ctime_ns + age)
    assert identity.validate_native_binary(path) is not None
    assert not identity._IDENTITIES


@pytest.mark.skipif(os.name != "posix", reason="POSIX change-time invalidation")
def test_aged_cached_binary_detects_same_size_restored_mtime_mutation(tmp_path):
    import time

    path = _binary(tmp_path)
    metadata = path.stat()
    time.sleep(2.05)
    before = identity.validate_native_binary(path)
    assert before is not None and identity._IDENTITIES
    path.write_bytes(b"native-runtime-modified")
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    after = identity.validate_native_binary(path)
    assert after is not None and after.sha256 != before.sha256
