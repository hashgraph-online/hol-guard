"""Windows digest reuse must hold a writer-denying handle and re-check its file."""

from __future__ import annotations

import hashlib
import os
import sys
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_binary_identity as identity
from codex_plugin_scanner.guard import native_binary_write_lock as write_lock


@pytest.fixture(autouse=True)
def empty_identity_cache():
    with identity._CACHE_LOCK:
        for key in tuple(identity._IDENTITIES):
            identity._forget_locked(key)
    yield
    with identity._CACHE_LOCK:
        for key in tuple(identity._IDENTITIES):
            identity._forget_locked(key)


def _binary(tmp_path: Path, name: str = "runtime.exe", content: bytes = b"native-runtime-original") -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


class _FakeLocks:
    """Stand-in for the Windows lock: a plain descriptor whose closes are counted."""

    def __init__(self) -> None:
        self.opened: list[int] = []

    def __call__(self, path: Path) -> int:
        if sys.platform == "win32":
            # Share everything so renames behave as they do under the real lock.
            share = write_lock._FILE_SHARE_READ | write_lock._FILE_SHARE_WRITE | write_lock._FILE_SHARE_DELETE
            handle = write_lock._create_file(path, write_lock._GENERIC_READ, share, 0)
            descriptor = write_lock._descriptor_for_handle(handle)
        else:
            descriptor = os.open(path, os.O_RDONLY)
        self.opened.append(descriptor)
        return descriptor

    def open_count(self) -> int:
        count = 0
        for descriptor in self.opened:
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            count += 1
        return count


@pytest.fixture
def windows_reuse(monkeypatch) -> _FakeLocks:
    locks = _FakeLocks()
    monkeypatch.setattr(identity, "_CACHE_ENABLED", False)
    monkeypatch.setattr(identity, "_WRITE_LOCK_ENABLED", True)
    monkeypatch.setattr(identity, "open_write_locked", locks)
    return locks


def _count_hashes(monkeypatch) -> list[object]:
    read = identity._read_digest
    calls: list[object] = []

    def counted(*args):
        calls.append(args)
        return read(*args)

    monkeypatch.setattr(identity, "_read_digest", counted)
    return calls


def test_locked_digest_is_reused_while_the_handle_names_the_same_file(monkeypatch, tmp_path, windows_reuse):
    path = _binary(tmp_path)
    calls = _count_hashes(monkeypatch)
    first = identity.validate_native_binary(path)
    second = identity.validate_native_binary(path)
    assert first is not None and first == second
    assert first.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(calls) == 1
    assert windows_reuse.open_count() == 1


def test_rewritten_timestamps_force_a_new_hash_and_release_the_old_lock(monkeypatch, tmp_path, windows_reuse):
    path = _binary(tmp_path)
    calls = _count_hashes(monkeypatch)
    before = identity.validate_native_binary(path)
    metadata = path.stat()
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000))
    after = identity.validate_native_binary(path)
    assert before is not None and after is not None
    assert len(calls) == 2
    assert windows_reuse.open_count() == 1
    assert len(identity._WRITE_LOCKS) == 1


def test_replaced_path_is_hashed_again(tmp_path, windows_reuse):
    path = _binary(tmp_path)
    before = identity.validate_native_binary(path)
    replacement = _binary(tmp_path, "replacement.exe", b"native-runtime-modified")
    metadata = path.stat()
    os.utime(replacement, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    path.rename(tmp_path / "retired.exe")
    replacement.replace(path)
    after = identity.validate_native_binary(path)
    assert before is not None and after is not None
    assert after.sha256 == hashlib.sha256(b"native-runtime-modified").hexdigest()
    assert windows_reuse.open_count() == 1


def test_lock_is_closed_when_the_hash_is_rejected(monkeypatch, tmp_path, windows_reuse):
    path = _binary(tmp_path)
    monkeypatch.setattr(identity, "_read_digest", lambda *_: None)
    assert identity.validate_native_binary(path) is None
    assert windows_reuse.open_count() == 0
    assert not identity._IDENTITIES and not identity._WRITE_LOCKS


def test_unproven_lock_falls_back_to_hashing_every_lookup(monkeypatch, tmp_path):
    path = _binary(tmp_path)
    monkeypatch.setattr(identity, "_CACHE_ENABLED", False)
    monkeypatch.setattr(identity, "_WRITE_LOCK_ENABLED", True)
    monkeypatch.setattr(identity, "open_write_locked", lambda _path: None)
    calls = _count_hashes(monkeypatch)
    assert identity.validate_native_binary(path) is not None
    assert identity.validate_native_binary(path) is not None
    assert len(calls) == 2
    assert not identity._IDENTITIES


@pytest.mark.parametrize(
    ("os_name", "version", "supported"),
    [("nt", (3, 10, 11), False), ("nt", (3, 11, 9), False), ("nt", (3, 12, 0), True), ("posix", (3, 13, 1), False)],
)
def test_write_lock_needs_full_windows_file_ids(os_name, version, supported):
    assert identity._write_lock_supported(os_name, version) is supported


def test_interpreters_without_full_file_ids_never_cache(monkeypatch, tmp_path):
    path = _binary(tmp_path)
    monkeypatch.setattr(identity, "_CACHE_ENABLED", False)
    monkeypatch.setattr(identity, "_WRITE_LOCK_ENABLED", identity._write_lock_supported("nt", (3, 11, 9)))
    opened: list[Path] = []
    monkeypatch.setattr(identity, "open_write_locked", lambda found: opened.append(found))
    calls = _count_hashes(monkeypatch)
    assert identity.validate_native_binary(path) is not None
    assert identity.validate_native_binary(path) is not None
    assert len(calls) == 2
    assert not opened and not identity._WRITE_LOCKS and not identity._IDENTITIES


def test_evicted_entries_close_their_locks(monkeypatch, tmp_path, windows_reuse):
    monkeypatch.setattr(identity, "_MAX_IDENTITIES", 2)
    for index in range(3):
        assert identity.validate_native_binary(_binary(tmp_path, f"{index}.exe")) is not None
    assert len(identity._IDENTITIES) == 2 and len(identity._WRITE_LOCKS) == 2
    assert windows_reuse.open_count() == 2


class _FakeWinapi:
    def __init__(self, probe_error: int | None) -> None:
        self.probe_error = probe_error
        self.closed: list[int] = []
        self.requests: list[tuple[int, int]] = []

    def create_file(self, path: Path, access: int, share: int, flags: int) -> int:
        self.requests.append((access, share))
        if access == write_lock._FILE_WRITE_DATA and self.probe_error is not None:
            error = OSError("probe refused")
            error.winerror = self.probe_error  # pyright: ignore[reportAttributeAccessIssue]
            raise error
        return 1000 + len(self.requests)

    def close_handle(self, handle: int) -> None:
        self.closed.append(handle)


@pytest.mark.parametrize(
    ("probe_error", "locked"),
    [(write_lock._ERROR_SHARING_VIOLATION, True), (5, False), (None, False)],
)
def test_lock_requires_the_filesystem_to_refuse_a_writer(monkeypatch, tmp_path, probe_error, locked):
    path = _binary(tmp_path)
    fake = _FakeWinapi(probe_error)
    descriptor = os.open(path, os.O_RDONLY)
    monkeypatch.setattr(write_lock, "_ENABLED", True)
    monkeypatch.setattr(write_lock, "_create_file", fake.create_file)
    monkeypatch.setattr(write_lock, "_close_handle", fake.close_handle)
    monkeypatch.setattr(write_lock, "_descriptor_for_handle", lambda _handle: descriptor)
    result = write_lock.open_write_locked(path)
    try:
        os.fstat(descriptor)
        still_open = True
    except OSError:
        still_open = False
    if still_open:
        os.close(descriptor)
    lock_access, lock_share = fake.requests[0]
    assert lock_access == write_lock._GENERIC_READ
    assert lock_share & write_lock._FILE_SHARE_WRITE == 0
    assert lock_share & write_lock._FILE_SHARE_DELETE
    assert (result is not None) is locked
    assert still_open is locked
    # A probe that opened the file is closed without ever writing to it.
    assert fake.closed == ([] if probe_error is not None else [1002])


def test_lock_is_unavailable_off_windows(tmp_path):
    if sys.platform == "win32":
        pytest.skip("covered by the Windows kernel test")
    assert write_lock.open_write_locked(_binary(tmp_path)) is None


@pytest.mark.skipif(not identity._WRITE_LOCK_ENABLED, reason="needs Windows on Python 3.12 or later")
def test_windows_kernel_refuses_writers_while_digest_is_reused(tmp_path):
    path = _binary(tmp_path)
    first = identity.validate_native_binary(path)
    assert first is not None and identity._WRITE_LOCKS
    with pytest.raises(PermissionError):
        path.write_bytes(b"native-runtime-modified")
    with pytest.raises(PermissionError), open(path, "r+b"):
        pass
    # Replacing the binary in place is refused, exactly as it is while the
    # runtime is running; moving it aside stays allowed.
    staged = _binary(tmp_path, "staged.exe", b"native-runtime-modified")
    with pytest.raises(PermissionError):
        staged.replace(path)
    assert identity.validate_native_binary(path) == first
    path.rename(tmp_path / "renamed.exe")
    staged.replace(path)
    after = identity.validate_native_binary(path)
    assert after is not None and after.sha256 == hashlib.sha256(b"native-runtime-modified").hexdigest()
    assert len(identity._WRITE_LOCKS) == 1


def _evict(key: tuple[str, tuple[int, ...]]) -> None:
    with identity._CACHE_LOCK:
        identity._forget_locked(key)


def _still_open(descriptor: int) -> bool:
    try:
        os.fstat(descriptor)
    except OSError:
        return False
    return True


def test_an_eviction_cannot_interleave_with_the_reused_digests_path_check(monkeypatch, tmp_path, windows_reuse):
    """The handle check and the path check are one decision, not two.

    The held handle is the whole proof that a cached digest still describes the
    file, because it is what keeps every writer out. If another thread can
    evict the entry and close that handle while the reuse path checks the
    paths, a Windows owner can rewrite the bytes in place and restore the size
    and timestamps that check reads, and the digest of the old bytes comes back
    for a file that no longer holds them.
    """

    path = _binary(tmp_path)
    first = identity.validate_native_binary(path)
    assert first is not None
    key = next(iter(identity._WRITE_LOCKS))
    descriptor = identity._WRITE_LOCKS[key]
    stable = identity._stable_names
    calls: list[int] = []
    observed: list[tuple[bool, bool]] = []
    evictor = threading.Thread(target=_evict, args=(key,))

    def watched(*args: object) -> bool:
        calls.append(1)
        # The first call precedes the cache lookup; the second is the reuse path.
        if len(calls) == 2:
            evictor.start()
            evictor.join(0.2)
            held = not identity._CACHE_LOCK.acquire(blocking=False)
            if not held:
                identity._CACHE_LOCK.release()
            observed.append((held, _still_open(descriptor)))
        return stable(*args)

    monkeypatch.setattr(identity, "_stable_names", watched)
    try:
        second = identity.validate_native_binary(path)
    finally:
        if evictor.is_alive() or evictor.ident is not None:
            evictor.join(5)

    assert observed == [(True, True)]
    assert second == first
