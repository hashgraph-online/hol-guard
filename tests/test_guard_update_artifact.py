"""Security contracts for immutable local update-wheel staging."""

from __future__ import annotations

import ctypes
import hashlib
import os
import stat
import types
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_artifact as artifact_module
from codex_plugin_scanner.guard.cli.update_artifact import (
    UpdateArtifactError,
    record_local_wheel_receipt,
    recover_local_wheel_original,
    stage_trusted_wheel,
)


def _wheel_path(root: Path, *, distribution: str = "hol_guard", version: str = "1.2.3") -> Path:
    return root / f"{distribution}-{version}-py3-none-any.whl"


def _metadata(*, name: str = "hol-guard", version: str = "1.2.3", suffix: bytes = b"") -> bytes:
    return f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n".encode() + suffix


def _write_wheel(path: Path, entries: list[tuple[str, bytes]] | None = None) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata_entries = entries or [("hol_guard-1.2.3.dist-info/METADATA", _metadata())]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in metadata_entries:
            archive.writestr(name, content)
    return path.read_bytes()


def _neutral_cwd(root: Path) -> Path:
    neutral = root / "neutral"
    neutral.mkdir(mode=0o700)
    return neutral


def _assert_reason(expected: str, callable_: object) -> None:
    assert callable(callable_)
    with pytest.raises(UpdateArtifactError) as exc_info:
        callable_()
    assert exc_info.value.reason_code == expected
    assert str(exc_info.value) == expected


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")


class _FakeWindowsFunction:
    def __init__(self, callback: Callable[..., object]) -> None:
        self.callback = callback
        self.argtypes: list[object] = []
        self.restype: object | None = None

    def __call__(self, *args: object) -> object:
        return self.callback(*args)


def test_stage_valid_wheel_is_private_hashed_revalidated_and_cleaned(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    source_bytes = _write_wheel(source)
    neutral = _neutral_cwd(tmp_path)

    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=neutral)

    expected_digest = hashlib.sha256(source_bytes).hexdigest()
    assert artifact.original_path == source.resolve()
    assert artifact.staged_path.parent.parent == neutral / "wheels"
    assert artifact.staging_root == artifact.staged_path.parent
    assert artifact.staged_path.name == source.name
    assert artifact.version == "1.2.3"
    assert artifact.sha256 == expected_digest
    assert artifact.size == len(source_bytes)
    assert artifact.staged_path.read_bytes() == source_bytes
    artifact.revalidate()
    if os.name != "nt":
        assert stat.S_IMODE(artifact.staging_root.stat().st_mode) == 0o700
        assert stat.S_IMODE(artifact.staged_path.stat().st_mode) == 0o600

    artifact.cleanup()
    artifact.cleanup()
    assert not artifact.staged_path.exists()
    assert not artifact.staging_root.exists()
    assert (neutral / "wheels").is_dir()


def test_local_wheel_receipt_recovers_original_after_staging_cleanup(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    staged_path = artifact.staged_path

    receipt_path = record_local_wheel_receipt(
        artifact,
        guard_home=guard_home,
        installed_version=artifact.version,
    )
    artifact.cleanup()
    recovered = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=staged_path,
        installed_version=artifact.version,
        wheel_sha256=artifact.sha256,
    )

    assert receipt_path == guard_home / "local-wheel-source.json"
    assert recovered == source.resolve()
    assert not staged_path.exists()
    if os.name != "nt":
        assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600


def test_local_wheel_receipt_rejects_changed_original_bytes(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    staged_path = artifact.staged_path
    record_local_wheel_receipt(artifact, guard_home=guard_home, installed_version=artifact.version)
    original_bytes = source.read_bytes()
    source.write_bytes(bytes([original_bytes[0] ^ 1]) + original_bytes[1:])
    assert source.stat().st_size == artifact.size
    artifact.cleanup()

    recovered = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=staged_path,
        installed_version=artifact.version,
        wheel_sha256=artifact.sha256,
    )

    assert recovered is None


@pytest.mark.parametrize("mismatch", ["staged_path", "version", "sha256"])
def test_local_wheel_receipt_rejects_metadata_mismatch(tmp_path: Path, mismatch: str) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    record_local_wheel_receipt(artifact, guard_home=guard_home, installed_version=artifact.version)

    recovered = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=(
            artifact.staged_path.with_name("other.whl") if mismatch == "staged_path" else artifact.staged_path
        ),
        installed_version="9.9.9" if mismatch == "version" else artifact.version,
        wheel_sha256="0" * 64 if mismatch == "sha256" else artifact.sha256,
    )

    assert recovered is None
    artifact.cleanup()


def test_local_wheel_receipt_missing_file_fails_closed(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)

    recovered = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=tmp_path / "missing.whl",
        installed_version="1.2.3",
        wheel_sha256="0" * 64,
    )

    assert recovered is None


def test_local_wheel_receipt_recovery_reads_bound_descriptor_not_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    record_local_wheel_receipt(artifact, guard_home=guard_home, installed_version=artifact.version)

    def forbidden_path_read(_path: Path) -> bytes:
        raise AssertionError("receipt recovery must read from its already-validated descriptor")

    monkeypatch.setattr(Path, "read_bytes", forbidden_path_read)

    recovered = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=artifact.staged_path,
        installed_version=artifact.version,
        wheel_sha256=artifact.sha256,
    )

    assert recovered == source.resolve()
    artifact.cleanup()


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor identity regression")
def test_local_wheel_receipt_rejects_oversized_file_without_reading_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    receipt_path = record_local_wheel_receipt(
        artifact,
        guard_home=guard_home,
        installed_version=artifact.version,
    )
    receipt_path.write_bytes(b"x" * (artifact_module._LOCAL_WHEEL_RECEIPT_MAX_BYTES + 1))
    receipt_metadata = receipt_path.stat()
    real_read = artifact_module.os.read

    def reject_receipt_read(file_descriptor: int, count: int) -> bytes:
        metadata = os.fstat(file_descriptor)
        if (metadata.st_dev, metadata.st_ino) == (receipt_metadata.st_dev, receipt_metadata.st_ino):
            raise AssertionError("an oversized receipt must be rejected before any content read")
        return real_read(file_descriptor, count)

    monkeypatch.setattr(artifact_module.os, "read", reject_receipt_read)

    recovered = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=artifact.staged_path,
        installed_version=artifact.version,
        wheel_sha256=artifact.sha256,
    )

    assert recovered is None
    artifact.cleanup()


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory-entry swap regression")
def test_local_wheel_receipt_rejects_entry_swap_during_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    receipt_path = record_local_wheel_receipt(
        artifact,
        guard_home=guard_home,
        installed_version=artifact.version,
    )
    receipt_bytes = receipt_path.read_bytes()
    moved_receipt = receipt_path.with_suffix(".moved")
    real_read_bounded = artifact_module._read_bounded_descriptor
    swapped = False

    def swap_receipt_entry(
        file_descriptor: int,
        *,
        maximum_bytes: int,
        reason_code: str,
    ) -> bytes:
        nonlocal swapped
        if not swapped:
            swapped = True
            receipt_path.rename(moved_receipt)
            receipt_path.write_bytes(receipt_bytes)
        return real_read_bounded(
            file_descriptor,
            maximum_bytes=maximum_bytes,
            reason_code=reason_code,
        )

    monkeypatch.setattr(artifact_module, "_read_bounded_descriptor", swap_receipt_entry)

    recovered = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=artifact.staged_path,
        installed_version=artifact.version,
        wheel_sha256=artifact.sha256,
    )

    assert swapped is True
    assert recovered is None
    assert moved_receipt.is_file()
    artifact.cleanup()


@pytest.mark.skipif(os.name == "nt", reason="POSIX openat/renameat/fsync contract")
def test_local_wheel_receipt_record_uses_bound_atomic_rename_and_syncs_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    real_rename = artifact_module.os.rename
    real_fsync = artifact_module.os.fsync
    rename_calls: list[tuple[str, str, int | None, int | None]] = []
    synchronized_modes: list[int] = []

    def track_rename(
        source_name: str,
        destination_name: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        rename_calls.append((source_name, destination_name, src_dir_fd, dst_dir_fd))
        real_rename(
            source_name,
            destination_name,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    def track_fsync(file_descriptor: int) -> None:
        synchronized_modes.append(os.fstat(file_descriptor).st_mode)
        real_fsync(file_descriptor)

    monkeypatch.setattr(artifact_module.os, "rename", track_rename)
    monkeypatch.setattr(artifact_module.os, "fsync", track_fsync)

    record_local_wheel_receipt(artifact, guard_home=guard_home, installed_version=artifact.version)

    assert len(rename_calls) == 1
    source_name, destination_name, source_directory, destination_directory = rename_calls[0]
    assert isinstance(source_name, str) and source_name.startswith(".local-wheel-source.json.")
    assert destination_name == "local-wheel-source.json"
    assert source_directory is not None
    assert source_directory == destination_directory
    assert any(stat.S_ISREG(mode) for mode in synchronized_modes)
    assert any(stat.S_ISDIR(mode) for mode in synchronized_modes)
    artifact.cleanup()


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory swap regression")
def test_local_wheel_receipt_record_never_redirects_into_replacement_guard_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    moved_guard_home = tmp_path / "guard-home-moved"
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    real_write_all = artifact_module._write_all
    replacement_temporary: Path | None = None

    def swap_guard_home_after_write(file_descriptor: int, data: bytes) -> None:
        nonlocal replacement_temporary
        real_write_all(file_descriptor, data)
        guard_home.rename(moved_guard_home)
        guard_home.mkdir(mode=0o700)
        original_temporary = next(moved_guard_home.glob(".local-wheel-source.json.*"))
        replacement_temporary = guard_home / original_temporary.name
        replacement_temporary.write_bytes(data)

    monkeypatch.setattr(artifact_module, "_write_all", swap_guard_home_after_write)

    _assert_reason(
        "update_artifact_receipt_failed",
        lambda: record_local_wheel_receipt(
            artifact,
            guard_home=guard_home,
            installed_version=artifact.version,
        ),
    )

    assert replacement_temporary is not None and replacement_temporary.is_file()
    assert not (guard_home / "local-wheel-source.json").exists()
    assert not (moved_guard_home / "local-wheel-source.json").exists()
    assert list(moved_guard_home.glob(".local-wheel-source.json.*")) == []
    artifact.cleanup()


@pytest.mark.skipif(os.name == "nt", reason="POSIX atomic replacement regression")
def test_local_wheel_receipt_record_replaces_destination_symlink_without_following(
    tmp_path: Path,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"do-not-overwrite")
    receipt_path = guard_home / "local-wheel-source.json"
    _symlink_or_skip(receipt_path, outside)

    persisted_path = record_local_wheel_receipt(
        artifact,
        guard_home=guard_home,
        installed_version=artifact.version,
    )

    assert persisted_path == receipt_path
    assert receipt_path.is_file() and not receipt_path.is_symlink()
    assert outside.read_bytes() == b"do-not-overwrite"
    artifact.cleanup()


@pytest.mark.skipif(os.name == "nt", reason="POSIX capability fallback regression")
def test_local_wheel_receipt_fails_closed_without_descriptor_relative_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    monkeypatch.setattr(artifact_module, "_POSIX_RECEIPT_DIR_FD_SUPPORTED", False)

    _assert_reason(
        "update_artifact_receipt_failed",
        lambda: record_local_wheel_receipt(
            artifact,
            guard_home=guard_home,
            installed_version=artifact.version,
        ),
    )
    recovered = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=artifact.staged_path,
        installed_version=artifact.version,
        wheel_sha256=artifact.sha256,
    )

    assert recovered is None
    assert not (guard_home / "local-wheel-source.json").exists()
    artifact.cleanup()


@pytest.mark.skipif(not hasattr(os, "mkfifo") or os.name == "nt", reason="POSIX special-file regression")
@pytest.mark.parametrize("replacement_kind", ["symlink", "fifo"])
def test_local_wheel_receipt_recovery_never_follows_special_entry(
    tmp_path: Path,
    replacement_kind: str,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    receipt_path = record_local_wheel_receipt(
        artifact,
        guard_home=guard_home,
        installed_version=artifact.version,
    )
    moved_receipt = receipt_path.with_suffix(".moved")
    receipt_path.rename(moved_receipt)
    if replacement_kind == "symlink":
        receipt_path.symlink_to(moved_receipt)
    else:
        os.mkfifo(receipt_path)

    recovered = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=artifact.staged_path,
        installed_version=artifact.version,
        wheel_sha256=artifact.sha256,
    )

    assert recovered is None
    artifact.cleanup()


def test_regular_descriptor_dispatches_to_atomic_windows_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("C:/Guard/update.whl")
    metadata = os.stat_result((stat.S_IFREG | 0o600, 17, 3, 1, 0, 0, 41, 0, 0, 0))
    calls: list[tuple[Path | str, str]] = []

    def fake_windows_open(
        opened_path: Path | str,
        *,
        reason_code: str,
    ) -> tuple[int, os.stat_result]:
        calls.append((opened_path, reason_code))
        return 83, metadata

    monkeypatch.setattr(artifact_module.os, "name", "nt")
    monkeypatch.setattr(artifact_module, "_open_windows_regular_descriptor", fake_windows_open)

    result = artifact_module._open_regular_descriptor(path, reason_code="artifact-failed")

    assert result == (83, metadata)
    assert calls == [(path, "artifact-failed")]


def test_windows_regular_descriptor_uses_bound_handle_without_cross_api_path_stat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = os.stat_result((stat.S_IFREG | 0o600, 17, 3, 1, 0, 0, 41, 0, 0, 0))
    create_arguments: list[tuple[object, ...]] = []
    converted_handles: list[tuple[int, int]] = []
    closed_handles: list[object] = []

    def create_file(*arguments: object) -> int:
        create_arguments.append(arguments)
        return 71

    def get_information(_handle: object, information_pointer: ctypes.c_void_p) -> int:
        information = ctypes.cast(
            information_pointer,
            ctypes.POINTER(artifact_module._WindowsByHandleFileInformation),
        ).contents
        information.dwFileAttributes = 0x00000020
        return 1

    def close_handle(handle: object) -> int:
        closed_handles.append(handle)
        return 1

    def open_osfhandle(handle: int, flags: int) -> int:
        converted_handles.append((handle, flags))
        return 83

    kernel32 = types.SimpleNamespace(
        CreateFileW=_FakeWindowsFunction(create_file),
        GetFileInformationByHandle=_FakeWindowsFunction(get_information),
        CloseHandle=_FakeWindowsFunction(close_handle),
    )
    fake_msvcrt = types.SimpleNamespace(open_osfhandle=open_osfhandle)
    monkeypatch.setattr(artifact_module.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setattr(artifact_module.importlib, "import_module", lambda _name: fake_msvcrt)
    monkeypatch.setattr(artifact_module.os, "fstat", lambda descriptor: metadata if descriptor == 83 else None)
    monkeypatch.setattr(
        artifact_module.os,
        "lstat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("a Win32-bound file must not be compared with path lstat metadata")
        ),
    )

    descriptor, opened_metadata = artifact_module._open_windows_regular_descriptor(
        Path("C:/Guard/update.whl"),
        reason_code="artifact-failed",
    )

    assert descriptor == 83
    assert opened_metadata is metadata
    assert converted_handles and converted_handles[0][0] == 71
    assert closed_handles == []
    assert len(create_arguments) == 1
    assert create_arguments[0][0] == str(Path("C:/Guard/update.whl"))
    assert create_arguments[0][1] == artifact_module._WINDOWS_GENERIC_READ
    assert create_arguments[0][2] == (
        artifact_module._WINDOWS_FILE_SHARE_READ | artifact_module._WINDOWS_FILE_SHARE_WRITE
    )
    assert create_arguments[0][5] == artifact_module._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT


def test_windows_regular_descriptor_rejects_reparse_and_closes_bound_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed_handles: list[object] = []

    def get_information(_handle: object, information_pointer: ctypes.c_void_p) -> int:
        information = ctypes.cast(
            information_pointer,
            ctypes.POINTER(artifact_module._WindowsByHandleFileInformation),
        ).contents
        information.dwFileAttributes = artifact_module._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        return 1

    def close_handle(handle: object) -> int:
        closed_handles.append(handle)
        return 1

    def forbidden_conversion(_handle: int, _flags: int) -> int:
        raise AssertionError("a reparse-point handle must not become a CRT descriptor")

    kernel32 = types.SimpleNamespace(
        CreateFileW=_FakeWindowsFunction(lambda *_args: 71),
        GetFileInformationByHandle=_FakeWindowsFunction(get_information),
        CloseHandle=_FakeWindowsFunction(close_handle),
    )
    fake_msvcrt = types.SimpleNamespace(open_osfhandle=forbidden_conversion)
    monkeypatch.setattr(artifact_module.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setattr(artifact_module.importlib, "import_module", lambda _name: fake_msvcrt)

    _assert_reason(
        "artifact-failed",
        lambda: artifact_module._open_windows_regular_descriptor(
            Path("C:/Guard/update.whl"),
            reason_code="artifact-failed",
        ),
    )

    assert closed_handles == [71]


def test_windows_receipt_child_lock_is_atomic_non_delete_shared_and_delete_on_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_arguments: list[tuple[object, ...]] = []
    closed_handles: list[object] = []

    def create_file(*arguments: object) -> int:
        create_arguments.append(arguments)
        return 71

    def get_information(_handle: object, information_pointer: ctypes.c_void_p) -> int:
        information = ctypes.cast(
            information_pointer,
            ctypes.POINTER(artifact_module._WindowsByHandleFileInformation),
        ).contents
        information.dwFileAttributes = artifact_module._WINDOWS_FILE_ATTRIBUTE_NORMAL
        return 1

    def close_handle(handle: object) -> int:
        closed_handles.append(handle)
        return 1

    kernel32 = types.SimpleNamespace(
        CreateFileW=_FakeWindowsFunction(create_file),
        GetFileInformationByHandle=_FakeWindowsFunction(get_information),
        CloseHandle=_FakeWindowsFunction(close_handle),
    )
    monkeypatch.setattr(artifact_module.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setattr(artifact_module.os, "getpid", lambda: 4102)
    monkeypatch.setattr(artifact_module.os, "urandom", lambda _size: b"\xab" * 16)

    child_handle = artifact_module._open_windows_receipt_child_lock(
        Path("C:/Guard Home"),
        reason_code="receipt-failed",
    )
    locks = artifact_module._WindowsReceiptDirectoryLocks(
        directory_handle=72,
        child_handle=child_handle,
    )
    locks.close()

    assert len(create_arguments) == 1
    assert create_arguments[0][0] == str(Path("C:/Guard Home") / (".local-wheel-source.json.lock.4102." + "ab" * 16))
    assert create_arguments[0][1] == (
        artifact_module._WINDOWS_GENERIC_READ | artifact_module._WINDOWS_GENERIC_WRITE | artifact_module._WINDOWS_DELETE
    )
    assert create_arguments[0][2] == (
        artifact_module._WINDOWS_FILE_SHARE_READ | artifact_module._WINDOWS_FILE_SHARE_WRITE
    )
    assert create_arguments[0][4] == artifact_module._WINDOWS_CREATE_NEW
    assert create_arguments[0][5] == (
        artifact_module._WINDOWS_FILE_ATTRIBUTE_NORMAL
        | artifact_module._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
        | artifact_module._WINDOWS_FILE_FLAG_DELETE_ON_CLOSE
    )
    assert closed_handles == [71, 72]


@pytest.mark.skipif(os.name != "nt", reason="Windows directory sharing contract")
def test_local_wheel_receipt_windows_lock_blocks_guard_home_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    moved_guard_home = tmp_path / "guard-home-moved"
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    real_replace = artifact_module.os.replace
    rename_was_blocked = False

    def verify_lock_and_replace(source_path: Path, destination_path: Path) -> None:
        nonlocal rename_was_blocked
        with pytest.raises(OSError):
            guard_home.rename(moved_guard_home)
        rename_was_blocked = True
        real_replace(source_path, destination_path)

    monkeypatch.setattr(artifact_module.os, "replace", verify_lock_and_replace)

    record_local_wheel_receipt(artifact, guard_home=guard_home, installed_version=artifact.version)

    assert rename_was_blocked is True
    artifact.cleanup()


def test_revalidate_hashes_from_descriptor_without_path_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))

    def forbidden_path_open(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("security revalidation must not use Path.open")

    monkeypatch.setattr(Path, "open", forbidden_path_open)

    artifact.revalidate()
    artifact.cleanup()


def test_concurrent_staging_preserves_valid_wheel_names_and_isolated_cleanup(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    neutral = _neutral_cwd(tmp_path)

    first = stage_trusted_wheel(source.resolve(), neutral_cwd=neutral)
    second = stage_trusted_wheel(source.resolve(), neutral_cwd=neutral)

    assert first.staged_path != second.staged_path
    assert first.staged_path.name == source.name
    assert second.staged_path.name == source.name
    first.cleanup()
    assert not first.staged_path.exists()
    second.revalidate()
    second.cleanup()
    assert list((neutral / "wheels").iterdir()) == []


def test_stage_rejects_non_zip_wheel_bytes_and_removes_staged_copy(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    source.parent.mkdir()
    source.write_bytes(b"this is not a zip archive")
    neutral = _neutral_cwd(tmp_path)

    _assert_reason(
        "update_artifact_invalid",
        lambda: stage_trusted_wheel(source.resolve(), neutral_cwd=neutral),
    )

    staging_root = neutral / "wheels"
    assert staging_root.is_dir()
    assert list(staging_root.iterdir()) == []


@pytest.mark.parametrize(
    ("filename_distribution", "metadata_name", "metadata_version"),
    [
        ("another_project", "hol-guard", "1.2.3"),
        ("hol_guard", "another-project", "1.2.3"),
        ("hol_guard", "hol-guard", "not-a-version"),
    ],
)
def test_stage_rejects_wrong_distribution_or_version(
    tmp_path: Path,
    filename_distribution: str,
    metadata_name: str,
    metadata_version: str,
) -> None:
    source = _wheel_path(tmp_path / "dist", distribution=filename_distribution)
    _write_wheel(
        source,
        [("package.dist-info/METADATA", _metadata(name=metadata_name, version=metadata_version))],
    )

    _assert_reason(
        "update_artifact_invalid",
        lambda: stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path)),
    )


def test_stage_rejects_metadata_filename_version_mismatch(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist", version="1.2.3")
    _write_wheel(source, [("hol_guard-1.2.4.dist-info/METADATA", _metadata(version="1.2.4"))])

    _assert_reason(
        "update_artifact_invalid",
        lambda: stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path)),
    )


@pytest.mark.parametrize("metadata_entries", [[], [("package.dist-info/WHEEL", b"Wheel-Version: 1.0\n")]])
def test_stage_rejects_missing_metadata(tmp_path: Path, metadata_entries: list[tuple[str, bytes]]) -> None:
    source = _wheel_path(tmp_path / "dist")
    # Passing an explicit empty list must not select _write_wheel's default metadata.
    source.parent.mkdir(parents=True)
    with zipfile.ZipFile(source, "w") as archive:
        for name, content in metadata_entries:
            archive.writestr(name, content)

    _assert_reason(
        "update_artifact_invalid",
        lambda: stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path)),
    )


def test_stage_rejects_multiple_metadata_records(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(
        source,
        [
            ("first.dist-info/METADATA", _metadata()),
            ("second.dist-info/METADATA", _metadata()),
        ],
    )

    _assert_reason(
        "update_artifact_invalid",
        lambda: stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path)),
    )


def test_stage_rejects_oversize_metadata(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    oversize = _metadata(suffix=b"x" * artifact_module._MAX_METADATA_BYTES)
    _write_wheel(source, [("hol_guard-1.2.3.dist-info/METADATA", oversize)])

    _assert_reason(
        "update_artifact_invalid",
        lambda: stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path)),
    )


def test_stage_rejects_source_symlink(tmp_path: Path) -> None:
    target = _wheel_path(tmp_path / "dist")
    _write_wheel(target)
    source_link = tmp_path / target.name
    _symlink_or_skip(source_link, target)

    _assert_reason(
        "update_artifact_invalid",
        lambda: stage_trusted_wheel(source_link.absolute(), neutral_cwd=_neutral_cwd(tmp_path)),
    )


@pytest.mark.skipif(not hasattr(os, "mkfifo") or os.name == "nt", reason="FIFO files require POSIX")
def test_stage_rejects_special_source_file(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path)
    os.mkfifo(source)

    _assert_reason(
        "update_artifact_invalid",
        lambda: stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path)),
    )


def test_revalidate_rejects_staged_byte_mutation(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    staged_bytes = bytearray(artifact.staged_path.read_bytes())
    staged_bytes[-1] ^= 1
    artifact.staged_path.write_bytes(staged_bytes)

    _assert_reason("update_artifact_identity_changed", artifact.revalidate)


def test_revalidate_rejects_staged_symlink_swap(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    moved = artifact.staged_path.with_suffix(".moved")
    artifact.staged_path.rename(moved)
    _symlink_or_skip(artifact.staged_path, moved)

    _assert_reason("update_artifact_identity_changed", artifact.revalidate)
    artifact.cleanup()
    assert not artifact.staged_path.is_symlink()
    assert not artifact.staged_path.exists()
    assert moved.is_file()


def test_revalidate_then_artifact_root_symlink_swap_fails_and_cleanup_does_not_follow(
    tmp_path: Path,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    source_bytes = _write_wheel(source)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    artifact.revalidate()
    moved_root = artifact.staging_root.with_name(f"{artifact.staging_root.name}-moved")
    artifact.staging_root.rename(moved_root)
    moved_wheel = moved_root / artifact.staged_path.name
    _symlink_or_skip(artifact.staging_root, moved_root)

    assert artifact.staged_path.read_bytes() == source_bytes
    _assert_reason("update_artifact_identity_changed", artifact.revalidate)

    artifact.cleanup()
    assert artifact.staging_root.is_symlink()
    assert moved_wheel.read_bytes() == source_bytes


def test_revalidate_rejects_same_byte_staged_rename_replacement(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    staged_bytes = artifact.staged_path.read_bytes()
    moved = artifact.staged_path.with_suffix(".moved")
    artifact.staged_path.rename(moved)
    artifact.staged_path.write_bytes(staged_bytes)

    _assert_reason("update_artifact_identity_changed", artifact.revalidate)
    artifact.cleanup()
    assert not artifact.staged_path.exists()
    assert moved.is_file()


@pytest.mark.skipif(not hasattr(os, "mkfifo") or os.name == "nt", reason="FIFO files require POSIX")
def test_revalidate_rejects_staged_fifo_swap_without_blocking(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))
    moved = artifact.staged_path.with_suffix(".moved")
    artifact.staged_path.rename(moved)
    os.mkfifo(artifact.staged_path)

    _assert_reason("update_artifact_identity_changed", artifact.revalidate)
    artifact.cleanup()
    assert not artifact.staged_path.exists()
    assert moved.is_file()


@pytest.mark.parametrize("failing_operation", ["fstat", "lstat"])
def test_revalidate_translates_staged_metadata_errors_to_stable_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failing_operation: str,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    artifact = stage_trusted_wheel(source.resolve(), neutral_cwd=_neutral_cwd(tmp_path))

    def metadata_failure(*_args: object, **_kwargs: object) -> None:
        raise OSError("hostile filesystem metadata failure")

    monkeypatch.setattr(artifact_module.os, failing_operation, metadata_failure)

    _assert_reason("update_artifact_identity_changed", artifact.revalidate)


@pytest.mark.skipif(
    not hasattr(os, "mkfifo") or os.name == "nt",
    reason="atomic symlink and FIFO swaps require POSIX",
)
@pytest.mark.parametrize("replacement_kind", ["missing", "regular", "symlink", "fifo"])
def test_stage_rejects_source_directory_entry_swap_after_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    source_bytes = _write_wheel(source)
    neutral = _neutral_cwd(tmp_path)
    moved = source.with_suffix(".moved")
    real_write_all = artifact_module._write_all
    swapped = False

    def swap_after_copy(file_descriptor: int, data: bytes) -> None:
        nonlocal swapped
        real_write_all(file_descriptor, data)
        if swapped:
            return
        swapped = True
        source.rename(moved)
        if replacement_kind == "regular":
            source.write_bytes(source_bytes)
        elif replacement_kind == "symlink":
            source.symlink_to(moved)
        elif replacement_kind == "fifo":
            os.mkfifo(source)

    monkeypatch.setattr(artifact_module, "_write_all", swap_after_copy)

    _assert_reason(
        "update_artifact_identity_changed",
        lambda: stage_trusted_wheel(source.absolute(), neutral_cwd=neutral),
    )
    assert swapped is True
    assert moved.is_file()
    assert list((neutral / "wheels").iterdir()) == []


def test_stage_rejects_source_identity_change_during_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    neutral = _neutral_cwd(tmp_path)
    real_fstat = artifact_module.os.fstat
    calls = 0

    def changing_fstat(file_descriptor: int) -> os.stat_result | types.SimpleNamespace:
        nonlocal calls
        metadata = real_fstat(file_descriptor)
        calls += 1
        if calls != 2:
            return metadata
        return types.SimpleNamespace(
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns + 1,
            st_ctime_ns=metadata.st_ctime_ns,
            st_mode=metadata.st_mode,
        )

    monkeypatch.setattr(artifact_module.os, "fstat", changing_fstat)

    _assert_reason(
        "update_artifact_identity_changed",
        lambda: stage_trusted_wheel(source.resolve(), neutral_cwd=neutral),
    )
    assert calls == 2
    assert list((neutral / "wheels").iterdir()) == []


@pytest.mark.parametrize(
    "failing_operation",
    [
        "fstat",
        pytest.param(
            "lstat",
            marks=pytest.mark.skipif(
                os.name == "nt",
                reason="Windows source descriptors are bound atomically without path lstat metadata",
            ),
        ),
    ],
)
def test_stage_translates_source_metadata_errors_to_stable_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failing_operation: str,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)

    def metadata_failure(*_args: object, **_kwargs: object) -> None:
        raise OSError("hostile filesystem metadata failure")

    monkeypatch.setattr(artifact_module.os, failing_operation, metadata_failure)

    _assert_reason(
        "update_artifact_invalid",
        lambda: stage_trusted_wheel(source.absolute(), neutral_cwd=_neutral_cwd(tmp_path)),
    )


def test_stage_translates_neutral_directory_resolve_error_to_stable_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    neutral = _neutral_cwd(tmp_path)

    def resolve_failure(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("filesystem resolution loop")

    monkeypatch.setattr(Path, "resolve", resolve_failure)

    _assert_reason(
        "update_artifact_staging_unavailable",
        lambda: stage_trusted_wheel(source.absolute(), neutral_cwd=neutral),
    )


def test_stage_rejects_symlinked_private_staging_directory(tmp_path: Path) -> None:
    source = _wheel_path(tmp_path / "dist")
    _write_wheel(source)
    neutral = _neutral_cwd(tmp_path)
    external = tmp_path / "external-wheels"
    external.mkdir()
    _symlink_or_skip(neutral / "wheels", external)

    _assert_reason(
        "update_artifact_staging_unavailable",
        lambda: stage_trusted_wheel(source.resolve(), neutral_cwd=neutral),
    )
    assert list(external.iterdir()) == []
