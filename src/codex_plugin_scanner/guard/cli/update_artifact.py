"""Immutable staging and identity checks for local HOL Guard wheels."""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import importlib
import json
import os
import stat
import zipfile
from contextlib import suppress
from ctypes import wintypes
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from .update_subprocess import FilesystemIdentity, UpdateSubprocessError

_MAX_WHEEL_BYTES = 512 * 1024 * 1024
_MAX_METADATA_BYTES = 256 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024
_LOCAL_WHEEL_RECEIPT_NAME = "local-wheel-source.json"
_LOCAL_WHEEL_RECEIPT_MAX_BYTES = 16 * 1024
_LOCAL_WHEEL_RECEIPT_SCHEMA_VERSION = 1
_POSIX_RECEIPT_DIR_FD_SUPPORTED = (
    os.name != "nt"
    and hasattr(os, "O_DIRECTORY")
    and os.open in os.supports_dir_fd
    and os.rename in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
)
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_OPEN_EXISTING = 3


class UpdateArtifactError(RuntimeError):
    """A local update artifact failed closed before installer execution."""

    reason_code: str

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class TrustedWheelArtifact:
    original_path: Path
    staged_path: Path
    staging_root: Path
    staging_identity: tuple[int, int, int, int, int, int]
    staging_filesystem_identity: FilesystemIdentity
    version: str
    sha256: str
    size: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int
    mode: int

    def revalidate(self) -> None:
        """Prove the private staging root and staged file are unchanged."""

        try:
            self.staging_filesystem_identity.revalidate(changed_reason="update_artifact_identity_changed")
        except UpdateSubprocessError as error:
            raise UpdateArtifactError("update_artifact_identity_changed") from error
        expected_identity = (
            self.device,
            self.inode,
            self.size,
            self.mtime_ns,
            self.ctime_ns,
            self.mode,
        )
        if self.staged_path.parent != self.staging_root or not self.staged_path.name:
            raise UpdateArtifactError("update_artifact_identity_changed")
        root_descriptor, root_metadata = _open_directory_descriptor(
            self.staging_root,
            reason_code="update_artifact_identity_changed",
        )
        try:
            if _stat_identity(root_metadata) != self.staging_identity:
                raise UpdateArtifactError("update_artifact_identity_changed")
            file_descriptor, opened_metadata = _open_regular_descriptor(
                self.staged_path.name if root_descriptor is not None else self.staged_path,
                reason_code="update_artifact_identity_changed",
                directory_descriptor=root_descriptor,
            )
            try:
                if _stat_identity(opened_metadata) != expected_identity:
                    raise UpdateArtifactError("update_artifact_identity_changed")
                digest, size = _hash_descriptor(
                    file_descriptor,
                    reason_code="update_artifact_identity_changed",
                )
                final_metadata = _descriptor_metadata(
                    file_descriptor,
                    reason_code="update_artifact_identity_changed",
                )
                if _stat_identity(final_metadata) != expected_identity or size != self.size or digest != self.sha256:
                    raise UpdateArtifactError("update_artifact_identity_changed")
                _verify_directory_entry_identity(
                    self.staged_path.name if root_descriptor is not None else self.staged_path,
                    expected_identity=expected_identity,
                    reason_code="update_artifact_identity_changed",
                    directory_descriptor=root_descriptor,
                )
                _verify_directory_identity(
                    self.staging_root,
                    expected_identity=self.staging_identity,
                    reason_code="update_artifact_identity_changed",
                )
                try:
                    self.staging_filesystem_identity.revalidate(changed_reason="update_artifact_identity_changed")
                except UpdateSubprocessError as error:
                    raise UpdateArtifactError("update_artifact_identity_changed") from error
            finally:
                with suppress(OSError):
                    os.close(file_descriptor)
        finally:
            if root_descriptor is not None:
                with suppress(OSError):
                    os.close(root_descriptor)

    def cleanup(self) -> None:
        """Remove entries only through the bound private staging root."""

        try:
            self.staging_filesystem_identity.revalidate(changed_reason="update_artifact_identity_changed")
            if self.staged_path.parent != self.staging_root or not self.staged_path.name:
                return
            root_descriptor, root_metadata = _open_directory_descriptor(
                self.staging_root,
                reason_code="update_artifact_identity_changed",
            )
            if not _same_directory_object(root_metadata, self.staging_identity):
                if root_descriptor is not None:
                    with suppress(OSError):
                        os.close(root_descriptor)
                return
            try:
                _unlink_staged_entry(
                    self.staged_path,
                    directory_descriptor=root_descriptor,
                )
            finally:
                if root_descriptor is not None:
                    with suppress(OSError):
                        os.close(root_descriptor)
            current_root = self.staging_root.lstat()
            if (
                stat.S_ISLNK(current_root.st_mode)
                or _metadata_is_reparse(current_root)
                or current_root.st_dev != self.staging_identity[0]
                or current_root.st_ino != self.staging_identity[1]
            ):
                return
            self.staging_root.rmdir()
        except (OSError, RuntimeError, ValueError, UpdateArtifactError, UpdateSubprocessError):
            return


def record_local_wheel_receipt(
    artifact: TrustedWheelArtifact,
    *,
    guard_home: Path,
    installed_version: str,
) -> Path:
    """Persist the original source behind an ephemeral PEP 610 staging URL."""

    directory_descriptor: int | None = None
    windows_directory_handle: object | None = None
    temporary_name: str | None = None
    resolved_guard_home: Path | None = None
    try:
        normalized_version = str(Version(installed_version))
        resolved_guard_home = guard_home.resolve(strict=True)
        guard_home_identity = FilesystemIdentity.capture(
            resolved_guard_home,
            kind="directory",
            failure_reason="update_artifact_receipt_failed",
        )
        directory_descriptor, windows_directory_handle, directory_metadata = _open_receipt_directory(
            resolved_guard_home,
            reason_code="update_artifact_receipt_failed",
        )
        guard_home_identity.revalidate(changed_reason="update_artifact_receipt_failed")
        payload = {
            "schema_version": _LOCAL_WHEEL_RECEIPT_SCHEMA_VERSION,
            "installed_version": normalized_version,
            "original_path": str(artifact.original_path.resolve(strict=True)),
            "staged_path": str(artifact.staged_path),
            "wheel_sha256": artifact.sha256,
            "wheel_size": artifact.size,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > _LOCAL_WHEEL_RECEIPT_MAX_BYTES:
            raise UpdateArtifactError("update_artifact_receipt_failed")
        receipt_path = resolved_guard_home / _LOCAL_WHEEL_RECEIPT_NAME
        temporary_name = f".{_LOCAL_WHEEL_RECEIPT_NAME}.{os.getpid()}.{os.urandom(8).hex()}"
        descriptor = _open_receipt_temporary(
            resolved_guard_home,
            temporary_name,
            directory_descriptor=directory_descriptor,
            reason_code="update_artifact_receipt_failed",
        )
        try:
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _revalidate_receipt_directory(
            resolved_guard_home,
            directory_descriptor=directory_descriptor,
            initial_metadata=directory_metadata,
            identity=guard_home_identity,
            reason_code="update_artifact_receipt_failed",
        )
        _replace_receipt_entry(
            resolved_guard_home,
            temporary_name,
            directory_descriptor=directory_descriptor,
            reason_code="update_artifact_receipt_failed",
        )
        temporary_name = None
        if directory_descriptor is not None:
            os.fsync(directory_descriptor)
        guard_home_identity.revalidate(changed_reason="update_artifact_receipt_failed")
        receipt_descriptor, receipt_metadata = _open_receipt_file(
            resolved_guard_home,
            directory_descriptor=directory_descriptor,
            reason_code="update_artifact_receipt_failed",
        )
        try:
            if receipt_metadata.st_size != len(encoded):
                raise UpdateArtifactError("update_artifact_receipt_failed")
            persisted = _read_bounded_descriptor(
                receipt_descriptor,
                maximum_bytes=_LOCAL_WHEEL_RECEIPT_MAX_BYTES,
                reason_code="update_artifact_receipt_failed",
            )
            final_receipt_metadata = _descriptor_metadata(
                receipt_descriptor,
                reason_code="update_artifact_receipt_failed",
            )
            if persisted != encoded or _stat_identity(final_receipt_metadata) != _stat_identity(receipt_metadata):
                raise UpdateArtifactError("update_artifact_receipt_failed")
            _verify_receipt_entry_identity(
                resolved_guard_home,
                expected_identity=_stat_identity(receipt_metadata),
                directory_descriptor=directory_descriptor,
                reason_code="update_artifact_receipt_failed",
            )
        finally:
            with suppress(OSError):
                os.close(receipt_descriptor)
        _revalidate_receipt_directory(
            resolved_guard_home,
            directory_descriptor=directory_descriptor,
            initial_metadata=directory_metadata,
            identity=guard_home_identity,
            reason_code="update_artifact_receipt_failed",
        )
        return receipt_path
    except UpdateArtifactError as error:
        if error.reason_code == "update_artifact_receipt_failed":
            raise
        raise UpdateArtifactError("update_artifact_receipt_failed") from error
    except (InvalidVersion, OSError, RuntimeError, TypeError, ValueError, UpdateSubprocessError) as error:
        raise UpdateArtifactError("update_artifact_receipt_failed") from error
    finally:
        if temporary_name is not None and resolved_guard_home is not None:
            _unlink_receipt_entry(
                resolved_guard_home,
                temporary_name,
                directory_descriptor=directory_descriptor,
            )
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
        if windows_directory_handle is not None:
            _close_windows_handle(windows_directory_handle)


def recover_local_wheel_original(
    *,
    guard_home: Path,
    staged_path: Path,
    installed_version: str,
    wheel_sha256: str,
) -> Path | None:
    """Resolve an original wheel only when receipt, PEP 610, and bytes agree."""

    normalized_sha256 = wheel_sha256.lower()
    if len(normalized_sha256) != 64 or any(character not in "0123456789abcdef" for character in normalized_sha256):
        return None
    directory_descriptor: int | None = None
    windows_directory_handle: object | None = None
    try:
        resolved_guard_home = guard_home.resolve(strict=True)
        guard_home_identity = FilesystemIdentity.capture(
            resolved_guard_home,
            kind="directory",
            failure_reason="update_artifact_receipt_invalid",
        )
        directory_descriptor, windows_directory_handle, directory_metadata = _open_receipt_directory(
            resolved_guard_home,
            reason_code="update_artifact_receipt_invalid",
        )
        guard_home_identity.revalidate(changed_reason="update_artifact_receipt_invalid")
        receipt_descriptor, receipt_metadata = _open_receipt_file(
            resolved_guard_home,
            directory_descriptor=directory_descriptor,
            reason_code="update_artifact_receipt_invalid",
        )
        try:
            if receipt_metadata.st_size <= 0 or receipt_metadata.st_size > _LOCAL_WHEEL_RECEIPT_MAX_BYTES:
                return None
            raw_receipt = _read_bounded_descriptor(
                receipt_descriptor,
                maximum_bytes=_LOCAL_WHEEL_RECEIPT_MAX_BYTES,
                reason_code="update_artifact_receipt_invalid",
            )
            final_receipt_metadata = _descriptor_metadata(
                receipt_descriptor,
                reason_code="update_artifact_receipt_invalid",
            )
            if len(raw_receipt) != receipt_metadata.st_size or _stat_identity(final_receipt_metadata) != _stat_identity(
                receipt_metadata
            ):
                return None
            _verify_receipt_entry_identity(
                resolved_guard_home,
                expected_identity=_stat_identity(receipt_metadata),
                directory_descriptor=directory_descriptor,
                reason_code="update_artifact_receipt_invalid",
            )
        finally:
            with suppress(OSError):
                os.close(receipt_descriptor)
        _revalidate_receipt_directory(
            resolved_guard_home,
            directory_descriptor=directory_descriptor,
            initial_metadata=directory_metadata,
            identity=guard_home_identity,
            reason_code="update_artifact_receipt_invalid",
        )
        receipt = json.loads(raw_receipt)
        if not isinstance(receipt, dict) or receipt.get("schema_version") != _LOCAL_WHEEL_RECEIPT_SCHEMA_VERSION:
            return None
        receipt_sha256 = receipt.get("wheel_sha256")
        receipt_size = receipt.get("wheel_size")
        receipt_version = receipt.get("installed_version")
        receipt_staged_path = receipt.get("staged_path")
        original_path_value = receipt.get("original_path")
        if (
            not isinstance(receipt_sha256, str)
            or not hmac.compare_digest(receipt_sha256.lower(), normalized_sha256)
            or type(receipt_size) is not int
            or receipt_size <= 0
            or receipt_size > _MAX_WHEEL_BYTES
            or not isinstance(receipt_version, str)
            or Version(receipt_version) != Version(installed_version)
            or not isinstance(receipt_staged_path, str)
            or Path(receipt_staged_path) != staged_path
            or not isinstance(original_path_value, str)
        ):
            return None
        original_path = Path(original_path_value)
        if not original_path.is_absolute() or original_path.suffix.lower() != ".whl":
            return None
        original_identity = FilesystemIdentity.capture(
            original_path,
            kind="file",
            failure_reason="update_artifact_receipt_invalid",
        )
        if (
            original_identity.size != receipt_size
            or original_identity.sha256 is None
            or not hmac.compare_digest(original_identity.sha256, normalized_sha256)
        ):
            return None
        original_identity.revalidate(changed_reason="update_artifact_receipt_invalid")
        return original_identity.canonical_path
    except (
        InvalidVersion,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        UpdateArtifactError,
        UpdateSubprocessError,
    ):
        return None
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
        if windows_directory_handle is not None:
            _close_windows_handle(windows_directory_handle)


def stage_trusted_wheel(source: Path, *, neutral_cwd: Path) -> TrustedWheelArtifact:
    """Copy and attest a wheel before exposing its path to a package manager."""

    try:
        original = source.expanduser()
    except (OSError, RuntimeError, ValueError) as error:
        raise UpdateArtifactError("update_artifact_invalid") from error
    if not original.is_absolute():
        raise UpdateArtifactError("update_artifact_invalid")
    filename_version = _wheel_filename_version(original.name)
    source_fd, source_metadata = _open_regular_descriptor(
        original,
        reason_code="update_artifact_invalid",
    )
    if source_metadata.st_size <= 0 or source_metadata.st_size > _MAX_WHEEL_BYTES:
        with suppress(OSError):
            os.close(source_fd)
        raise UpdateArtifactError("update_artifact_invalid")
    try:
        wheel_root = _private_staging_root(neutral_cwd)
        staging_root = _private_artifact_root(wheel_root)
    except BaseException:
        with suppress(OSError):
            os.close(source_fd)
        raise
    temporary = staging_root / ".stage.whl"
    staged = staging_root / original.name

    digest = hashlib.sha256()
    copied = 0
    try:
        destination_fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            while True:
                chunk = os.read(source_fd, _COPY_CHUNK_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > _MAX_WHEEL_BYTES:
                    raise UpdateArtifactError("update_artifact_invalid")
                digest.update(chunk)
                _write_all(destination_fd, chunk)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        final_source_metadata = _descriptor_metadata(
            source_fd,
            reason_code="update_artifact_identity_changed",
        )
        if _stat_identity(final_source_metadata) != _stat_identity(source_metadata):
            raise UpdateArtifactError("update_artifact_identity_changed")
        _verify_directory_entry_identity(
            original,
            expected_identity=_stat_identity(source_metadata),
            reason_code="update_artifact_identity_changed",
        )
    except UpdateArtifactError:
        _cleanup_failed_staging(staging_root, temporary, staged)
        raise
    except (OSError, RuntimeError, ValueError) as error:
        _cleanup_failed_staging(staging_root, temporary, staged)
        raise UpdateArtifactError("update_artifact_invalid") from error
    finally:
        with suppress(OSError):
            os.close(source_fd)
    if copied != source_metadata.st_size:
        _cleanup_failed_staging(staging_root, temporary, staged)
        raise UpdateArtifactError("update_artifact_identity_changed")

    sha256 = digest.hexdigest()
    try:
        os.replace(temporary, staged)
        staged_fd, staged_metadata = _open_regular_descriptor(
            staged,
            reason_code="update_artifact_identity_changed",
        )
        try:
            staged_identity = _stat_identity(staged_metadata)
            staged_digest, staged_size = _hash_descriptor(
                staged_fd,
                reason_code="update_artifact_identity_changed",
            )
            if staged_size != copied or staged_digest != sha256:
                raise UpdateArtifactError("update_artifact_identity_changed")
            metadata_version = _wheel_metadata_version(staged_fd)
            final_staged_metadata = _descriptor_metadata(
                staged_fd,
                reason_code="update_artifact_identity_changed",
            )
            if _stat_identity(final_staged_metadata) != staged_identity:
                raise UpdateArtifactError("update_artifact_identity_changed")
            _verify_directory_entry_identity(
                staged,
                expected_identity=staged_identity,
                reason_code="update_artifact_identity_changed",
            )
        finally:
            with suppress(OSError):
                os.close(staged_fd)
    except UpdateArtifactError:
        _cleanup_failed_staging(staging_root, temporary, staged)
        raise
    except (OSError, RuntimeError, ValueError) as error:
        _cleanup_failed_staging(staging_root, temporary, staged)
        raise UpdateArtifactError("update_artifact_invalid") from error
    if metadata_version != filename_version:
        _cleanup_failed_staging(staging_root, staged)
        raise UpdateArtifactError("update_artifact_invalid")
    try:
        root_descriptor, root_metadata = _open_directory_descriptor(
            staging_root,
            reason_code="update_artifact_identity_changed",
        )
    except UpdateArtifactError:
        _cleanup_failed_staging(staging_root, staged)
        raise
    if root_descriptor is not None:
        with suppress(OSError):
            os.close(root_descriptor)
    try:
        staging_filesystem_identity = FilesystemIdentity.capture(
            staging_root,
            kind="directory",
            failure_reason="update_artifact_identity_changed",
        )
    except UpdateSubprocessError as error:
        _cleanup_failed_staging(staging_root, staged)
        raise UpdateArtifactError("update_artifact_identity_changed") from error
    artifact = TrustedWheelArtifact(
        original_path=original,
        staged_path=staged,
        staging_root=staging_root,
        staging_identity=_stat_identity(root_metadata),
        staging_filesystem_identity=staging_filesystem_identity,
        version=str(filename_version),
        sha256=sha256,
        size=copied,
        device=staged_metadata.st_dev,
        inode=staged_metadata.st_ino,
        mtime_ns=staged_metadata.st_mtime_ns,
        ctime_ns=staged_metadata.st_ctime_ns,
        mode=staged_metadata.st_mode,
    )
    artifact.revalidate()
    return artifact


def _private_staging_root(neutral_cwd: Path) -> Path:
    try:
        root = neutral_cwd.resolve(strict=True) / "wheels"
        if root.exists() and (root.is_symlink() or _metadata_is_reparse(root.lstat())):
            raise UpdateArtifactError("update_artifact_staging_unavailable")
        root.mkdir(mode=0o700, parents=False, exist_ok=True)
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _metadata_is_reparse(metadata):
            raise UpdateArtifactError("update_artifact_staging_unavailable")
        if os.name != "nt":
            root.chmod(0o700)
        return root.resolve(strict=True)
    except UpdateArtifactError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise UpdateArtifactError("update_artifact_staging_unavailable") from error


def _private_artifact_root(wheel_root: Path) -> Path:
    for _attempt in range(8):
        root = wheel_root / f"artifact-{os.getpid()}-{os.urandom(8).hex()}"
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            continue
        except (OSError, RuntimeError, ValueError) as error:
            raise UpdateArtifactError("update_artifact_staging_unavailable") from error
        try:
            metadata = root.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _metadata_is_reparse(metadata):
                raise UpdateArtifactError("update_artifact_staging_unavailable")
            if os.name != "nt":
                root.chmod(0o700)
                if root.stat().st_mode & 0o077:
                    raise UpdateArtifactError("update_artifact_staging_unavailable")
            return root.resolve(strict=True)
        except UpdateArtifactError:
            with suppress(OSError):
                root.rmdir()
            raise
        except (OSError, RuntimeError, ValueError) as error:
            with suppress(OSError):
                root.rmdir()
            raise UpdateArtifactError("update_artifact_staging_unavailable") from error
    raise UpdateArtifactError("update_artifact_staging_unavailable")


def _cleanup_failed_staging(staging_root: Path, *paths: Path) -> None:
    for path in paths:
        try:
            if path.parent == staging_root:
                path.unlink(missing_ok=True)
        except (OSError, RuntimeError, ValueError):
            pass
    with suppress(OSError):
        staging_root.rmdir()


def _wheel_filename_version(filename: str) -> Version:
    try:
        distribution, version, _build, _tags = parse_wheel_filename(filename)
    except InvalidWheelFilename as error:
        raise UpdateArtifactError("update_artifact_invalid") from error
    if canonicalize_name(distribution) != "hol-guard":
        raise UpdateArtifactError("update_artifact_invalid")
    return version


def _wheel_metadata_version(file_descriptor: int) -> Version:
    duplicate_descriptor: int | None = None
    try:
        duplicate_descriptor = os.dup(file_descriptor)
        with os.fdopen(duplicate_descriptor, "rb") as wheel_file:
            duplicate_descriptor = None
            with zipfile.ZipFile(wheel_file) as archive:
                metadata_entries = [info for info in archive.infolist() if _is_metadata_entry(info.filename)]
                if len(metadata_entries) != 1:
                    raise UpdateArtifactError("update_artifact_invalid")
                metadata_info = metadata_entries[0]
                if metadata_info.file_size <= 0 or metadata_info.file_size > _MAX_METADATA_BYTES:
                    raise UpdateArtifactError("update_artifact_invalid")
                metadata_bytes = archive.read(metadata_info)
    except UpdateArtifactError:
        raise
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, KeyError) as error:
        raise UpdateArtifactError("update_artifact_invalid") from error
    finally:
        if duplicate_descriptor is not None:
            with suppress(OSError):
                os.close(duplicate_descriptor)
    metadata = BytesParser().parsebytes(metadata_bytes, headersonly=True)
    names = metadata.get_all("Name", [])
    versions = metadata.get_all("Version", [])
    if len(names) != 1 or canonicalize_name(str(names[0])) != "hol-guard" or len(versions) != 1:
        raise UpdateArtifactError("update_artifact_invalid")
    try:
        return Version(str(versions[0]))
    except InvalidVersion as error:
        raise UpdateArtifactError("update_artifact_invalid") from error


def _open_receipt_directory(
    path: Path,
    *,
    reason_code: str,
) -> tuple[int | None, object | None, os.stat_result]:
    """Pin the receipt directory against replacement for one transaction."""

    if os.name == "nt":
        directory_handle = _open_windows_directory_lock(path, reason_code=reason_code)
        try:
            metadata = os.lstat(path)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _metadata_is_reparse(metadata):
                raise UpdateArtifactError(reason_code)
            return None, directory_handle, metadata
        except UpdateArtifactError:
            _close_windows_handle(directory_handle)
            raise
        except (OSError, RuntimeError, ValueError) as error:
            _close_windows_handle(directory_handle)
            raise UpdateArtifactError(reason_code) from error
    if not _POSIX_RECEIPT_DIR_FD_SUPPORTED:
        raise UpdateArtifactError(reason_code)
    directory_descriptor, metadata = _open_directory_descriptor(path, reason_code=reason_code)
    if directory_descriptor is None:
        raise UpdateArtifactError(reason_code)
    return directory_descriptor, None, metadata


def _open_receipt_temporary(
    directory: Path,
    name: str,
    *,
    directory_descriptor: int | None,
    reason_code: str,
) -> int:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOINHERIT", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        if directory_descriptor is None:
            return os.open(directory / name, flags, 0o600)
        return os.open(name, flags, 0o600, dir_fd=directory_descriptor)
    except (OSError, RuntimeError, ValueError) as error:
        raise UpdateArtifactError(reason_code) from error


def _open_receipt_file(
    directory: Path,
    *,
    directory_descriptor: int | None,
    reason_code: str,
) -> tuple[int, os.stat_result]:
    if os.name == "nt":
        return _open_windows_receipt_file(
            directory / _LOCAL_WHEEL_RECEIPT_NAME,
            reason_code=reason_code,
        )
    return _open_regular_descriptor(
        _LOCAL_WHEEL_RECEIPT_NAME if directory_descriptor is not None else directory / _LOCAL_WHEEL_RECEIPT_NAME,
        reason_code=reason_code,
        directory_descriptor=directory_descriptor,
    )


def _replace_receipt_entry(
    directory: Path,
    temporary_name: str,
    *,
    directory_descriptor: int | None,
    reason_code: str,
) -> None:
    try:
        if directory_descriptor is None:
            os.replace(directory / temporary_name, directory / _LOCAL_WHEEL_RECEIPT_NAME)
        else:
            os.rename(
                temporary_name,
                _LOCAL_WHEEL_RECEIPT_NAME,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
    except (OSError, RuntimeError, ValueError) as error:
        raise UpdateArtifactError(reason_code) from error


def _unlink_receipt_entry(
    directory: Path,
    name: str,
    *,
    directory_descriptor: int | None,
) -> None:
    try:
        if directory_descriptor is None:
            os.unlink(directory / name)
        else:
            os.unlink(name, dir_fd=directory_descriptor)
    except FileNotFoundError:
        return
    except (OSError, RuntimeError, ValueError):
        return


def _verify_receipt_entry_identity(
    directory: Path,
    *,
    expected_identity: tuple[int, int, int, int, int, int],
    directory_descriptor: int | None,
    reason_code: str,
) -> None:
    _verify_directory_entry_identity(
        _LOCAL_WHEEL_RECEIPT_NAME if directory_descriptor is not None else directory / _LOCAL_WHEEL_RECEIPT_NAME,
        expected_identity=expected_identity,
        reason_code=reason_code,
        directory_descriptor=directory_descriptor,
    )


def _revalidate_receipt_directory(
    path: Path,
    *,
    directory_descriptor: int | None,
    initial_metadata: os.stat_result,
    identity: FilesystemIdentity,
    reason_code: str,
) -> None:
    try:
        if directory_descriptor is not None:
            current_metadata = os.fstat(directory_descriptor)
            if not _same_directory_object(current_metadata, _stat_identity(initial_metadata)):
                raise UpdateArtifactError(reason_code)
        identity.revalidate(changed_reason=reason_code)
        entry_metadata = os.lstat(path)
        if not _same_directory_object(entry_metadata, _stat_identity(initial_metadata)):
            raise UpdateArtifactError(reason_code)
    except UpdateArtifactError:
        raise
    except (OSError, RuntimeError, ValueError, UpdateSubprocessError) as error:
        raise UpdateArtifactError(reason_code) from error


def _read_bounded_descriptor(
    file_descriptor: int,
    *,
    maximum_bytes: int,
    reason_code: str,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        while True:
            remaining = maximum_bytes - total
            chunk = os.read(file_descriptor, min(_COPY_CHUNK_BYTES, remaining + 1))
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > maximum_bytes:
                raise UpdateArtifactError(reason_code)
            chunks.append(chunk)
    except UpdateArtifactError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise UpdateArtifactError(reason_code) from error


def _open_windows_directory_lock(path: Path, *, reason_code: str) -> object:
    """Hold a non-delete-shared directory handle so its path cannot be swapped."""

    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise UpdateArtifactError(reason_code)
    handle: object | None = None
    try:
        kernel32 = win_dll("kernel32", use_last_error=True)

        class _ByHandleFileInformation(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            ]

        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        get_information = kernel32.GetFileInformationByHandle
        get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation)]
        get_information.restype = wintypes.BOOL
        handle = create_file(
            str(path),
            _WINDOWS_FILE_READ_ATTRIBUTES,
            _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
            None,
            _WINDOWS_OPEN_EXISTING,
            _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle in {None, invalid_handle}:
            raise UpdateArtifactError(reason_code)
        information = _ByHandleFileInformation()
        if not get_information(handle, ctypes.byref(information)):
            _close_windows_handle(handle)
            raise UpdateArtifactError(reason_code)
        attributes = int(information.dwFileAttributes)
        if not attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            _close_windows_handle(handle)
            raise UpdateArtifactError(reason_code)
        return handle
    except UpdateArtifactError:
        raise
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError) as error:
        if handle is not None:
            _close_windows_handle(handle)
        raise UpdateArtifactError(reason_code) from error


def _open_windows_receipt_file(path: Path, *, reason_code: str) -> tuple[int, os.stat_result]:
    """Open a receipt itself, rather than its reparse target, as a CRT descriptor."""

    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise UpdateArtifactError(reason_code)
    handle: object | None = None
    descriptor: int | None = None
    try:
        msvcrt = importlib.import_module("msvcrt")
        kernel32 = win_dll("kernel32", use_last_error=True)

        class _ByHandleFileInformation(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            ]

        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        get_information = kernel32.GetFileInformationByHandle
        get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation)]
        get_information.restype = wintypes.BOOL
        handle = create_file(
            str(path),
            _WINDOWS_GENERIC_READ,
            _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
            None,
            _WINDOWS_OPEN_EXISTING,
            _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle in {None, invalid_handle}:
            raise UpdateArtifactError(reason_code)
        information = _ByHandleFileInformation()
        if not get_information(handle, ctypes.byref(information)):
            raise UpdateArtifactError(reason_code)
        attributes = int(information.dwFileAttributes)
        if attributes & (_WINDOWS_FILE_ATTRIBUTE_DIRECTORY | _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT):
            raise UpdateArtifactError(reason_code)
        handle_value = handle if isinstance(handle, int) else getattr(handle, "value", None)
        if not isinstance(handle_value, int):
            raise UpdateArtifactError(reason_code)
        descriptor = int(
            msvcrt.open_osfhandle(
                handle_value,
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
            )
        )
        handle = None
        metadata = os.fstat(descriptor)
        entry_metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(entry_metadata.st_mode)
            or _metadata_is_reparse(entry_metadata)
            or _stat_identity(entry_metadata) != _stat_identity(metadata)
        ):
            raise UpdateArtifactError(reason_code)
        return descriptor, metadata
    except UpdateArtifactError:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if handle is not None:
            _close_windows_handle(handle)
        raise
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError) as error:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if handle is not None:
            _close_windows_handle(handle)
        raise UpdateArtifactError(reason_code) from error


def _close_windows_handle(handle: object) -> None:
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return
    with suppress(OSError, RuntimeError, TypeError, ValueError):
        kernel32 = win_dll("kernel32", use_last_error=True)
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        _ = close_handle(handle)


def _open_regular_descriptor(
    path: Path | str,
    *,
    reason_code: str,
    directory_descriptor: int | None = None,
) -> tuple[int, os.stat_result]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        if directory_descriptor is None:
            file_descriptor = os.open(path, flags)
        else:
            file_descriptor = os.open(path, flags, dir_fd=directory_descriptor)
    except (OSError, RuntimeError, ValueError) as error:
        raise UpdateArtifactError(reason_code) from error
    try:
        metadata = os.fstat(file_descriptor)
        entry_metadata = os.lstat(path) if directory_descriptor is None else os.lstat(path, dir_fd=directory_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(entry_metadata.st_mode)
            or _metadata_is_reparse(entry_metadata)
            or _stat_identity(entry_metadata) != _stat_identity(metadata)
        ):
            raise UpdateArtifactError(reason_code)
        return file_descriptor, metadata
    except UpdateArtifactError:
        with suppress(OSError):
            os.close(file_descriptor)
        raise
    except (OSError, RuntimeError, ValueError) as error:
        with suppress(OSError):
            os.close(file_descriptor)
        raise UpdateArtifactError(reason_code) from error


def _open_directory_descriptor(
    path: Path,
    *,
    reason_code: str,
) -> tuple[int | None, os.stat_result]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    if not hasattr(os, "O_DIRECTORY"):
        try:
            metadata = os.lstat(path)
        except (OSError, RuntimeError, ValueError) as error:
            raise UpdateArtifactError(reason_code) from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _metadata_is_reparse(metadata):
            raise UpdateArtifactError(reason_code)
        return None, metadata
    try:
        directory_descriptor = os.open(path, flags)
    except (OSError, RuntimeError, ValueError) as error:
        raise UpdateArtifactError(reason_code) from error
    try:
        metadata = os.fstat(directory_descriptor)
        entry_metadata = os.lstat(path)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(entry_metadata.st_mode)
            or _metadata_is_reparse(entry_metadata)
            or _stat_identity(entry_metadata) != _stat_identity(metadata)
        ):
            raise UpdateArtifactError(reason_code)
        return directory_descriptor, metadata
    except UpdateArtifactError:
        with suppress(OSError):
            os.close(directory_descriptor)
        raise
    except (OSError, RuntimeError, ValueError) as error:
        with suppress(OSError):
            os.close(directory_descriptor)
        raise UpdateArtifactError(reason_code) from error


def _descriptor_metadata(file_descriptor: int, *, reason_code: str) -> os.stat_result:
    try:
        return os.fstat(file_descriptor)
    except (OSError, RuntimeError, ValueError) as error:
        raise UpdateArtifactError(reason_code) from error


def _hash_descriptor(file_descriptor: int, *, reason_code: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        while chunk := os.read(file_descriptor, _COPY_CHUNK_BYTES):
            size += len(chunk)
            if size > _MAX_WHEEL_BYTES:
                raise UpdateArtifactError(reason_code)
            digest.update(chunk)
    except UpdateArtifactError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise UpdateArtifactError(reason_code) from error
    return digest.hexdigest(), size


def _verify_directory_entry_identity(
    path: Path | str,
    *,
    expected_identity: tuple[int, int, int, int, int, int],
    reason_code: str,
    directory_descriptor: int | None = None,
) -> None:
    file_descriptor, metadata = _open_regular_descriptor(
        path,
        reason_code=reason_code,
        directory_descriptor=directory_descriptor,
    )
    try:
        if _stat_identity(metadata) != expected_identity:
            raise UpdateArtifactError(reason_code)
    finally:
        with suppress(OSError):
            os.close(file_descriptor)


def _verify_directory_identity(
    path: Path,
    *,
    expected_identity: tuple[int, int, int, int, int, int],
    reason_code: str,
) -> None:
    directory_descriptor, metadata = _open_directory_descriptor(path, reason_code=reason_code)
    try:
        if _stat_identity(metadata) != expected_identity:
            raise UpdateArtifactError(reason_code)
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)


def _unlink_staged_entry(staged_path: Path, *, directory_descriptor: int | None) -> None:
    try:
        if directory_descriptor is None:
            staged_path.unlink(missing_ok=True)
        else:
            os.unlink(staged_path.name, dir_fd=directory_descriptor)
    except FileNotFoundError:
        return


def _is_metadata_entry(filename: str) -> bool:
    path = PurePosixPath(filename)
    return (
        not path.is_absolute()
        and len(path.parts) == 2
        and path.parts[0] not in {".", ".."}
        and path.parts[0].endswith(".dist-info")
        and path.parts[1] == "METADATA"
    )


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_mode,
    )


def _metadata_is_reparse(metadata: os.stat_result) -> bool:
    reparse_attribute = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400))
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & reparse_attribute)


def _same_directory_object(
    metadata: os.stat_result,
    expected_identity: tuple[int, int, int, int, int, int],
) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_dev == expected_identity[0]
        and metadata.st_ino == expected_identity[1]
        and stat.S_IFMT(metadata.st_mode) == stat.S_IFMT(expected_identity[5])
    )


def _write_all(file_descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(file_descriptor, data[offset:])
        if written <= 0:
            raise UpdateArtifactError("update_artifact_invalid")
        offset += written


__all__ = [
    "TrustedWheelArtifact",
    "UpdateArtifactError",
    "record_local_wheel_receipt",
    "recover_local_wheel_original",
    "stage_trusted_wheel",
]
