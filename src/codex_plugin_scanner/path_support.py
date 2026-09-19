"""Shared path validation and normalization helpers."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from urllib.parse import urlparse

REMOTE_PREFIXES = ("https://", "git+", "github://")
DEFAULT_SAFE_READ_LIMIT_BYTES = 1_048_576


def path_entry_exists(path: Path) -> bool:
    """Return whether a directory entry exists without following its final link."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        # An unreadable entry is security-relevant and must reach the safe reader.
        return True
    return True


class FileChangedDuringReadError(OSError):
    """A checked input no longer names the same stable regular file."""


def _read_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _path_descriptor_identity(metadata: os.stat_result) -> tuple[int, ...]:
    # Windows Python exposes creation time as lstat().st_ctime_ns while
    # fstat().st_ctime_ns can contain the distinct metadata change time.
    # Compare their explicit birthtime across APIs; retain full change-time
    # comparisons between the two observations made with each same API.
    # Windows lstat cannot witness a metadata-only change before open when
    # creation time, identity, size and modification time all remain unchanged.
    if sys.platform != "win32":
        return _read_identity(metadata)
    return (*_read_identity(metadata)[:-1], getattr(metadata, "st_birthtime_ns", metadata.st_ctime_ns))


def read_bytes_file_within_root(
    root: Path,
    candidate: Path,
    *,
    max_bytes: int = DEFAULT_SAFE_READ_LIMIT_BYTES,
) -> bytes:
    """Read a bounded regular file without following symbolic links."""
    resolved_root = root.resolve(strict=True)
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError(f"not a regular file: {candidate}")
    resolved_candidate = candidate.resolve(strict=True)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise OSError(f"file escapes root: {candidate}") from exc
    if metadata.st_size > max_bytes:
        raise OSError(f"file exceeds {max_bytes} bytes: {candidate}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise FileChangedDuringReadError(f"checked file unavailable while opening: {candidate}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise FileChangedDuringReadError(f"file changed while opening: {candidate}")
        if _path_descriptor_identity(opened) != _path_descriptor_identity(metadata):
            raise FileChangedDuringReadError(f"file changed while opening: {candidate}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            # Read one byte beyond the observed size to detect growth without
            # allocating the entire configured budget for each small file.
            raw = handle.read(opened.st_size + 1)
        after = os.fstat(descriptor)
        try:
            path_after = candidate.lstat()
        except OSError as error:
            raise FileChangedDuringReadError(f"file changed while reading: {candidate}") from error
        if (
            len(raw) > max_bytes
            or len(raw) != opened.st_size
            or _read_identity(after) != _read_identity(opened)
            or _read_identity(path_after) != _read_identity(metadata)
        ):
            raise FileChangedDuringReadError(f"file changed while reading: {candidate}")
        return raw
    finally:
        os.close(descriptor)


def read_text_file_within_root(
    root: Path,
    candidate: Path,
    *,
    max_bytes: int = DEFAULT_SAFE_READ_LIMIT_BYTES,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> str:
    """Read bounded text from one verified regular-file descriptor."""
    return read_bytes_file_within_root(root, candidate, max_bytes=max_bytes).decode(encoding, errors=errors)


def is_remote_reference(value: str) -> bool:
    return value.startswith(REMOTE_PREFIXES)


def is_dot_relative_path(value: str) -> bool:
    return value.startswith("./")


def resolves_within_root(root: Path, candidate: Path, *, require_exists: bool = False) -> bool:
    try:
        resolved_root = root.resolve()
        resolved_candidate = candidate.resolve()
    except (OSError, RuntimeError):
        return False
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError:
        return False
    return not (require_exists and not resolved_candidate.exists())


def is_safe_relative_path(
    root: Path,
    value: str,
    *,
    require_prefix: bool = False,
    require_exists: bool = False,
) -> bool:
    candidate = Path(value)
    if candidate.is_absolute():
        return False
    if require_prefix and not is_dot_relative_path(value):
        return False
    return resolves_within_root(root, root / candidate, require_exists=require_exists)


def iter_safe_matching_files(root: Path, base_dir: Path, pattern: str) -> tuple[Path, ...]:
    try:
        resolved_root = root.resolve()
    except OSError:
        return ()
    if not base_dir.is_dir() or not resolves_within_root(resolved_root, base_dir, require_exists=True):
        return ()
    return tuple(
        candidate
        for candidate in sorted(base_dir.glob(pattern))
        if candidate.is_file() and resolves_within_root(resolved_root, candidate, require_exists=True)
    )


def resolve_path_within_allowed_roots(
    value: str,
    allowed_roots: tuple[Path, ...],
    *,
    require_exists: bool = False,
) -> Path | None:
    stripped = value.strip()
    if not stripped or stripped.lower() in {"none", "null"}:
        return None
    try:
        # codeql[py/path-injection] The resolved candidate is accepted only after an allowed-root containment check.
        resolved = Path(stripped).expanduser().resolve()
    except OSError:
        return None
    if require_exists and not resolved.is_dir():
        return None
    for root in allowed_roots:
        if resolves_within_root(root, resolved, require_exists=require_exists):
            return resolved
    return None


def normalize_codex_relative_path(value: str) -> str:
    if not value or is_remote_reference(value):
        return value
    if urlparse(value).scheme or Path(value).is_absolute():
        return value
    if value.startswith("./") or value.startswith("../"):
        return value
    return f"./{value}"
