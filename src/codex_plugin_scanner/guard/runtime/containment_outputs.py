"""Bounded declared-output capture for contained workspace execution."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .containment_contract import ContainmentRequest

_MAX_FILES: Final = 20_000
_MAX_ENTRIES: Final = _MAX_FILES * 3
_MAX_TOTAL_BYTES: Final = 256 * 1024 * 1024
_MAX_CAPTURED_OUTPUT_BYTES: Final = 16 * 1024 * 1024


class OutputBoundaryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ContainmentCapturedOutput:
    snapshot_path: str
    content: bytes
    content_digest: str


def capture_declared_outputs(
    request: ContainmentRequest,
    snapshot: Path,
) -> tuple[ContainmentCapturedOutput, ...]:
    """Capture exact declared outputs and reject every undeclared file change."""

    expected = {item.snapshot_path: item.content_digest for item in request.inputs}
    output_paths = request.declared_outputs
    allowed = set(output_paths)
    observed: dict[str, tuple[bytes, str]] = {}
    total_bytes = 0
    present: set[str] = set()
    for path in _snapshot_regular_files(snapshot):
        relative = path.relative_to(snapshot).as_posix()
        present.add(relative)
        content, digest = _read_verified_output(path)
        total_bytes += len(content)
        if total_bytes > _MAX_TOTAL_BYTES:
            raise OutputBoundaryError("contained workspace output exceeds the total byte budget")
        if relative in allowed:
            if len(content) > _MAX_CAPTURED_OUTPUT_BYTES:
                raise OutputBoundaryError("declared containment output exceeds its byte budget")
            observed[relative] = (content, digest)
        elif expected.get(relative) != digest:
            raise OutputBoundaryError("contained execution changed an undeclared workspace path")
    if any(path not in observed for path in output_paths):
        raise OutputBoundaryError("contained execution did not produce every declared output")
    if any(path not in allowed and path not in present for path in expected):
        raise OutputBoundaryError("contained execution removed an undeclared workspace path")
    return tuple(ContainmentCapturedOutput(path, observed[path][0], observed[path][1]) for path in output_paths)


def _snapshot_regular_files(root: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    pending = [(root, _directory_identity(root))]
    visited_entries = [0]
    while pending:
        directory, expected_identity = pending.pop()
        for entry in _bounded_directory_entries(directory, expected_identity, visited_entries):
            path = directory / entry.name
            if entry.is_symlink():
                raise OutputBoundaryError("contained execution produced a symlink")
            if entry.is_dir(follow_symlinks=False):
                metadata = entry.stat(follow_symlinks=False)
                pending.append((path, (metadata.st_dev, metadata.st_ino)))
            elif entry.is_file(follow_symlinks=False):
                files.append(path)
                if len(files) > _MAX_FILES:
                    raise OutputBoundaryError("contained output discovery exceeded its file budget")
            else:
                raise OutputBoundaryError("contained execution produced a special file")
    return tuple(sorted(files))


def _bounded_directory_entries(
    directory: Path,
    expected_identity: tuple[int, int],
    visited_entries: list[int],
) -> Iterator[os.DirEntry[str]]:
    if os.name == "nt":
        return _bounded_windows_entries(directory, expected_identity, visited_entries)
    return _bounded_descriptor_entries(directory, expected_identity, visited_entries)


def _bounded_descriptor_entries(
    directory: Path,
    expected_identity: tuple[int, int],
    visited_entries: list[int],
) -> Iterator[os.DirEntry[str]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        raise OutputBoundaryError("contained output discovery failed") from exc
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != expected_identity:
            raise OutputBoundaryError("contained output directory identity changed")
        with os.scandir(descriptor) as entries:
            for entry in entries:
                visited_entries[0] += 1
                if visited_entries[0] > _MAX_ENTRIES:
                    raise OutputBoundaryError("contained output discovery exceeded its entry budget")
                yield entry
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != expected_identity:
            raise OutputBoundaryError("contained output directory identity changed")
    except OSError as exc:
        raise OutputBoundaryError("contained output discovery failed") from exc
    finally:
        os.close(descriptor)


def _bounded_windows_entries(
    directory: Path,
    expected_identity: tuple[int, int],
    visited_entries: list[int],
) -> Iterator[os.DirEntry[str]]:
    try:
        if _directory_identity(directory) != expected_identity:
            raise OutputBoundaryError("contained output directory identity changed")
        with os.scandir(directory) as entries:
            for entry in entries:
                visited_entries[0] += 1
                if visited_entries[0] > _MAX_ENTRIES:
                    raise OutputBoundaryError("contained output discovery exceeded its entry budget")
                yield entry
        if _directory_identity(directory) != expected_identity:
            raise OutputBoundaryError("contained output directory identity changed")
    except OSError as exc:
        raise OutputBoundaryError("contained output discovery failed") from exc


def _directory_identity(path: Path) -> tuple[int, int]:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise OutputBoundaryError("contained output directory identity is unavailable") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise OutputBoundaryError("contained output discovery requires a regular directory")
    return metadata.st_dev, metadata.st_ino


def _read_verified_output(path: Path) -> tuple[bytes, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OutputBoundaryError("contained output could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAX_TOTAL_BYTES:
            raise OutputBoundaryError("contained output must be a bounded singly linked regular file")
        chunks: list[bytes] = []
        consumed = 0
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            consumed += len(chunk)
            if consumed > _MAX_TOTAL_BYTES:
                raise OutputBoundaryError("contained output exceeds its byte budget")
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise OutputBoundaryError("contained output changed while it was captured")
        return b"".join(chunks), digest.hexdigest()
    finally:
        os.close(descriptor)


__all__ = ("ContainmentCapturedOutput", "OutputBoundaryError", "capture_declared_outputs")
