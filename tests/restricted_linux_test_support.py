"""Direct native calls for the Linux containment projections Python no longer owns.

Rust owns ELF loader admission, the no-follow read index, mapping-record
validation, mount-target decoding and bounded mapping evidence. These helpers
call the native transports straight through so the tests below keep exercising
that request path without a Python runtime module in the middle.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.native_restricted_linux import linux_native
from codex_plugin_scanner.guard.native_restricted_pytest import restricted_native
from codex_plugin_scanner.guard.runtime.restricted_linux_landlock import LinuxContainmentUnavailableError
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError

_MAX_ENTRIES = 240_000
_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_MAPPING_BYTES = 1024 * 1024 * 1024


def read_grants(root: Path, max_entries: int) -> list[dict[str, Any]]:
    """Decode native inode evidence through a bounded private transport file."""
    try:
        with tempfile.TemporaryDirectory(prefix="hol-guard-linux-index-") as directory:
            snapshot = Path(directory).resolve() / "linux-index.json"
            result = linux_native(
                "linux_read_grants",
                {"root": root, "max_entries": max_entries, "result_snapshot": snapshot},
                dict,
            )
            if (
                set(result) != {"decoded_bytes", "sha256"}
                or type(result["decoded_bytes"]) is not int
                or not 0 <= result["decoded_bytes"] <= 64 * 1024 * 1024
                or not isinstance(result["sha256"], str)
            ):
                raise ValueError("Invalid native index envelope.")
            descriptor = os.open(snapshot, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                status = os.fstat(stream.fileno())
                if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid() or status.st_mode & 0o077:
                    raise ValueError("Invalid native index snapshot.")
                raw = stream.read(result["decoded_bytes"] + 1)
            if len(raw) != result["decoded_bytes"] or hashlib.sha256(raw).hexdigest() != result["sha256"]:
                raise ValueError("Invalid native index envelope.")
            value = json.loads(raw)
            if not isinstance(value, list) or any(
                not isinstance(item, dict)
                or set(item) != {"path", "device", "inode"}
                or not isinstance(item["path"], str)
                or any(type(item[key]) is not int for key in ("device", "inode"))
                for item in value
            ):
                raise ValueError("Invalid native index reply.")
            return value
    except (OSError, ValueError, TypeError) as error:
        raise LinuxContainmentUnavailableError("Linux workspace index transport is unavailable.") from error


@dataclass(frozen=True, slots=True)
class NativeLinuxReadGrant:
    path: Path
    device: int
    inode: int


def native_elf_loader(executable: Path) -> Path | None:
    value = linux_native("linux_elf_loader", {"executable": executable}, (str, type(None)))
    return None if value is None else Path(value)


def native_read_grants(root: Path, *, max_entries: int = _MAX_ENTRIES) -> tuple[NativeLinuxReadGrant, ...]:
    return tuple(
        NativeLinuxReadGrant(Path(row["path"]), row["device"], row["inode"]) for row in read_grants(root, max_entries)
    )


def native_path_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_mode)


def _linux_dict(operation, fields):
    try:
        return linux_native(operation, fields, dict)
    except LinuxContainmentUnavailableError as error:
        raise ValueError(str(error)) from error


def native_validate_records(records, *, approved_paths):
    value = _linux_dict(
        "linux_validate_records", {"records": records, "approved_paths": [str(path) for path in approved_paths]}
    )
    return [
        (Path(path), tuple(identity), digest, tuple(Path(v) for v in aliases))
        for path, identity, digest, aliases in value["records"]
    ]


def native_mount_targets(raw):
    value = _linux_dict("linux_mount_targets", {"raw_hex": raw.hex()})
    return [(Path(path), flags) for path, flags in value["targets"]]


def native_mapping_elf(path: Path, *, library: bool, system_library: bool = False):
    try:
        value = restricted_native(
            "mapping_elf", {"path": path, "library": library, "system_library": system_library}, list
        )
    except RestrictedPytestError as error:
        raise ValueError(str(error)) from error
    return value[0], tuple(value[1])


def native_mapping_evidence(
    *,
    images: set[Path],
    read_files: set[Path],
    runtime_roots: tuple[Path, ...],
    workspace: Path,
    max_file_bytes: int = _MAX_FILE_BYTES,
    max_mapping_bytes: int = _MAX_MAPPING_BYTES,
) -> list[dict[str, object]]:
    try:
        return restricted_native(
            "mapping_evidence",
            {
                "images": sorted(images),
                "read_files": sorted(read_files),
                "runtime_roots": runtime_roots,
                "workspace": workspace,
                "max_file_bytes": max_file_bytes,
                "max_mapping_bytes": max_mapping_bytes,
            },
            list,
        )
    except RestrictedPytestError as error:
        raise LinuxContainmentUnavailableError(str(error)) from error


__all__ = [
    "NativeLinuxReadGrant",
    "native_elf_loader",
    "native_mapping_elf",
    "native_mapping_evidence",
    "native_mount_targets",
    "native_path_identity",
    "native_read_grants",
    "native_validate_records",
]
