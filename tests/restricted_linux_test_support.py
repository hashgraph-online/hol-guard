"""Direct native calls for the Linux containment projections Python no longer owns.

Rust owns ELF loader admission, the no-follow read index, mapping-record
validation, mount-target decoding and bounded mapping evidence. These helpers
call the native transports straight through so the tests below keep exercising
that request path without a Python runtime module in the middle.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.native_restricted_linux import linux_native, read_grants
from codex_plugin_scanner.guard.native_restricted_pytest import restricted_native
from codex_plugin_scanner.guard.runtime.restricted_linux_landlock import LinuxContainmentUnavailableError
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError

_MAX_ENTRIES = 240_000
_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_MAPPING_BYTES = 1024 * 1024 * 1024


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
