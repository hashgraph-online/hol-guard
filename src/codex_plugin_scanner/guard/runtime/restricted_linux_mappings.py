"""Typed portable projections; executable sealing and mounts are native."""

from pathlib import Path

from ..native_restricted_linux import linux_native
from .restricted_linux_landlock import LinuxContainmentUnavailableError

_BIND = 4096
_REMOUNT = 32
_RDONLY = 1
_NOSUID = 2
_NODEV = 4
_NOEXEC = 8
_NOATIME = 1024
_NODIRATIME = 2048
_RELATIME = 1 << 21
_STRICTATIME = 1 << 24


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_mode)


def _project(operation, fields):
    try:
        return linux_native(operation, fields, dict)
    except LinuxContainmentUnavailableError as error:
        raise ValueError(str(error)) from error


def validate_records(records, *, approved_paths):
    value = _project(
        "linux_validate_records", {"records": records, "approved_paths": [str(path) for path in approved_paths]}
    )
    return [
        (Path(path), tuple(identity), digest, tuple(Path(v) for v in aliases))
        for path, identity, digest, aliases in value["records"]
    ]


def mount_targets(raw):
    value = _project("linux_mount_targets", {"raw_hex": raw.hex()})
    return [(Path(path), flags) for path, flags in value["targets"]]
