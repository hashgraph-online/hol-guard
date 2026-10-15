"""Native bounded ELF dependency evidence for immutable executable mappings."""

from __future__ import annotations

from pathlib import Path

from ..native_restricted_pytest import restricted_native
from .restricted_linux_landlock import LinuxContainmentUnavailableError
from .restricted_pytest_model import RestrictedPytestError

_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_MAPPING_BYTES = 1024 * 1024 * 1024


def _elf(path: Path, *, library: bool, system_library: bool = False):
    """Project native ELF evidence from a path with measured file metadata."""
    try:
        value = restricted_native(
            "mapping_elf",
            {
                "path": path,
                "library": library,
                "system_library": system_library,
            },
            list,
        )
    except RestrictedPytestError as error:
        raise ValueError(str(error)) from error
    return value[0], tuple(value[1])


def collect_mapping_evidence(
    *,
    images: set[Path],
    read_files: set[Path],
    runtime_roots: tuple[Path, ...],
    workspace: Path,
) -> list[dict[str, object]]:
    try:
        return restricted_native(
            "mapping_evidence",
            {
                "images": sorted(images),
                "read_files": sorted(read_files),
                "runtime_roots": runtime_roots,
                "workspace": workspace,
                "max_file_bytes": _MAX_FILE_BYTES,
                "max_mapping_bytes": _MAX_MAPPING_BYTES,
            },
            list,
        )
    except RestrictedPytestError as error:
        raise LinuxContainmentUnavailableError(str(error)) from error
