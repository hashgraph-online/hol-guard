"""Typed results and bounded defaults for offline archive inspection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

_DEFAULT_TIMEOUT_SECONDS = 2.0
_DEFAULT_MAX_ARCHIVE_BYTES = 6 * 1024 * 1024
_DEFAULT_MAX_FILES = 500
_DEFAULT_MAX_EXPANDED_BYTES = 32 * 1024 * 1024
_DEFAULT_MAX_MEMBER_BYTES = 8 * 1024 * 1024
_DEFAULT_MAX_PACKAGE_JSON_BYTES = 256 * 1024
_DEFAULT_MAX_MEMORY_BYTES = 512 * 1024 * 1024
_DEFAULT_MAX_DECOMPRESSION_RATIO = 200.0
_DEFAULT_MAX_NESTED_ARCHIVES = 8
_DEFAULT_MAX_PATH_DEPTH = 64
_CHILD_RESULT_MAX_BYTES = 16 * 1024
_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
_NPM_REGISTRY_ALIAS_RE = re.compile(
    r"^npm:(?:@[a-z0-9][a-z0-9._~-]*/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)(?:@[^\s:/\\]+)?$"
)
_NESTED_ARCHIVE_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".zip",
    ".whl",
)

ArchiveInspectionStatus = Literal["clean", "blocked", "incomplete"]


class _ArchivePolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class ArchiveInspectionResult:
    status: ArchiveInspectionStatus
    code: str
    message: str
    severity: str
    sha256: str | None = None


def _result(
    status: ArchiveInspectionStatus,
    code: str,
    message: str,
    *,
    severity: str,
    sha256: str | None = None,
) -> ArchiveInspectionResult:
    return ArchiveInspectionResult(
        status=status,
        code=code,
        message=message,
        severity=severity,
        sha256=sha256,
    )


__all__ = ["ArchiveInspectionResult", "ArchiveInspectionStatus"]
