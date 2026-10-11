"""Public compatibility exports for native approved-archive acquisition."""

from __future__ import annotations

from ..native_archive_acquisition import (
    canonical_external_https_archive_source,
    download_restricted_archive,
    is_external_https_archive_source,
)
from .restricted_archive_contract import (
    RestrictedArchiveDownload,
    RestrictedArchiveDownloadResult,
    RestrictedArchiveFailure,
)

__all__ = [
    "RestrictedArchiveDownload",
    "RestrictedArchiveDownloadResult",
    "RestrictedArchiveFailure",
    "canonical_external_https_archive_source",
    "download_restricted_archive",
    "is_external_https_archive_source",
]
