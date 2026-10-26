"""Typed restricted-download destinations, responses, blobs, and failures."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from types import TracebackType


@dataclass(frozen=True, slots=True)
class RestrictedArchiveFailure:
    """A stable, non-sensitive reason that an archive download stopped."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class RestrictedArchiveDownload:
    """A bounded archive blob whose content digest was computed while reading."""

    path: Path
    sha256: str
    size: int
    source_url: str = field(repr=False)
    final_url: str = field(repr=False)
    _temporary_directory: TemporaryDirectory[str] | None = field(default=None, repr=False, compare=False)

    def cleanup(self) -> None:
        if self._temporary_directory is not None:
            with suppress(OSError):
                self._temporary_directory.cleanup()
            return
        with suppress(OSError):
            self.path.unlink()

    def __del__(self) -> None:
        self.cleanup()

    def __enter__(self) -> RestrictedArchiveDownload:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.cleanup()


RestrictedArchiveDownloadResult = RestrictedArchiveDownload | RestrictedArchiveFailure


__all__ = [
    "RestrictedArchiveDownload",
    "RestrictedArchiveDownloadResult",
    "RestrictedArchiveFailure",
]
