"""Typed restricted-download destinations, responses, blobs, and failures."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Protocol


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

    def cleanup(self) -> None:
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


@dataclass(frozen=True, slots=True)
class _CanonicalDestination:
    url: str
    hostname: str
    port: int
    request_target: str
    host_header: str


class _ReadableResponse(Protocol):
    status: int

    def read(self, amount: int = -1) -> bytes: ...

    def get_header(self, name: str) -> str | None: ...

    def header_items(self) -> tuple[tuple[str, str], ...]: ...

    def set_timeout(self, timeout: float) -> None: ...

    def close(self) -> None: ...


class _RestrictedDownloadError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = message


__all__ = [
    "RestrictedArchiveDownload",
    "RestrictedArchiveDownloadResult",
    "RestrictedArchiveFailure",
]
