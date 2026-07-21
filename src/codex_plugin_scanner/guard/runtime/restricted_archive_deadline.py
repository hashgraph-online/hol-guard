"""Bound blocking archive operations by one absolute request deadline."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from contextlib import suppress
from typing import TypeVar, cast

from .restricted_archive_contract import _RestrictedDownloadError

_BLOCKING_OPERATION_SLOTS = threading.BoundedSemaphore(value=4)
_CallResult = TypeVar("_CallResult")


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _RestrictedDownloadError(
            "external_archive_download_timeout",
            "External archive download exceeded Guard's time limit.",
        )
    return remaining


def _call_with_deadline(
    operation: Callable[[], _CallResult],
    *,
    deadline: float,
    cancel: Callable[[], object] | None = None,
) -> _CallResult:
    results: list[object] = []
    errors: list[BaseException] = []
    if not _BLOCKING_OPERATION_SLOTS.acquire(blocking=False):
        raise _RestrictedDownloadError(
            "external_archive_download_timeout",
            "External archive operation capacity is unavailable.",
        )

    def invoke() -> None:
        try:
            results.append(operation())
        except BaseException as error:  # pragma: no cover - transferred to caller
            errors.append(error)
        finally:
            _BLOCKING_OPERATION_SLOTS.release()

    worker = threading.Thread(target=invoke, name="guard-archive-deadline", daemon=True)
    try:
        worker.start()
    except RuntimeError:
        _BLOCKING_OPERATION_SLOTS.release()
        raise _RestrictedDownloadError(
            "external_archive_connection_failed",
            "External archive operation could not be started.",
        ) from None
    worker.join(_remaining_seconds(deadline))
    if worker.is_alive():
        if cancel is not None:
            with suppress(OSError):
                _ = cancel()
        worker.join(0.05)
        raise _RestrictedDownloadError(
            "external_archive_download_timeout",
            "External archive download exceeded Guard's time limit.",
        )
    if errors:
        raise errors[0]
    if not results:
        raise _RestrictedDownloadError(
            "external_archive_connection_failed",
            "External archive operation did not return a result.",
        )
    return cast(_CallResult, results[0])
