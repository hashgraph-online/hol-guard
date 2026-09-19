"""Keep optional uploads separate from policy progress and authorization."""

from __future__ import annotations

import urllib.error
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, TypeVar

from .sync_response import InvalidSyncResponseError
from .telemetry_upload_progress import TelemetryProgressError

if TYPE_CHECKING:
    from ..store import GuardStore

_T = TypeVar("_T")


class PainSignalSyncError(RuntimeError):
    """A failed telemetry page with the count of already completed uploads."""

    def __init__(self, message: str, *, uploaded_count: int) -> None:
        super().__init__(message)
        self.uploaded_count = uploaded_count


@dataclass(frozen=True)
class _UploadResult(Generic[_T]):
    value: _T | None
    reason: str | None = None
    completed: int = 0


def sync_nonessential_telemetry(
    store: GuardStore,
    *,
    pain_signals: Callable[[], int],
    guard_events: Callable[[], dict[str, object]],
    authorization_errors: tuple[type[BaseException], ...],
) -> dict[str, object]:
    pain = _upload(pain_signals, authorization_errors)
    previous_event_summary = store.get_sync_payload("guard_events_v1_summary")
    events = _upload(guard_events, authorization_errors)
    event_reason = events.reason or _returned_event_failure(events.value)
    event_payload = events.value
    if events.reason is not None:
        previous = store.get_sync_payload("guard_events_v1_summary")
        previous = previous if isinstance(previous, dict) else {}
        progress_known = previous != previous_event_summary and previous.get("status") == "failed"
        event_payload = {
            "synced_at": None,
            "status": "degraded",
            "events": _count(previous.get("events")) if progress_known else None,
            "accepted": _count(previous.get("accepted")) if progress_known else None,
            "sync_reason": events.reason,
            "pending_count": _count(previous.get("pending_events")) if progress_known else None,
            "progress_known": progress_known,
        }
    return {
        "telemetry_status": "degraded" if pain.reason or event_reason else "success",
        "pain_signals_uploaded": pain.value if pain.reason is None else pain.completed,
        "pain_signals_upload_status": "degraded" if pain.reason else "success",
        "pain_signals_upload_reason": pain.reason,
        "guard_events_v1": event_payload,
        "guard_events_upload_status": "degraded" if event_reason else "success",
        "guard_events_upload_reason": event_reason,
    }


def _upload(upload: Callable[[], _T], authorization_errors: tuple[type[BaseException], ...]) -> _UploadResult[_T]:
    try:
        return _UploadResult(upload())
    except (RuntimeError, OSError) as error:
        chain = _exception_chain(error)
        if any(
            isinstance(item, (*authorization_errors, TelemetryProgressError))
            or (
                isinstance(item, urllib.error.HTTPError)
                and 400 <= item.code < 500
                and item.code not in {404, 408, 425, 429}
            )
            for item in chain
        ):
            raise
        completed = error.uploaded_count if isinstance(error, PainSignalSyncError) else 0
        return _UploadResult(None, _failure_reason(chain), completed)


def _exception_chain(error: BaseException) -> list[BaseException]:
    pending = [error]
    result: list[BaseException] = []
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        result.append(current)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return result


def _failure_reason(chain: list[BaseException]) -> str:
    if any(isinstance(error, InvalidSyncResponseError) for error in chain):
        return "telemetry_invalid_response"
    for error in chain:
        if isinstance(error, urllib.error.HTTPError):
            return {
                404: "telemetry_endpoint_unavailable",
                429: "telemetry_rate_limited",
            }.get(error.code, "telemetry_service_error")
    return (
        "telemetry_transport_error" if any(isinstance(error, OSError) for error in chain) else "telemetry_upload_failed"
    )


def _returned_event_failure(value: object) -> str | None:
    if not isinstance(value, dict) or (value.get("sync_skipped") is not True and value.get("status") != "failed"):
        return None
    return {
        "guard_events_endpoint_unavailable": "telemetry_endpoint_unavailable",
        "guard_events_rate_limited": "telemetry_rate_limited",
    }.get(str(value.get("sync_reason")), "telemetry_upload_failed")


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0
