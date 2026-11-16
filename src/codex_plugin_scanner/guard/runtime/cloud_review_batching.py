"""Bounded batching policy for durable Cloud Review event delivery, decided by native ``cloud_review_batch``."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .cloud_review_event_delivery import CloudReviewEventProtocolError

CLOUD_REVIEW_DEFAULT_BATCH_EVENTS = 50
CLOUD_REVIEW_MAX_BATCH_EVENTS = 250
CLOUD_REVIEW_MAX_BATCH_BYTES = 512 * 1024


@dataclass(frozen=True)
class CloudReviewBatchLimits:
    """Effective limits for one Cloud Review upload request."""

    events: int = CLOUD_REVIEW_DEFAULT_BATCH_EVENTS
    bytes: int = CLOUD_REVIEW_MAX_BATCH_BYTES
    event_cap: int = CLOUD_REVIEW_MAX_BATCH_EVENTS


class CloudReviewEventTooLargeError(RuntimeError):
    """Raised when one projected event cannot fit an authenticated byte cap."""


class _RequestTooLargeError(RuntimeError):
    """The events are too large to hand to the native runtime in one request."""


def review_batch_answer(request: dict[str, object]) -> dict[str, object]:
    """Ask the native ``cloud_review_batch`` kind; without it nothing is sent."""
    from ..native_runner_authority import (
        NativeRunnerAuthorityError,
        NativeRunnerAuthorityRefusalError,
        native_runner_authority,
    )

    try:
        answer = native_runner_authority("cloud_review_batch", request)
    except NativeRunnerAuthorityError as error:
        if isinstance(error, NativeRunnerAuthorityRefusalError) and str(error).endswith("_request_too_large"):
            raise _RequestTooLargeError(str(error)) from error
        raise CloudReviewEventProtocolError(
            "Guard Cloud Review batches could not be prepared without the HOL Guard native runtime."
        ) from error
    message = answer.get("error")
    if isinstance(message, str):
        raise CloudReviewEventProtocolError(message)
    return answer


def _limits(answer: dict[str, object]) -> CloudReviewBatchLimits:
    values = [answer.get(name) for name in ("events", "bytes", "event_cap")]
    if not all(type(value) is int and value > 0 for value in values):
        raise CloudReviewEventProtocolError("HOL Guard native runtime returned malformed Review batch limits.")
    events, byte_cap, event_cap = values
    return CloudReviewBatchLimits(events=events, bytes=byte_cap, event_cap=event_cap)  # pyright: ignore[reportArgumentType]


def select_review_event_batch(
    events: list[dict[str, object]],
    limits: CloudReviewBatchLimits,
) -> list[dict[str, object]]:
    """Return the largest ordered prefix that fits the effective limits."""
    window = events[: limits.events]
    answer: dict[str, object] = {"too_large": True} if events else {"count": 0}
    while window:
        request = {"op": "select", "events": window, "limit_events": limits.events, "limit_bytes": limits.bytes}
        try:
            answer = review_batch_answer(request)  # pyright: ignore[reportArgumentType]
            break
        except _RequestTooLargeError:
            # Far past any byte cap: a shorter window still makes a batch; the rest go next.
            window = window[: len(window) // 2]
    if answer.get("too_large") is True:
        raise CloudReviewEventTooLargeError("A Cloud Review event exceeds the negotiated upload byte limit.")
    count = answer.get("count")
    if type(count) is not int or not 0 <= count <= len(events):
        raise CloudReviewEventProtocolError("HOL Guard native runtime returned a malformed Review batch.")
    return events[:count]


def next_review_batch_limits(
    current: CloudReviewBatchLimits,
    response: dict[str, object],
) -> CloudReviewBatchLimits:
    """Grow after success while honoring authenticated server-advertised caps."""
    return _limits(review_batch_answer({"op": "next", "limits": asdict(current), "response": response}))


def persisted_review_batch_limits(state: dict[str, object], binding_key: str) -> CloudReviewBatchLimits:
    """Load authenticated binding-scoped limits, clamped to client maxima."""
    return _limits(review_batch_answer({"op": "limits", "state": state, "binding_key": binding_key}))


__all__ = [
    "CLOUD_REVIEW_DEFAULT_BATCH_EVENTS",
    "CLOUD_REVIEW_MAX_BATCH_BYTES",
    "CLOUD_REVIEW_MAX_BATCH_EVENTS",
    "CloudReviewBatchLimits",
    "CloudReviewEventTooLargeError",
    "next_review_batch_limits",
    "persisted_review_batch_limits",
    "review_batch_answer",
    "select_review_event_batch",
]
