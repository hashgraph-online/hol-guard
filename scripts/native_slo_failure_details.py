"""Bounded evidence for failed capacity requests, without retaining exception text."""

from __future__ import annotations

import http.client
from collections import Counter

from scripts.native_slo_progress import classify_benchmark_error

_FAILURE_TYPES = (
    (http.client.IncompleteRead, "http_incomplete_body"),
    (http.client.RemoteDisconnected, "http_disconnected_before_response"),
    (http.client.BadStatusLine, "http_invalid_status"),
    (http.client.CannotSendRequest, "http_connection_state"),
    (http.client.ResponseNotReady, "http_response_state"),
    (TimeoutError, "transport_timeout"),
    (ConnectionResetError, "connection_reset"),
    (ConnectionRefusedError, "connection_refused"),
    (BrokenPipeError, "broken_pipe"),
    (OSError, "operating_system_error"),
)


def failure_details(error: Exception) -> dict[str, str]:
    """Describe only the known category and typed cause, never the exception message."""
    cause = "unclassified"
    seen: set[int] = set()
    current: BaseException | None = error
    for _ in range(8):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        matched = next((label for kind, label in _FAILURE_TYPES if isinstance(current, kind)), None)
        if matched is not None:
            cause = matched
            break
        current = current.__cause__ or current.__context__
    return {"category": classify_benchmark_error(error), "cause": cause}


def summarize_request_failures(failures: list[dict[str, str]]) -> dict[str, dict[str, int]]:
    """Only internal, finite labels supplied by failure_details enter this summary."""
    return {
        "categories": dict(Counter(item["category"] for item in failures)),
        "causes": dict(Counter(item["cause"] for item in failures)),
    }
