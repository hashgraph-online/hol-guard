"""How long a sync request waits before retrying an HTTP error."""

from __future__ import annotations

import urllib.error
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

_SYNC_RETRYABLE_GATEWAY_STATUS_CODES = frozenset({502, 503, 504, 522, 524})


def parse_retry_after_header(error: urllib.error.HTTPError) -> int:
    """Parse the Retry-After header from a 429 response. Returns seconds to wait."""
    retry_after = error.headers.get("Retry-After") if error.headers else None
    if not retry_after:
        return 60  # Default: 60 seconds
    try:
        return max(1, int(retry_after))
    except ValueError:
        pass
    try:
        retry_date = parsedate_to_datetime(retry_after)
        if retry_date.tzinfo is None:
            retry_date = retry_date.replace(tzinfo=timezone.utc)
        return max(1, int((retry_date - datetime.now(timezone.utc)).total_seconds()))
    except (ValueError, TypeError):
        pass
    try:
        retry_date = datetime.fromisoformat(retry_after.replace("Z", "+00:00"))
        if retry_date.tzinfo is None:
            retry_date = retry_date.replace(tzinfo=timezone.utc)
        delta = (retry_date - datetime.now(timezone.utc)).total_seconds()
        return max(1, int(delta))
    except (ValueError, TypeError):
        return 60


def retryable_gateway_http_error(error: urllib.error.HTTPError) -> bool:
    return error.code in _SYNC_RETRYABLE_GATEWAY_STATUS_CODES


def retry_after_sleep_seconds(
    error: urllib.error.HTTPError,
    retry_timeout_seconds: int,
    *,
    unhinted_gateway_retry_seconds: float | None = None,
) -> float:
    """How long to wait before retrying a gateway error.

    A response without ``Retry-After`` waits the default 429 delay unless the
    caller names a shorter one; a gateway error that gives no hint is usually
    a proxy that lost its upstream, such as a server replaced during a deploy,
    and the next request reaches a live one.
    """

    if unhinted_gateway_retry_seconds is not None and not (error.headers and error.headers.get("Retry-After")):
        return max(unhinted_gateway_retry_seconds, 0.0)
    return min(parse_retry_after_header(error), retry_timeout_seconds)


__all__ = ["parse_retry_after_header", "retry_after_sleep_seconds", "retryable_gateway_http_error"]
