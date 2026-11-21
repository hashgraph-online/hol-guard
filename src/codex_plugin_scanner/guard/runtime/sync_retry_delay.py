"""How long Guard waits after a rate-limited Guard Cloud answer."""

from __future__ import annotations

import urllib.error
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


def parse_retry_after_header(error: urllib.error.HTTPError) -> int:
    """Parse the Retry-After header from a 429 response. Returns seconds to wait."""
    return parse_retry_after_value(error.headers.get("Retry-After") if error.headers else None)


def parse_retry_after_value(retry_after: str | None) -> int:
    """Seconds to wait for a ``Retry-After`` value: delay seconds, an HTTP date or an ISO time."""
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


__all__ = ["parse_retry_after_header", "parse_retry_after_value"]
