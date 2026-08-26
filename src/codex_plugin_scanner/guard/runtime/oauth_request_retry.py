"""One-shot OAuth refresh for authenticated Guard Cloud requests."""

from __future__ import annotations

import logging
import urllib.error
from collections.abc import Callable
from typing import TypeVar

_Result = TypeVar("_Result")


def request_after_oauth_refresh(
    auth_context: dict[str, object],
    *,
    request: Callable[[dict[str, object]], _Result],
    refresh: Callable[[], dict[str, object]],
    logger: logging.Logger,
    operation: str,
) -> tuple[_Result, dict[str, object]]:
    """Retry one request with a forced token refresh after an HTTP 401."""

    try:
        return request(auth_context), auth_context
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
    logger.warning("%s 401, attempting OAuth refresh retry.", operation)
    refreshed = refresh()
    return request(refreshed), refreshed


__all__ = ["request_after_oauth_refresh"]
