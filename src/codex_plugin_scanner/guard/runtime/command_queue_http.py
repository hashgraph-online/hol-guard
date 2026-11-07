"""Bounded authenticated HTTP requests for the Guard command queue."""

from __future__ import annotations

import json

from .command_queue_protocol import command_api_url, redacted_error
from .runner import (
    _guard_sync_request,
    _sync_http_error_message,
    _sync_url_error_message,
    _urlopen_json_with_timeout_retry,
)

_REQUEST_TIMEOUT_SECONDS = 35
_RETRY_TIMEOUT_SECONDS = 60
# A gateway error with no Retry-After is usually a proxy whose upstream went
# away mid-request, as when Guard Cloud replaces a server during a deploy. The
# next request reaches a live server, so a decision waiting on this lease, ack
# or result is retried after a second rather than the minute a sync waits.
UNHINTED_GATEWAY_RETRY_SECONDS = 1.0


def format_redacted_error(error: BaseException) -> str:
    return redacted_error(error, http_formatter=_sync_http_error_message, os_formatter=_sync_url_error_message)


def request_json(
    auth_context: dict[str, object],
    *,
    method: str,
    path: str,
    payload: dict[str, object],
    base_path: str = "/api/guard/commands",
) -> dict[str, object]:
    request_url = command_api_url(auth_context["sync_url"], path, base_path=base_path)
    request = _guard_sync_request(
        auth_context,
        request_url=request_url,
        method=method,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    return _urlopen_json_with_timeout_retry(
        request=request,
        timeout_seconds=_REQUEST_TIMEOUT_SECONDS,
        retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
        unhinted_gateway_retry_seconds=UNHINTED_GATEWAY_RETRY_SECONDS,
    )


__all__ = ["UNHINTED_GATEWAY_RETRY_SECONDS", "format_redacted_error", "request_json"]
