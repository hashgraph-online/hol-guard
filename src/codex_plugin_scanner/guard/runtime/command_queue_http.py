"""Bounded authenticated HTTP requests for the Guard command queue."""

from __future__ import annotations

import json

from .command_queue_protocol import command_api_url, redacted_error
from .runner import _sync_http_error_message, _sync_url_error_message

_REQUEST_TIMEOUT_SECONDS = 35
_RETRY_TIMEOUT_SECONDS = 60


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
    """POST ``payload`` to a command queue route through the native runtime.

    A gateway error is retried after the runtime's short pause rather than the
    minute a sync waits, so a decision waiting on a lease, ack or result is not
    held while Guard Cloud replaces a server.
    """

    if method != "POST":
        raise ValueError("Guard command queue requests are POST requests.")
    from . import cloud_bundle_sync

    return cloud_bundle_sync.cloud_json_request(
        auth_context,
        url=command_api_url(auth_context["sync_url"], path, base_path=base_path),
        body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        timeout_seconds=_REQUEST_TIMEOUT_SECONDS,
        retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
    )


__all__ = ["format_redacted_error", "request_json"]
