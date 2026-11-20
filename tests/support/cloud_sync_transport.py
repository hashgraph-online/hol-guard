"""The urllib Guard Cloud transport the Python runner used before the native request.

The native ``cloud-event-sync`` command now sends every Guard Cloud request
itself, with its own DPoP nonce, rate-limit, gateway and timeout retries
(``rust/crates/guard-runtime/src/cloud_json_request.rs``). Unit tests that
check what the runner does with Cloud's answer still send requests through
this copy so they can fake ``urllib`` or replace ``_guard_sync_request`` and
``_urlopen_json_with_timeout_retry`` here. Production code never imports it.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from codex_plugin_scanner.guard.mdm import network
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.sync_retry_delay import parse_retry_after_header

_RETRYABLE_GATEWAY_STATUS_CODES = frozenset({502, 503, 504, 522, 524})
_RETRYABLE_GATEWAY_MAX_ATTEMPTS = 2
_RETRY_CONTEXT = "_guard_dpop_retry_context"


def _guard_sync_request(
    auth_context: dict[str, object],
    *,
    request_url: str,
    method: str,
    data: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    dpop_nonce: str | None = None,
) -> urllib.request.Request:
    headers = runner._guard_sync_headers(
        auth_context,
        request_url=request_url,
        method=method,
        extra_headers=extra_headers,
        dpop_nonce=dpop_nonce,
    )
    request = urllib.request.Request(request_url, data=data, method=method, headers=headers)
    object.__setattr__(
        request,
        _RETRY_CONTEXT,
        {
            "auth_context": auth_context,
            "request_url": request_url,
            "method": method,
            "extra_headers": None if extra_headers is None else dict(extra_headers),
            "dpop_nonce": dpop_nonce,
        },
    )
    return request


def _resign(request: urllib.request.Request, *, dpop_nonce: str | None) -> urllib.request.Request | None:
    """Sign the same request again, with a fresh DPoP proof and the given nonce."""
    context = getattr(request, _RETRY_CONTEXT, None)
    if not isinstance(context, dict):
        return None
    auth_context = context.get("auth_context")
    request_url = context.get("request_url")
    method = context.get("method")
    extra_headers = context.get("extra_headers")
    if not isinstance(auth_context, dict) or not isinstance(request_url, str) or not isinstance(method, str):
        return None
    return _guard_sync_request(
        auth_context,
        request_url=request_url,
        method=method,
        data=request.data if isinstance(request.data, bytes) else None,
        extra_headers=None if not isinstance(extra_headers, dict) else dict(extra_headers),
        dpop_nonce=dpop_nonce,
    )


def _current_nonce(request: urllib.request.Request) -> str | None:
    context = getattr(request, _RETRY_CONTEXT, None)
    nonce = context.get("dpop_nonce") if isinstance(context, dict) else None
    return nonce if isinstance(nonce, str) else None


def _refresh_guard_sync_request(request: urllib.request.Request) -> urllib.request.Request | None:
    """A new proof for a retry; reusing a proof after a timeout looks like a replay."""
    return _resign(request, dpop_nonce=_current_nonce(request))


def _with_nonce(request: urllib.request.Request, dpop_nonce: str) -> urllib.request.Request | None:
    if _current_nonce(request) == dpop_nonce:
        return None
    return _resign(request, dpop_nonce=dpop_nonce)


def _gateway_wait(
    error: urllib.error.HTTPError, retry_timeout_seconds: int, unhinted_gateway_retry_seconds: float | None
) -> float:
    if unhinted_gateway_retry_seconds is not None and not (error.headers and error.headers.get("Retry-After")):
        return max(unhinted_gateway_retry_seconds, 0.0)
    return min(parse_retry_after_header(error), retry_timeout_seconds)


def _urlopen_json_with_timeout_retry(
    *,
    request: urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
    max_response_bytes: int | None = None,
    unhinted_gateway_retry_seconds: float | None = None,
) -> dict[str, object]:
    """Send one request with the retries the Python runner applied.

    Order: bounded 429 waits with a re-signed request, bounded gateway
    retries, the DPoP nonce challenge, then one retry at the longer timeout.
    """
    current = request
    timeout = timeout_seconds
    retried_timeout = False
    nonce_retries = 0
    rate_limit_retries = 0
    gateway_retries = 0
    while True:
        try:
            with network.managed_urlopen(current, timeout=timeout) as response:
                raw = response.read() if max_response_bytes is None else response.read(max_response_bytes + 1)
                if max_response_bytes is not None and len(raw) > max_response_bytes:
                    raise RuntimeError("Guard Cloud sync response exceeds its byte budget.")
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
                return payload
        except urllib.error.HTTPError as error:
            retry: urllib.request.Request | None = None
            if error.code == 429 and rate_limit_retries < 2:
                time.sleep(min(parse_retry_after_header(error), 120))
                rate_limit_retries += 1
                retry = _refresh_guard_sync_request(current)
                if retry is None:
                    raise
            elif error.code in _RETRYABLE_GATEWAY_STATUS_CODES and gateway_retries < _RETRYABLE_GATEWAY_MAX_ATTEMPTS:
                time.sleep(_gateway_wait(error, retry_timeout_seconds, unhinted_gateway_retry_seconds))
                gateway_retries += 1
                retry = _refresh_guard_sync_request(current) or current
            else:
                error_payload = runner._http_error_payload(error) if error.code in {400, 401} else None
                nonce = runner._dpop_nonce_from_http_error(error, error_payload)
                if nonce is not None and nonce_retries < 3:
                    retry = _with_nonce(current, nonce)
                if retry is None:
                    raise
                nonce_retries += 1
            current = retry
            timeout = timeout_seconds
            retried_timeout = False
        except OSError as error:
            if retried_timeout or not runner._is_timeout_error(error):
                raise
            refreshed = _refresh_guard_sync_request(current)
            if refreshed is None:
                raise
            current = refreshed
            timeout = retry_timeout_seconds
            retried_timeout = True
