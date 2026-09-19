"""Http.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _parse_retry_after_header(error: runner.urllib.error.HTTPError) -> int:
    """Parse the Retry-After header from a 429 response. Returns seconds to wait."""
    retry_after = error.headers.get("Retry-After") if error.headers else None
    if not retry_after:
        return 60  # Default: 60 seconds
    try:
        return max(1, int(retry_after))
    except ValueError:
        pass
    try:
        retry_date = runner.datetime.fromisoformat(retry_after.replace("Z", "+00:00"))
        delta = (retry_date - runner.datetime.now(runner.timezone.utc)).total_seconds()
        return max(1, int(delta))
    except (ValueError, TypeError):
        return 60


def _retryable_gateway_http_error(error: runner.urllib.error.HTTPError) -> bool:
    return error.code in runner._SYNC_RETRYABLE_GATEWAY_STATUS_CODES


def _retry_after_sleep_seconds(error: runner.urllib.error.HTTPError, retry_timeout_seconds: int) -> int:
    return min(runner._parse_retry_after_header(error), retry_timeout_seconds)


def _request_for_gateway_retry(request: runner.urllib.request.Request) -> runner.urllib.request.Request:
    return runner._refresh_guard_sync_request(request) or request


def _read_guard_cloud_error_message(payload: dict[str, object]) -> str | None:
    guard_error = payload.get("guardError")
    if isinstance(guard_error, dict):
        for key in ("msg", "message"):
            nested = guard_error.get(key)
            if isinstance(nested, str) and nested.strip():
                return nested.strip()
    for key in ("err", "message", "error"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _sync_http_error_message(error: runner.urllib.error.HTTPError) -> str:
    try:
        raw_body = error.read().decode("utf-8", errors="replace")
    except OSError:
        raw_body = ""
    try:
        payload = runner.json.loads(raw_body) if raw_body else None
    except runner.json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        message = runner._read_guard_cloud_error_message(payload)
        if message is not None:
            return message
    normalized_body = raw_body.strip()
    if normalized_body:
        return normalized_body
    return f"HTTP Error {error.code}: {error.reason}"


def _redact_sync_text(value: str) -> str:
    return runner.redact_sensitive_text(value)


def _check_plan_restriction_403(
    error: runner.urllib.error.HTTPError,
) -> tuple[bool, str]:
    """Read a 403 response body exactly once.

    Returns (is_plan_restriction, error_message) so callers never
    drain the stream more than once regardless of which branch they take.
    Checks both machine-readable fields (syncEnabled, error, code) and
    human-readable error messages for plan-restriction signals.
    """
    try:
        raw_body = error.read().decode("utf-8", errors="replace")
    except OSError:
        raw_body = ""
    try:
        payload: object = runner.json.loads(raw_body) if raw_body else None
    except runner.json.JSONDecodeError:
        payload = None
    fallback = raw_body.strip() or f"HTTP Error {error.code}: {error.reason}"
    if not isinstance(payload, dict):
        return False, fallback
    message = payload.get("error")
    message_str = message.strip() if isinstance(message, str) and message.strip() else fallback
    if payload.get("syncEnabled") is False:
        return True, message_str
    error_field = str(payload.get("error") or "").lower()
    code_field = str(payload.get("code") or "").lower()
    combined = f"{error_field} {code_field}"
    if any(kw in combined for kw in runner._PLAN_403_KEYWORDS):
        return True, message_str
    return False, message_str


def _sync_url_error_message(error: OSError) -> str:
    reason = getattr(error, "reason", error)
    if reason is not None:
        reason_text = str(reason).strip()
        if reason_text:
            return f"Guard sync failed: {reason_text}"
    return "Guard sync failed because the remote endpoint could not be reached."


def _is_timeout_error(error: OSError) -> bool:
    if isinstance(error, TimeoutError | runner.socket.timeout):
        return True
    reason = getattr(error, "reason", error)
    if isinstance(reason, TimeoutError | runner.socket.timeout):
        return True
    reason_text = str(reason).strip().lower()
    if not reason_text:
        return False
    return reason_text == "timed out" or reason_text.endswith(" timed out") or "timed out" in reason_text


def _urlopen_with_sync_retries(
    *,
    request: runner.urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
    parse_json_response: bool,
    nonce_fast_path: bool,
) -> object:
    """Drive one Guard Cloud request through the shared sync retry policies.

    Retry order is deliberate: an optional DPoP nonce fast path for raw
    requests, then bounded 429 rate-limit waits with a freshly signed
    request, then bounded gateway retries, then the generic DPoP nonce
    challenge retry, and finally one timeout retry at the longer budget.
    """

    current_request = request
    current_timeout_seconds = timeout_seconds
    retried_timeout = False
    nonce_retry_count = 0
    rate_limit_retry_count = 0
    gateway_retry_count = 0
    while True:
        try:
            with runner.managed_urlopen(current_request, timeout=current_timeout_seconds) as response:
                if parse_json_response:
                    return runner.json.loads(response.read().decode("utf-8"))
                return None
        except runner.urllib.error.HTTPError as error:
            if nonce_fast_path and error.code == 401:
                error_payload = runner._http_error_payload(error)
                dpop_nonce = runner._dpop_nonce_from_http_error(error, error_payload)
                if dpop_nonce is not None and nonce_retry_count < 3:
                    nonce_retry_count += 1
                    retry_request = runner._guard_sync_request_with_nonce(current_request, dpop_nonce)
                    if retry_request is not None:
                        current_request = retry_request
                        current_timeout_seconds = timeout_seconds
                        retried_timeout = False
                        continue
            if error.code == 429 and rate_limit_retry_count < 2:
                retry_after = runner._parse_retry_after_header(error)
                runner.time.sleep(min(retry_after, 120))
                rate_limit_retry_count += 1
                refreshed_request = runner._refresh_guard_sync_request(current_request)
                if refreshed_request is None:
                    raise
                current_request = refreshed_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            if (
                runner._retryable_gateway_http_error(error)
                and gateway_retry_count < runner._SYNC_RETRYABLE_GATEWAY_MAX_ATTEMPTS
            ):
                retry_after = runner._retry_after_sleep_seconds(error, retry_timeout_seconds)
                runner.time.sleep(retry_after)
                gateway_retry_count += 1
                current_request = runner._request_for_gateway_retry(current_request)
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            error_payload = runner._http_error_payload(error) if error.code in {400, 401} else None
            dpop_nonce = runner._dpop_nonce_from_http_error(error, error_payload)
            retry_request = (
                None
                if dpop_nonce is None or nonce_retry_count >= 3
                else runner._guard_sync_request_with_nonce(current_request, dpop_nonce)
            )
            if retry_request is not None:
                nonce_retry_count += 1
                current_request = retry_request
                current_timeout_seconds = timeout_seconds
                retried_timeout = False
                continue
            raise
        except OSError as error:
            if not retried_timeout and runner._is_timeout_error(error):
                refreshed_request = runner._refresh_guard_sync_request(current_request)
                if refreshed_request is None:
                    raise
                current_request = refreshed_request
                current_timeout_seconds = retry_timeout_seconds
                retried_timeout = True
                continue
            raise


def _urlopen_json_with_timeout_retry(
    *,
    request: runner.urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
) -> dict[str, object]:
    payload = runner._urlopen_with_sync_retries(
        request=request,
        timeout_seconds=timeout_seconds,
        retry_timeout_seconds=retry_timeout_seconds,
        parse_json_response=True,
        nonce_fast_path=False,
    )
    if not isinstance(payload, dict):
        raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
    return payload


def _urlopen_with_timeout_retry(
    *,
    request: runner.urllib.request.Request,
    timeout_seconds: int,
    retry_timeout_seconds: int,
) -> None:
    runner._urlopen_with_sync_retries(
        request=request,
        timeout_seconds=timeout_seconds,
        retry_timeout_seconds=retry_timeout_seconds,
        parse_json_response=False,
        nonce_fast_path=True,
    )
