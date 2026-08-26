"""Daemon bridge request/retry/fallback flow."""

from __future__ import annotations

import http.client
import json
import secrets
import time
import urllib.error
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from pathlib import Path

from ..codex_hook_bridge_runtime import TrustedHookLaunch, trusted_hook_launch
from ..codex_hook_launch_runtime import isolated_hook_environment, run_isolated_hook_process
from .codex_daemon_hook_auth import _DaemonResponseError
from .codex_daemon_hook_transport import _daemon_response_once, _DaemonGenerationChangedError

_DAEMON_START_TIMEOUT_SECONDS = 8
_MINIMUM_OPERATION_SECONDS = 0.01
_OVERLOAD_RESERVE_MS = 100


def bridge_review_response(
    *,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    query: str,
    data: str,
    deadline: float,
    manifest_path: str | Path | None,
    config_json: str | None,
) -> tuple[dict[str, object] | None, bool, bool]:
    response: dict[str, object] | None = None
    trusted_launch: TrustedHookLaunch | None = None
    launch_integrity_failed = False
    daemon_overloaded = False

    def daemon_request() -> dict[str, object] | None:
        return _daemon_response(
            state_path=state_path,
            query=query,
            data=data,
            timeout_seconds=_remaining_seconds(deadline),
        )

    try:
        response = daemon_request()
    except (OSError, ValueError, http.client.HTTPException, urllib.error.URLError) as error:
        daemon_overloaded = _authenticated_daemon_overload(error)
        if _transient_overload(error) is not None:
            with suppress(OSError, ValueError, http.client.HTTPException, urllib.error.URLError):
                response = _retry_transient_overload(error, deadline=deadline, request=daemon_request)
        trusted_launch, launch_integrity_failed = _trusted_launch_for_fallback(
            manifest_path=manifest_path,
            state_path=state_path,
            fallback_command=fallback_command,
            start_command=start_command,
            config_json=config_json,
        )
        if _daemon_start_succeeded(
            daemon_overloaded=daemon_overloaded,
            response=response,
            trusted_launch=trusted_launch,
            launch_integrity_failed=launch_integrity_failed,
            start_command=start_command,
            deadline=deadline,
            failure_kind=_daemon_failure_kind(error),
        ):
            with suppress(OSError, ValueError, http.client.HTTPException, urllib.error.URLError):
                response = daemon_request()
    if response is not None and _daemon_process_failed(response):
        response = None
    if response is None and not daemon_overloaded:
        response = _fallback_response(
            trusted_launch=trusted_launch,
            launch_integrity_failed=launch_integrity_failed,
            fallback_command=fallback_command,
            data=data,
            deadline=deadline,
        )
    return response, daemon_overloaded, launch_integrity_failed


def _daemon_response(
    *,
    state_path: str | Path,
    query: str,
    data: str,
    timeout_seconds: float,
) -> dict[str, object] | None:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    for attempt in range(2):
        try:
            return _daemon_response_once(
                state_path=state_path,
                query=query,
                data=data,
                timeout_seconds=_remaining_seconds(deadline),
            )
        except _DaemonGenerationChangedError:
            if attempt > 0 or _remaining_seconds(deadline) < _MINIMUM_OPERATION_SECONDS:
                raise
    raise AssertionError("unreachable")


def _transient_overload(error: BaseException) -> tuple[int, int] | None:
    if not isinstance(error, _DaemonResponseError) or not error.authenticated:
        return None
    payload = _json_object(error.detail)
    if payload is None or payload.get("reason_code") != "transient_overload":
        return None
    retry_after = payload.get("retry_after_ms", 25)
    estimated_service = payload.get("estimated_service_ms", 750)
    if not isinstance(retry_after, int) or isinstance(retry_after, bool):
        return None
    if not isinstance(estimated_service, int) or isinstance(estimated_service, bool):
        return None
    return min(75, max(25, retry_after)), min(2_800, max(100, estimated_service))


def _retry_transient_overload(
    error: BaseException,
    *,
    deadline: float,
    request: Callable[[], dict[str, object] | None],
) -> dict[str, object] | None:
    overload = _transient_overload(error)
    if overload is None:
        return None
    retry_after_ms, estimated_service_ms = overload
    jitter_ms = max(retry_after_ms, 25 + secrets.randbelow(51))
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    if remaining_ms < jitter_ms + estimated_service_ms + _OVERLOAD_RESERVE_MS:
        return None
    time.sleep(jitter_ms / 1000)
    return request()


def _trusted_launch_for_fallback(
    *,
    manifest_path: str | Path | None,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    config_json: str | None,
) -> tuple[TrustedHookLaunch | None, bool]:
    if manifest_path is None and config_json is None:
        return None, False
    try:
        if manifest_path is None or config_json is None:
            raise ValueError("managed Codex hook launch identity is incomplete")
        return (
            trusted_hook_launch(
                manifest_path=manifest_path,
                state_path=state_path,
                fallback_command=fallback_command,
                start_command=start_command,
                config_json=config_json,
            ),
            False,
        )
    except (ImportError, OSError, RuntimeError, ValueError):
        return None, True


def _daemon_start_succeeded(
    *,
    daemon_overloaded: bool,
    response: dict[str, object] | None,
    trusted_launch: TrustedHookLaunch | None,
    launch_integrity_failed: bool,
    start_command: Sequence[str],
    deadline: float,
    failure_kind: str,
) -> bool:
    if daemon_overloaded or response is not None:
        return False
    timeout = _remaining_seconds(deadline, cap=_DAEMON_START_TIMEOUT_SECONDS)
    if trusted_launch is not None:
        return trusted_launch.run_start(start_command, timeout_seconds=timeout, failure_kind=failure_kind)
    return not launch_integrity_failed and _run_daemon_start(
        start_command,
        timeout_seconds=timeout,
        failure_kind=failure_kind,
    )


def _fallback_response(
    *,
    trusted_launch: TrustedHookLaunch | None,
    launch_integrity_failed: bool,
    fallback_command: Sequence[str],
    data: str,
    deadline: float,
) -> dict[str, object] | None:
    if trusted_launch is not None:
        fallback_stdout = trusted_launch.run_fallback(
            fallback_command,
            data=data,
            timeout_seconds=_remaining_seconds(deadline),
        )
        if fallback_stdout is None:
            return None
        return _json_object(fallback_stdout.strip()) if fallback_stdout.strip() else {}
    if launch_integrity_failed:
        return None
    return _run_local_fallback(fallback_command, data=data, timeout_seconds=_remaining_seconds(deadline))


def _run_daemon_start(
    start_command: Sequence[str],
    *,
    timeout_seconds: float,
    failure_kind: str = "transport-failure",
) -> bool:
    timeout = min(timeout_seconds, _DAEMON_START_TIMEOUT_SECONDS)
    if timeout < _MINIMUM_OPERATION_SECONDS:
        return False
    environment = isolated_hook_environment()
    environment["HOL_GUARD_HOOK_FAILURE_KIND"] = failure_kind
    result = run_isolated_hook_process(
        start_command,
        input_text="",
        cwd=Path.home(),
        environment=environment,
        timeout_seconds=timeout,
        allow_windows_breakaway=True,
    )
    return result.returncode == 0 and not result.timed_out and not result.output_limit_exceeded


def _run_local_fallback(
    fallback_command: Sequence[str],
    *,
    data: str,
    timeout_seconds: float,
) -> dict[str, object] | None:
    if timeout_seconds < _MINIMUM_OPERATION_SECONDS:
        return None
    result = run_isolated_hook_process(
        fallback_command,
        input_text=data,
        cwd=Path.home(),
        environment=isolated_hook_environment(),
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0 or result.timed_out or result.output_limit_exceeded:
        return None
    return _json_object(result.stdout.strip()) if result.stdout.strip() else {}


def _authenticated_daemon_overload(error: BaseException) -> bool:
    if not isinstance(error, _DaemonResponseError) or not error.authenticated:
        return False
    detail = error.detail.lower()
    return error.status == 429 or any(
        marker in detail for marker in ("capacity", "overload", "too_many", "too many", "busy")
    )


def _daemon_failure_kind(error: BaseException) -> str:
    if _authenticated_daemon_overload(error):
        return "overload"
    if isinstance(error, _DaemonResponseError):
        if error.authenticated and error.status in {401, 403}:
            return "authenticated-control-plane-failure"
        return "transport-failure"
    if isinstance(error, ValueError):
        return "authenticated-control-plane-failure"
    return "transport-failure"


def _daemon_process_failed(response: Mapping[str, object]) -> bool:
    reason_code = response.get("reason_code")
    return isinstance(reason_code, str) and reason_code.startswith("daemon_hook_process_")


def _remaining_seconds(deadline: float, *, cap: float | None = None) -> float:
    remaining = max(0.0, deadline - time.monotonic())
    return remaining if cap is None else min(remaining, cap)


def _json_object(text: str) -> dict[str, object] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


__all__ = ["bridge_review_response"]
