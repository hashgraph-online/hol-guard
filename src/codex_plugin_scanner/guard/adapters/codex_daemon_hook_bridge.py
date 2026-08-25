"""Fast, authenticated bridge from Codex hooks to the local Guard daemon."""

from __future__ import annotations

import http.client
import json
import secrets
import sys
import time
import urllib.error
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

if __package__:
    from ..codex_hook_bridge_runtime import BridgeConfig
    from ..codex_hook_bridge_runtime import TrustedHookLaunch as _TrustedHookLaunch
    from ..codex_hook_bridge_runtime import bounded_hook_input as _hook_input
    from ..codex_hook_bridge_runtime import bridge_config_from_argv as _parse_bridge_config
    from ..codex_hook_bridge_runtime import trusted_hook_launch as _trusted_hook_launch
    from ..codex_hook_launch_runtime import isolated_hook_environment as _isolated_hook_environment
    from ..codex_hook_launch_runtime import run_isolated_hook_process as _run_isolated_hook_process
    from ..live_process_identity import CODEX_BROWSER_WAIT_PROCESS_KEY, current_process_identity
    from .codex_daemon_hook_auth import _DaemonResponseError
    from .codex_daemon_hook_resume import apply_browser_approval_wait
    from .codex_daemon_hook_transport import _daemon_response_once, _DaemonGenerationChangedError
else:  # pragma: no cover - exercised by subprocess integration tests
    _package_root = str(Path(__file__).resolve().parents[3])
    if _package_root not in sys.path:
        sys.path.insert(0, _package_root)
    from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import (
        _DaemonResponseError,
    )
    from codex_plugin_scanner.guard.adapters.codex_daemon_hook_resume import (
        apply_browser_approval_wait,
    )
    from codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport import (
        _daemon_response_once,
        _DaemonGenerationChangedError,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        BridgeConfig,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        TrustedHookLaunch as _TrustedHookLaunch,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bounded_hook_input as _hook_input,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bridge_config_from_argv as _parse_bridge_config,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        trusted_hook_launch as _trusted_hook_launch,
    )
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
        isolated_hook_environment as _isolated_hook_environment,
    )
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
        run_isolated_hook_process as _run_isolated_hook_process,
    )
    from codex_plugin_scanner.guard.live_process_identity import (
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        current_process_identity,
    )

_HOOK_TIMEOUT_GRACE_SECONDS = 2
_DAEMON_START_TIMEOUT_SECONDS = 8
_DISCOVERY_PROTOCOL_VERSION = 1
_MAX_HOOK_INPUT_BYTES = 1_000_000
_FAIL_CLOSED_REASON = "HOL Guard could not authenticate the local daemon. Run `hol-guard daemon repair`, then retry."
_LAUNCH_INTEGRITY_REASON = (
    "HOL Guard could not authenticate its managed Codex hook launcher. Run `hol-guard install codex`, then retry."
)
_MINIMUM_OPERATION_SECONDS = 0.01
_OVERLOAD_RESERVE_MS = 100
_OVERLOAD_REASON = (
    "HOL Guard is temporarily saturated and kept this action blocked. No approval was requested; retry the action."
)


def _json_object(text: str) -> dict[str, object] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


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


def _event_name(data: str) -> str:
    payload = _json_object(data)
    if payload is None:
        return "PreToolUse"
    value = payload.get("hook_event_name", payload.get("event", "PreToolUse"))
    return value.strip() if isinstance(value, str) and value.strip() else "PreToolUse"


def _with_browser_wait_process(data: str) -> str:
    payload = _json_object(data)
    if payload is None:
        return data
    process_identity = current_process_identity()
    if process_identity is None:
        payload.pop(CODEX_BROWSER_WAIT_PROCESS_KEY, None)
    else:
        payload[CODEX_BROWSER_WAIT_PROCESS_KEY] = process_identity
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _request_timeout(event_name: str, hook_timeouts: Mapping[str, int]) -> float:
    timeout = hook_timeouts.get(event_name, min(hook_timeouts.values(), default=10))
    return float(max(1, timeout - _HOOK_TIMEOUT_GRACE_SECONDS))


def _remaining_seconds(deadline: float, *, cap: float | None = None) -> float:
    remaining = max(0.0, deadline - time.monotonic())
    return remaining if cap is None else min(remaining, cap)


def _fail_closed(event_name: str, reason: str = _FAIL_CLOSED_REASON) -> dict[str, object]:
    if event_name == "PermissionRequest":
        return {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "decision": {
                    "behavior": "deny",
                    "message": reason,
                },
            }
        }
    if event_name == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    if event_name == "PostToolUse":
        return {
            "continue": False,
            "stopReason": reason,
            "systemMessage": reason,
        }
    return {
        "continue": False,
        "stopReason": reason,
        "systemMessage": reason,
    }


def _unavailable_response(event_name: str, reason: str) -> dict[str, object]:
    if event_name == "UserPromptSubmit":
        return {
            "continue": True,
            "systemMessage": reason,
        }
    return _fail_closed(event_name, reason)


def _run_daemon_start(
    start_command: Sequence[str],
    *,
    timeout_seconds: float,
    failure_kind: str = "transport-failure",
) -> bool:
    timeout = min(timeout_seconds, _DAEMON_START_TIMEOUT_SECONDS)
    if timeout < _MINIMUM_OPERATION_SECONDS:
        return False
    environment = _isolated_hook_environment()
    environment["HOL_GUARD_HOOK_FAILURE_KIND"] = failure_kind
    result = _run_isolated_hook_process(
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
    result = _run_isolated_hook_process(
        fallback_command,
        input_text=data,
        cwd=Path.home(),
        environment=_isolated_hook_environment(),
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0 or result.timed_out or result.output_limit_exceeded:
        return None
    if not result.stdout.strip():
        return {}
    return _json_object(result.stdout.strip())


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


def _daemon_process_failed(response: Mapping[str, object]) -> bool:
    reason_code = response.get("reason_code")
    return isinstance(reason_code, str) and reason_code.startswith("daemon_hook_process_")


def _codex_hook_response(response: Mapping[str, object], *, event_name: str) -> dict[str, object]:
    """Keep daemon metadata out of Codex's strict hook response schemas."""

    universal_keys = {"continue", "stopReason", "suppressOutput", "systemMessage"}
    event_keys = {
        "PostToolUse": {"decision", "reason"},
    }.get(event_name, set())
    allowed_keys = universal_keys | event_keys | {"hookSpecificOutput"}
    filtered = {key: value for key, value in response.items() if key in allowed_keys}
    hook_output = filtered.get("hookSpecificOutput")
    if event_name == "PostToolUse":
        if not isinstance(hook_output, Mapping):
            filtered.pop("hookSpecificOutput", None)
        else:
            post_tool_keys = {"hookEventName", "additionalContext", "updatedMCPToolOutput"}
            filtered["hookSpecificOutput"] = {key: value for key, value in hook_output.items() if key in post_tool_keys}
    return filtered


def _bound_hook_input() -> tuple[str, str] | None:
    raw_data = _hook_input(_MAX_HOOK_INPUT_BYTES)
    if raw_data is None:
        return None
    event_name = _event_name(raw_data)
    data = _with_browser_wait_process(raw_data) if event_name == "PreToolUse" else raw_data
    return event_name, data


def main(
    *,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    query: str,
    hook_timeouts: Mapping[str, int],
    manifest_path: str | Path | None = None,
    config_json: str | None = None,
) -> int:
    """Review one Codex hook through the resident daemon or a fail-safe fallback."""

    hook_input = _bound_hook_input()
    if hook_input is None:
        sys.stdout.write(json.dumps(_fail_closed("PreToolUse"), separators=(",", ":")))
        return 0
    event_name, data = hook_input
    timeout_seconds = _request_timeout(event_name, hook_timeouts)
    deadline = time.monotonic() + timeout_seconds
    response: dict[str, object] | None = None
    trusted_launch: _TrustedHookLaunch | None = None
    launch_integrity_failed = False
    daemon_overloaded = False
    transient_overload = False
    failure_kind = "transport-failure"

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
        transient_overload = _transient_overload(error) is not None
        failure_kind = _daemon_failure_kind(error)
        if transient_overload:
            try:
                response = _retry_transient_overload(error, deadline=deadline, request=daemon_request)
            except (OSError, ValueError, http.client.HTTPException, urllib.error.URLError):
                response = None
        if manifest_path is not None or config_json is not None:
            try:
                if manifest_path is None or config_json is None:
                    raise ValueError("managed Codex hook launch identity is incomplete")
                trusted_launch = _trusted_hook_launch(
                    manifest_path=manifest_path,
                    state_path=state_path,
                    fallback_command=fallback_command,
                    start_command=start_command,
                    config_json=config_json,
                )
            except (ImportError, OSError, RuntimeError, ValueError):
                launch_integrity_failed = True
        start_succeeded = (
            False
            if daemon_overloaded or response is not None
            else (
                trusted_launch.run_start(
                    start_command,
                    timeout_seconds=_remaining_seconds(deadline, cap=_DAEMON_START_TIMEOUT_SECONDS),
                    failure_kind=failure_kind,
                )
                if trusted_launch is not None
                else not launch_integrity_failed
                and _run_daemon_start(
                    start_command,
                    timeout_seconds=_remaining_seconds(deadline, cap=_DAEMON_START_TIMEOUT_SECONDS),
                    failure_kind=failure_kind,
                )
            )
        )
        if start_succeeded and response is None:
            try:
                response = _daemon_response(
                    state_path=state_path,
                    query=query,
                    data=data,
                    timeout_seconds=_remaining_seconds(deadline),
                )
            except (OSError, ValueError, http.client.HTTPException, urllib.error.URLError):
                response = None
    if response is not None and _daemon_process_failed(response):
        response = None
    if response is None and not daemon_overloaded:
        if trusted_launch is not None:
            fallback_stdout = trusted_launch.run_fallback(
                fallback_command,
                data=data,
                timeout_seconds=_remaining_seconds(deadline),
            )
            if fallback_stdout is not None:
                response = _json_object(fallback_stdout.strip()) if fallback_stdout.strip() else {}
        elif not launch_integrity_failed:
            response = _run_local_fallback(
                fallback_command,
                data=data,
                timeout_seconds=_remaining_seconds(deadline),
            )
    if response is None:
        failure_reason = (
            _OVERLOAD_REASON
            if daemon_overloaded
            else _LAUNCH_INTEGRITY_REASON
            if launch_integrity_failed
            else _FAIL_CLOSED_REASON
        )
        response = _unavailable_response(event_name, failure_reason)
    sys.stdout.write(_bridge_output(response, event_name=event_name, state_path=state_path, deadline=deadline))
    return 0


def _bridge_output(
    response: dict[str, object],
    *,
    event_name: str,
    state_path: str | Path,
    deadline: float,
) -> str:
    payload = apply_browser_approval_wait(
        response,
        event_name=event_name,
        state_path=state_path,
        deadline=deadline,
    )
    return json.dumps(_codex_hook_response(payload, event_name=event_name), separators=(",", ":"))


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


def _bridge_config_from_argv(argv: Sequence[str]) -> BridgeConfig:
    return _parse_bridge_config(argv, timeout_grace_seconds=_HOOK_TIMEOUT_GRACE_SECONDS)


if __name__ == "__main__":
    _config = _bridge_config_from_argv(sys.argv)
    raise SystemExit(
        main(
            state_path=_config["state_path"],
            manifest_path=_config["manifest_path"],
            fallback_command=_config["fallback_command"],
            start_command=_config["start_command"],
            query=_config["query"],
            hook_timeouts=_config["hook_timeouts"],
            config_json=_config["config_json"],
        )
    )
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
        isolated_hook_environment as _isolated_hook_environment,
    )
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
        run_isolated_hook_process as _run_isolated_hook_process,
    )
