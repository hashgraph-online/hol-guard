"""Claude Code daemon hook bridge executed by the same Python as Guard."""

from __future__ import annotations

import json
import queue
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, urljoin, urlparse

from ..codex_hook_launch_runtime import (
    isolated_daemon_start_command,
    isolated_hook_environment,
    run_isolated_hook_process,
)
from ..daemon.manager import load_guard_daemon_auth_token
from .claude_code import CLAUDE_GUARD_DAEMON_HOOK_MARKER
from .claude_daemon_state import canonical_daemon_state_path, daemon_port_from_state, state_path_for_query

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DEGRADED_DAEMON_MESSAGE = (
    "HOL Guard could not reach the local daemon ({reason}) and continued this action without native review."
)
_RISKY_PROMPT_SYSTEM_MESSAGE = (
    "HOL Guard intercepted this prompt because it asks Claude to access local secrets. If Claude "
    "asks to continue, HOL Guard will route the decision through a branded approval prompt."
)
_RISKY_PROMPT_ADDITIONAL_CONTEXT = (
    "HOL Guard will intercept Claude's next attempt to access local secrets and open a branded "
    "approval question to protect you."
)
_HARNESS_TIMEOUT_BUDGET_SECONDS = 10
_DAEMON_IO_TIMEOUT_SECONDS = 2
_RECOVERY_TIMEOUT_SECONDS = 3
_FALLBACK_TIMEOUT_SECONDS = 8
_MAX_DAEMON_RESPONSE_BYTES = 1_000_000
_MAX_HOOK_INPUT_BYTES = 1_000_000
_HOOK_DEADLINE_SECONDS = 8
_MINIMUM_OPERATION_SECONDS = 0.01


class _ResponseReader(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...

    def close(self) -> None: ...


class _DaemonHTTPError(RuntimeError):
    def __init__(self, code: int, detail: str) -> None:
        super().__init__(f"daemon returned HTTP {code}")
        self.code = code
        self.detail = detail


def main(
    *,
    state_path: str | Path,
    fallback_daemon_url: str,
    fallback_command: tuple[str, ...],
    query: str,
) -> int:
    """Proxy Claude hook stdin to the Guard daemon, falling back to the Python hook."""

    _ = CLAUDE_GUARD_DAEMON_HOOK_MARKER
    deadline = time.monotonic() + _HOOK_DEADLINE_SECONDS
    body = sys.stdin.read(_MAX_HOOK_INPUT_BYTES + 1)
    if len(body.encode("utf-8", errors="replace")) > _MAX_HOOK_INPUT_BYTES:
        event = _event_name(body)
        if not (event.startswith("Permission") or event in {"UserPromptSubmit", "PostToolUse", "Stop"}):
            event = "PreToolUse"
        sys.stdout.write(_limit_denied("hook input", event))
        return 0
    data = body.strip() or "{}"
    try:
        state_path = state_path_for_query(state_path, query)
    except ValueError as error:
        sys.stdout.write(_run_local_fallback(_daemon_failure_reason(error), data, fallback_command, deadline=deadline))
        return 0
    recovery_command = _recovery_command(state_path, query)
    try:
        endpoint = urljoin(_daemon_url(state_path, fallback_daemon_url), f"/v1/hooks/claude-code?{query}")
        _assert_loopback_http_url(endpoint)
        response_body = _valid_hook_json_or_degraded(
            _post_to_loopback_daemon(endpoint, data, state_path=state_path, deadline=deadline),
            reason="daemon returned malformed hook JSON",
            data=data,
        )
    except Exception as error:
        reason = _daemon_failure_reason(error)
        failure_kind = _daemon_failure_kind(error)
        if failure_kind == "authenticated-control-plane-failure":
            response_body = _authenticated_control_plane_failure(reason, data)
        elif _daemon_failure_is_recoverable(error):
            response_body = _recover_retry_or_fallback(
                reason,
                data,
                state_path=state_path,
                fallback_daemon_url=fallback_daemon_url,
                fallback_command=fallback_command,
                recovery_command=recovery_command,
                query=query,
                deadline=deadline,
                failure_kind=failure_kind,
            )
        else:
            response_body = _run_local_fallback(reason, data, fallback_command, deadline=deadline)
        sys.stdout.write(response_body)
        return 0
    if _should_suppress_output(data, response_body):
        return 0
    sys.stdout.write(response_body if response_body.strip() else "{}")
    return 0


def _build_loopback_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _LoopbackOnlyRedirectHandler(),
    )


class _LoopbackOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _assert_loopback_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _assert_loopback_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise ValueError(f"daemon URL must use http, not {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(f"daemon URL must target loopback, not {host!r}")
    if parsed.port is None:
        raise ValueError("daemon URL must include an explicit port")


def _remaining_seconds(deadline: float | None, *, cap: float) -> float:
    if deadline is None:
        return cap
    return min(cap, max(0.0, deadline - time.monotonic()))


def _post_to_loopback_daemon(
    endpoint: str,
    data: str,
    *,
    state_path: str | Path,
    deadline: float | None = None,
) -> str:
    result_queue: queue.Queue[tuple[str | None, Exception | None]] = queue.Queue(maxsize=1)
    timeout_seconds = _remaining_seconds(deadline, cap=_DAEMON_IO_TIMEOUT_SECONDS)
    if timeout_seconds < _MINIMUM_OPERATION_SECONDS:
        raise TimeoutError("Guard daemon hook request exhausted its absolute deadline")

    def request_once() -> None:
        request_deadline = time.monotonic() + timeout_seconds
        try:
            result_queue.put(
                (
                    _blocking_post_to_loopback_daemon(
                        endpoint,
                        data,
                        state_path=state_path,
                        timeout_seconds=timeout_seconds,
                    ),
                    None,
                )
            )
        except urllib.error.HTTPError as error:
            detail = _read_bounded_response(error, deadline=request_deadline).strip()
            result_queue.put((None, _DaemonHTTPError(error.code, detail)))
        except Exception as error:
            result_queue.put((None, error))

    threading.Thread(target=request_once, daemon=True, name="hol-guard-claude-hook-request").start()
    try:
        response_body, error = result_queue.get(timeout=timeout_seconds)
    except queue.Empty as error:
        raise TimeoutError("Guard daemon hook request exceeded its absolute deadline") from error
    if error is not None:
        raise error
    if response_body is None:
        raise RuntimeError("Guard daemon hook request returned no response")
    return response_body


def _blocking_post_to_loopback_daemon(
    endpoint: str,
    data: str,
    *,
    state_path: str | Path,
    timeout_seconds: float,
) -> str:
    auth_token = load_guard_daemon_auth_token(canonical_daemon_state_path(state_path).parent)
    headers = {"Content-Type": "application/json"}
    if isinstance(auth_token, str) and auth_token.strip():
        headers["X-Guard-Token"] = auth_token
    request = urllib.request.Request(
        endpoint,
        data=data.encode("utf-8"),
        headers=headers,
        method="POST",
    )
    opener = _build_loopback_opener()
    with opener.open(request, timeout=timeout_seconds) as response:
        final_url = response.geturl()
        if final_url:
            _assert_loopback_http_url(final_url)
        return _read_bounded_response(response, deadline=time.monotonic() + timeout_seconds)


def _read_bounded_response(response: _ResponseReader, *, deadline: float | None = None) -> str:
    timer: threading.Timer | None = None
    if deadline is not None:
        remaining = max(0.0, deadline - time.monotonic())
        if remaining < _MINIMUM_OPERATION_SECONDS:
            raise TimeoutError("Guard daemon response exhausted its absolute deadline")
        timer = threading.Timer(remaining, response.close)
        timer.daemon = True
        timer.start()
    try:
        body = response.read(_MAX_DAEMON_RESPONSE_BYTES + 1)
    finally:
        if timer is not None:
            timer.cancel()
    if len(body) > _MAX_DAEMON_RESPONSE_BYTES:
        raise ValueError("Guard daemon hook response exceeded the safe size limit")
    return body.decode("utf-8", errors="replace")


def _daemon_url(state_path: str | Path, fallback_daemon_url: str) -> str:
    port = daemon_port_from_state(state_path)
    if port is not None:
        return f"http://127.0.0.1:{port}/"
    normalized = fallback_daemon_url.rstrip("/") + "/"
    _assert_loopback_http_url(normalized)
    return normalized


def _event_name(data: str) -> str:
    try:
        payload = json.loads(data or "{}")
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        return str(payload.get("hook_event_name") or payload.get("event") or "PreToolUse")
    prefix = data[:4096]
    for key in ("hook_event_name", "event"):
        start = prefix.find(f'"{key}"')
        colon = prefix.find(":", start, start + 64) if start >= 0 else -1
        quote = prefix.find('"', colon + 1, colon + 80) if colon >= 0 else -1
        end = prefix.find('"', quote + 1, quote + 80) if quote >= 0 else -1
        if quote >= 0 and end > quote:
            return prefix[quote + 1 : end] or "PreToolUse"
    return "PreToolUse"


def _prompt_text(data: str) -> str:
    try:
        payload = json.loads(data or "{}")
    except json.JSONDecodeError:
        return ""
    if not isinstance(payload, dict):
        return ""
    prompt = payload.get("prompt", payload.get("user_prompt", ""))
    return str(prompt or "")


def _degraded_prompt(data: str) -> str:
    prompt = _prompt_text(data).lower()
    risky = any(token in prompt for token in (".env", "secret", "api key", "token"))
    if risky:
        return json.dumps(
            {
                "systemMessage": _RISKY_PROMPT_SYSTEM_MESSAGE,
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": _RISKY_PROMPT_ADDITIONAL_CONTEXT,
                },
            },
            separators=(",", ":"),
        )
    return json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}, separators=(",", ":"))


def _limit_denied(kind: str, event: str = "PreToolUse") -> str:
    return _deny_event(event, f"HOL Guard blocked this action because {kind} exceeded the safe size limit.")


def _deny_event(event: str, message: str) -> str:
    if event.startswith("Permission"):
        output: dict[str, object] = {
            "hookEventName": event,
            "decision": {"behavior": "deny", "message": message},
        }
        return json.dumps({"systemMessage": message, "hookSpecificOutput": output}, separators=(",", ":"))
    if event in {"UserPromptSubmit", "PostToolUse", "Stop"}:
        body = {"decision": "block", "reason": message, "hookSpecificOutput": {"hookEventName": event}}
        return json.dumps(body, separators=(",", ":"))
    output = {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": message,
    }
    return json.dumps({"systemMessage": message, "hookSpecificOutput": output}, separators=(",", ":"))


def _degraded(reason: str, data: str) -> str:
    event = _event_name(data)
    message = _DEGRADED_DAEMON_MESSAGE.format(reason=reason)
    if event == "UserPromptSubmit":
        return _degraded_prompt(data)
    if event == "PreToolUse":
        return json.dumps(
            {
                "continue": True,
                "hookSpecificOutput": {
                    "hookEventName": event,
                    "permissionDecision": "allow",
                    "permissionDecisionReason": message,
                },
            },
            separators=(",", ":"),
        )
    return "{}"


def _authenticated_control_plane_failure(reason: str, data: str) -> str:
    message = f"HOL Guard denied the action because daemon authentication failed: {reason}"
    event = _event_name(data)
    if event.startswith("Permission") or event == "PreToolUse":
        return _deny_event(event, message)
    return json.dumps({"continue": True, "stopReason": message}, separators=(",", ":"))


def _should_suppress_output(data: str, response_body: str) -> bool:
    if _event_name(data) != "UserPromptSubmit":
        return False
    trimmed = (response_body or "").strip()
    return trimmed in {"", "{}"}


def _valid_hook_json_or_degraded(output: str, *, reason: str, data: str) -> str:
    trimmed = (output or "").strip()
    if not trimmed:
        return _degraded(reason, data)
    try:
        decoded = json.loads(trimmed)
    except json.JSONDecodeError:
        return _degraded(reason, data)
    if not isinstance(decoded, dict):
        return _degraded(reason, data)
    return trimmed


def _run_local_fallback(
    reason: str,
    data: str,
    fallback_command: tuple[str, ...],
    *,
    deadline: float | None = None,
) -> str:
    timeout_seconds = _remaining_seconds(deadline, cap=_FALLBACK_TIMEOUT_SECONDS)
    if timeout_seconds < _MINIMUM_OPERATION_SECONDS:
        return _degraded(f"{reason}; fallback exhausted the hook deadline", data)
    result = run_isolated_hook_process(
        fallback_command,
        input_text=data,
        cwd=Path.home(),
        environment=isolated_hook_environment(),
        timeout_seconds=timeout_seconds,
    )
    if result.returncode == 0 and not result.timed_out and not result.output_limit_exceeded:
        stdout = (result.stdout or "").strip()
        if _should_suppress_output(data, stdout):
            return ""
        return _valid_hook_json_or_degraded(
            stdout,
            reason=f"{reason}; fallback returned malformed hook JSON",
            data=data,
        )
    suffix = "; fallback timed out" if result.timed_out else f"; fallback exited {result.returncode}"
    if result.output_limit_exceeded:
        return _limit_denied("hook output", _event_name(data))
    return _degraded(f"{reason}{suffix}", data)


def _daemon_failure_reason(error: Exception) -> str:
    if isinstance(error, _DaemonHTTPError):
        reason = str(error)
        return f"{reason}: {error.detail}" if error.detail else reason
    if isinstance(error, urllib.error.HTTPError):
        return f"daemon returned HTTP {error.code}"
    if isinstance(error, urllib.error.URLError):
        return str(error.reason or error)
    return str(error)


def _daemon_failure_is_recoverable(error: Exception) -> bool:
    if isinstance(error, ValueError):
        return False
    if isinstance(error, (urllib.error.HTTPError, _DaemonHTTPError)):
        if _daemon_failure_is_authenticated_overload(error):
            return False
        return error.code in {408, 500, 502, 503, 504}
    return True


def _recover_retry_or_fallback(
    reason: str,
    data: str,
    *,
    state_path: str | Path,
    fallback_daemon_url: str,
    fallback_command: tuple[str, ...],
    recovery_command: tuple[str, ...],
    query: str,
    deadline: float | None = None,
    failure_kind: str = "transport-failure",
) -> str:
    if recovery_command and _run_recovery_command(
        recovery_command,
        deadline=deadline,
        failure_kind=failure_kind,
    ):
        try:
            endpoint = urljoin(_daemon_url(state_path, fallback_daemon_url), f"/v1/hooks/claude-code?{query}")
            _assert_loopback_http_url(endpoint)
            return _valid_hook_json_or_degraded(
                _post_to_loopback_daemon(endpoint, data, state_path=state_path, deadline=deadline),
                reason=f"{reason}; recovered daemon returned malformed hook JSON",
                data=data,
            )
        except Exception as retry_error:
            reason = f"{reason}; daemon recovery retry failed: {retry_error}"
    return _run_local_fallback(reason, data, fallback_command, deadline=deadline)


def _run_recovery_command(
    recovery_command: tuple[str, ...],
    *,
    deadline: float | None = None,
    failure_kind: str = "transport-failure",
) -> bool:
    timeout_seconds = _remaining_seconds(deadline, cap=_RECOVERY_TIMEOUT_SECONDS)
    if timeout_seconds < _MINIMUM_OPERATION_SECONDS:
        return False
    environment = isolated_hook_environment()
    environment["HOL_GUARD_HOOK_FAILURE_KIND"] = failure_kind
    result = run_isolated_hook_process(
        recovery_command,
        input_text="",
        cwd=Path.home(),
        environment=environment,
        timeout_seconds=timeout_seconds,
        allow_windows_breakaway=True,
    )
    return result.returncode == 0 and not result.timed_out and not result.output_limit_exceeded


def _daemon_failure_is_authenticated_overload(error: urllib.error.HTTPError | _DaemonHTTPError) -> bool:
    detail = error.detail.lower() if isinstance(error, _DaemonHTTPError) else ""
    return error.code == 429 or any(
        marker in detail for marker in ("capacity", "overload", "too_many", "too many", "busy")
    )


def _daemon_failure_kind(error: Exception) -> str:
    if isinstance(error, (urllib.error.HTTPError, _DaemonHTTPError)):
        if _daemon_failure_is_authenticated_overload(error):
            return "overload"
        if error.code in {401, 403}:
            return "authenticated-control-plane-failure"
        return "transport-failure"
    if isinstance(error, ValueError):
        return "authenticated-control-plane-failure"
    return "transport-failure"


def _recovery_command(state_path: str | Path, query: str) -> tuple[str, ...]:
    query_values = parse_qs(query)
    home_values = query_values.get("home")
    home_dir = Path(home_values[0]) if home_values and home_values[0] else Path.home()
    package_root = Path(__file__).resolve().parents[3]
    return isolated_daemon_start_command(
        sys.executable,
        package_root,
        Path(state_path).parent,
        home_dir,
    )


def _bridge_config_from_argv(argv: list[str]) -> dict[str, Any]:
    if len(argv) != 2:
        raise SystemExit("claude_daemon_hook_bridge expects one JSON config argument")
    payload = json.loads(argv[1])
    if not isinstance(payload, dict):
        raise SystemExit("claude_daemon_hook_bridge config must be a JSON object")
    fallback_command = payload.get("fallback_command")
    if not isinstance(fallback_command, list) or not fallback_command:
        raise SystemExit("claude_daemon_hook_bridge config missing fallback_command")
    config: dict[str, Any] = {}
    for required_key in ("state_path", "fallback_daemon_url", "query"):
        if required_key not in payload:
            raise SystemExit(f"claude_daemon_hook_bridge config missing {required_key!r}")
        config[required_key] = str(payload[required_key])
    config["fallback_command"] = tuple(str(item) for item in fallback_command)
    return config


if __name__ == "__main__":
    config = _bridge_config_from_argv(sys.argv)
    raise SystemExit(
        main(
            state_path=config["state_path"],
            fallback_daemon_url=config["fallback_daemon_url"],
            fallback_command=config["fallback_command"],
            query=config["query"],
        )
    )
