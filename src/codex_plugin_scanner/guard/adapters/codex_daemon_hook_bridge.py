"""Fast, authenticated bridge from Codex hooks to the local Guard daemon."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import secrets
import stat
import sys
import time
import urllib.error
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from urllib.parse import urlparse

if __package__:
    from ..codex_hook_bridge_runtime import BridgeConfig
    from ..codex_hook_bridge_runtime import TrustedHookLaunch as _TrustedHookLaunch
    from ..codex_hook_bridge_runtime import bounded_hook_input as _hook_input
    from ..codex_hook_bridge_runtime import bridge_config_from_argv as _parse_bridge_config
    from ..codex_hook_bridge_runtime import trusted_hook_launch as _trusted_hook_launch
    from ..codex_hook_launch_runtime import isolated_hook_environment as _isolated_hook_environment
    from ..codex_hook_launch_runtime import run_isolated_hook_process as _run_isolated_hook_process
else:  # pragma: no cover - exercised by subprocess integration tests
    _package_root = str(Path(__file__).resolve().parents[3])
    if _package_root not in sys.path:
        sys.path.insert(0, _package_root)
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

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_HOOK_TIMEOUT_GRACE_SECONDS = 2
_DAEMON_START_TIMEOUT_SECONDS = 8
_DISCOVERY_PROTOCOL_VERSION = 1
_DISCOVERY_CHALLENGE_TTL_SECONDS = 5
_MAX_DAEMON_RESPONSE_BYTES = 1_000_000
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


class _DaemonResponseError(ValueError):
    def __init__(self, status: int, detail: str, *, authenticated: bool) -> None:
        super().__init__(f"daemon returned HTTP {status}")
        self.status = status
        self.detail = detail
        self.authenticated = authenticated


def _assert_loopback_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise ValueError(f"daemon URL must use http, not {parsed.scheme!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("daemon URL must not contain credentials")
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(f"daemon URL must target loopback, not {host!r}")
    if parsed.port is None:
        raise ValueError("daemon URL must include an explicit port")


def _json_object(text: str) -> dict[str, object] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _with_remaining_hint(data: str, deadline: float) -> str:
    payload = _json_object(data)
    if payload is None:
        return data
    payload["guard_remaining_ms"] = min(60_000, max(1, int((deadline - time.monotonic()) * 1000)))
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


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


def _private_file_text(path: Path, *, label: str) -> str:
    try:
        parent_metadata = path.parent.lstat()
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise ValueError("Guard home is not a directory")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular file")
    if os.name != "nt":
        if parent_metadata.st_uid != os.getuid() or metadata.st_uid != os.getuid():
            raise ValueError(f"{label} ownership does not match the current user")
        if stat.S_IMODE(parent_metadata.st_mode) & 0o077 or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"{label} permissions are not owner-only")
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ValueError(f"{label} is unreadable") from error


def _canonical_discovery_payload(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sign_discovery_payload(discovery_key: str, payload: dict[str, object]) -> str:
    try:
        key = bytes.fromhex(discovery_key)
    except ValueError as error:
        raise ValueError("daemon discovery key is malformed") from error
    if len(key) != 32:
        raise ValueError("daemon discovery key is malformed")
    return hmac.new(key, _canonical_discovery_payload(payload), hashlib.sha256).hexdigest()


def _authenticated_state(state_path: str | Path) -> tuple[dict[str, object], str]:
    path = Path(state_path)
    discovery_key = _private_file_text(path.parent / "daemon-discovery-key", label="daemon discovery key")
    try:
        payload = json.loads(_private_file_text(path, label="daemon state"))
    except json.JSONDecodeError as error:
        raise ValueError("daemon state is malformed") from error
    if not isinstance(payload, dict):
        raise ValueError("daemon state must be a JSON object")
    signature = payload.get("state_signature")
    unsigned = {key: value for key, value in payload.items() if key != "state_signature"}
    try:
        expected_key_id = hashlib.sha256(bytes.fromhex(discovery_key)).hexdigest()
    except ValueError as error:
        raise ValueError("daemon discovery key is malformed") from error
    if (
        not isinstance(signature, str)
        or unsigned.get("discovery_protocol_version") != _DISCOVERY_PROTOCOL_VERSION
        or unsigned.get("discovery_key_id") != expected_key_id
        or not secrets.compare_digest(signature, _sign_discovery_payload(discovery_key, unsigned))
    ):
        raise ValueError("daemon state authentication failed")
    host = unsigned.get("host")
    port = unsigned.get("port")
    pid = unsigned.get("pid")
    state_id = unsigned.get("state_id")
    started_at = unsigned.get("started_at")
    guard_home = unsigned.get("guard_home")
    auth_token_id = unsigned.get("auth_token_id")
    if (
        not isinstance(host, str)
        or host.lower() not in _LOOPBACK_HOSTS
        or not isinstance(port, int)
        or not 0 < port <= 65535
        or not isinstance(pid, int)
        or pid <= 0
        or not isinstance(state_id, str)
        or not state_id
        or not isinstance(started_at, str)
        or not started_at
        or not isinstance(guard_home, str)
        or not isinstance(auth_token_id, str)
    ):
        raise ValueError("daemon state identity is incomplete")
    try:
        expected_guard_home = str(path.parent.resolve())
        state_guard_home = str(Path(guard_home).resolve())
    except OSError as error:
        raise ValueError("daemon state Guard home is invalid") from error
    if state_guard_home != expected_guard_home:
        raise ValueError("daemon state belongs to a different Guard home")
    return payload, discovery_key


def _daemon_url(state_path: str | Path) -> str:
    payload, _discovery_key = _authenticated_state(state_path)
    host = str(payload["host"])
    port = payload.get("port")
    rendered_host = f"[{host}]" if ":" in host else host
    return f"http://{rendered_host}:{port}"


def _daemon_auth_token(state_path: str | Path, state: Mapping[str, object]) -> str:
    path = Path(state_path)
    token = _private_file_text(path.parent / "daemon-auth-token", label="daemon auth token")
    expected_token_id = state.get("auth_token_id")
    actual_token_id = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if (
        not token
        or not isinstance(expected_token_id, str)
        or not secrets.compare_digest(actual_token_id, expected_token_id)
    ):
        raise ValueError("daemon auth token does not match authenticated state")
    return token


def _http_json_response(
    response: http.client.HTTPResponse,
    *,
    label: str,
    connection: http.client.HTTPConnection,
    deadline: float,
    authenticated: bool,
) -> dict[str, object]:
    body = bytearray()
    while len(body) <= _MAX_DAEMON_RESPONSE_BYTES:
        remaining = _remaining_seconds(deadline)
        if remaining < _MINIMUM_OPERATION_SECONDS:
            raise TimeoutError(f"{label} exceeded the hook deadline")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        chunk = response.read1(min(64 * 1024, _MAX_DAEMON_RESPONSE_BYTES + 1 - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    if len(body) > _MAX_DAEMON_RESPONSE_BYTES:
        raise ValueError(f"{label} response is too large")
    if response.status != 200:
        raise _DaemonResponseError(
            response.status,
            body.decode("utf-8", errors="replace").strip(),
            authenticated=authenticated,
        )
    payload = _json_object(bytes(body).decode("utf-8", errors="replace").strip())
    if payload is None:
        raise ValueError(f"{label} returned malformed JSON")
    return payload


def _verify_challenge_response(
    response: dict[str, object],
    *,
    state: Mapping[str, object],
    discovery_key: str,
    nonce: str,
    hook_event: str,
) -> str:
    proof = response.get("proof")
    unsigned = {key: value for key, value in response.items() if key != "proof"}
    expected_fields = {
        "protocol_version": _DISCOVERY_PROTOCOL_VERSION,
        "nonce": nonce,
        "state_id": state.get("state_id"),
        "host": state.get("host"),
        "port": state.get("port"),
        "pid": state.get("pid"),
        "started_at": state.get("started_at"),
        "guard_home": state.get("guard_home"),
        "hook_event": hook_event,
    }
    if any(unsigned.get(key) != value for key, value in expected_fields.items()):
        raise ValueError("daemon identity challenge did not match authenticated state")
    issued_at_ms = unsigned.get("issued_at_ms")
    expires_at_ms = unsigned.get("expires_at_ms")
    now_ms = int(time.time() * 1000)
    if (
        not isinstance(issued_at_ms, int)
        or not isinstance(expires_at_ms, int)
        or issued_at_ms > now_ms + 1000
        or expires_at_ms < now_ms
        or expires_at_ms - issued_at_ms > _DISCOVERY_CHALLENGE_TTL_SECONDS * 1000
    ):
        raise ValueError("daemon identity challenge expired")
    expected_proof = _sign_discovery_payload(discovery_key, unsigned)
    if not isinstance(proof, str) or not secrets.compare_digest(proof, expected_proof):
        raise ValueError("daemon identity challenge authentication failed")
    return proof


def _event_name(data: str) -> str:
    payload = _json_object(data)
    if payload is None:
        return "PreToolUse"
    value = payload.get("hook_event_name", payload.get("event", "PreToolUse"))
    return value.strip() if isinstance(value, str) and value.strip() else "PreToolUse"


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
    state, discovery_key = _authenticated_state(state_path)
    host = str(state["host"])
    port_value = state["port"]
    if not isinstance(port_value, int):
        raise ValueError("daemon state port is invalid")
    port = port_value
    rendered_host = f"[{host}]" if ":" in host else host
    endpoint = f"http://{rendered_host}:{port}/v1/hooks/codex?{query}"
    _assert_loopback_http_url(endpoint)
    hook_event = _event_name(data)
    nonce = secrets.token_hex(32)
    connection = http.client.HTTPConnection(host, port, timeout=timeout_seconds)
    try:
        challenge_body = json.dumps(
            {
                "protocol_version": _DISCOVERY_PROTOCOL_VERSION,
                "nonce": nonce,
                "state_id": state["state_id"],
                "hook_event": hook_event,
            },
            separators=(",", ":"),
        )
        connection.request(
            "POST",
            "/v1/daemon/identity-challenge",
            body=challenge_body.encode("utf-8"),
            headers={"Content-Type": "application/json", "Connection": "keep-alive"},
        )
        challenge = _http_json_response(
            connection.getresponse(),
            label="daemon identity challenge",
            connection=connection,
            deadline=deadline,
            authenticated=False,
        )
        proof = _verify_challenge_response(
            challenge,
            state=state,
            discovery_key=discovery_key,
            nonce=nonce,
            hook_event=hook_event,
        )
        current_state, current_key = _authenticated_state(state_path)
        if current_state != state or not secrets.compare_digest(current_key, discovery_key):
            raise ValueError("daemon state changed during identity verification")
        auth_token = _daemon_auth_token(state_path, state)
        remaining = _remaining_seconds(deadline)
        if remaining < _MINIMUM_OPERATION_SECONDS:
            raise TimeoutError("daemon identity challenge exhausted the hook deadline")
        connection.timeout = remaining
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        hook_path = f"/v1/hooks/codex?{query}"
        hinted_data = _with_remaining_hint(data, deadline)
        connection.request(
            "POST",
            hook_path,
            body=hinted_data.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Connection": "close",
                "X-Guard-Token": auth_token,
                "X-Guard-Daemon-Nonce": nonce,
                "X-Guard-Daemon-Proof": proof,
            },
        )
        return _http_json_response(
            connection.getresponse(),
            label="daemon hook",
            connection=connection,
            deadline=deadline,
            authenticated=True,
        )
    finally:
        connection.close()


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
    if event_name == "PostToolUse" and isinstance(hook_output, Mapping):
        post_tool_keys = {"hookEventName", "additionalContext", "updatedMCPToolOutput"}
        filtered["hookSpecificOutput"] = {key: value for key, value in hook_output.items() if key in post_tool_keys}
    return filtered


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

    data = _hook_input(_MAX_HOOK_INPUT_BYTES)
    if data is None:
        sys.stdout.write(json.dumps(_fail_closed("PreToolUse"), separators=(",", ":")))
        return 0
    event_name = _event_name(data)
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
        response = _fail_closed(event_name, failure_reason)
    sys.stdout.write(json.dumps(_codex_hook_response(response, event_name=event_name), separators=(",", ":")))
    return 0


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
