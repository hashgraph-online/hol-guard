"""Fast, authenticated bridge from Codex hooks to the local Guard daemon."""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlparse

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_HOOK_TIMEOUT_GRACE_SECONDS = 2
_DAEMON_START_TIMEOUT_SECONDS = 8
_FAIL_CLOSED_REASON = "HOL Guard could not complete local Codex hook review safely."


class BridgeConfig(TypedDict):
    state_path: str
    fallback_daemon_url: str
    fallback_command: tuple[str, ...]
    start_command: tuple[str, ...]
    query: str
    hook_timeouts: dict[str, int]


class _LoopbackOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _assert_loopback_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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


def _state_payload(state_path: str | Path) -> dict[str, object]:
    try:
        payload = json.loads(Path(state_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _daemon_url(state_path: str | Path, fallback_daemon_url: str) -> str:
    payload = _state_payload(state_path)
    port = payload.get("port")
    if isinstance(port, int) and 0 < port <= 65535:
        return f"http://127.0.0.1:{port}"
    normalized = fallback_daemon_url.rstrip("/")
    _assert_loopback_http_url(normalized)
    return normalized


def _daemon_auth_token(state_path: str | Path) -> str | None:
    path = Path(state_path)
    try:
        token = (path.parent / "daemon-auth-token").read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    if token:
        return token
    state_token = _state_payload(path).get("auth_token")
    return state_token if isinstance(state_token, str) and state_token.strip() else None


def _build_loopback_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _LoopbackOnlyRedirectHandler(),
    )


def _post_to_loopback_daemon(
    endpoint: str,
    data: str,
    *,
    state_path: str | Path,
    timeout_seconds: float,
) -> str:
    _assert_loopback_http_url(endpoint)
    headers = {"Content-Type": "application/json"}
    auth_token = _daemon_auth_token(state_path)
    if auth_token:
        headers["X-Guard-Token"] = auth_token
    request = urllib.request.Request(
        endpoint,
        data=data.encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with _build_loopback_opener().open(request, timeout=timeout_seconds) as response:
        final_url = response.geturl()
        if final_url:
            _assert_loopback_http_url(final_url)
        return response.read().decode("utf-8", errors="replace")


def _event_name(data: str) -> str:
    payload = _json_object(data)
    if payload is None:
        return "PreToolUse"
    value = payload.get("hook_event_name", payload.get("event", "PreToolUse"))
    return value.strip() if isinstance(value, str) and value.strip() else "PreToolUse"


def _request_timeout(event_name: str, hook_timeouts: Mapping[str, int]) -> float:
    timeout = hook_timeouts.get(event_name, min(hook_timeouts.values(), default=10))
    return float(max(1, timeout - _HOOK_TIMEOUT_GRACE_SECONDS))


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


def _run_daemon_start(start_command: Sequence[str], *, timeout_seconds: float) -> bool:
    try:
        result = subprocess.run(
            list(start_command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=min(timeout_seconds, _DAEMON_START_TIMEOUT_SECONDS),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _run_local_fallback(
    fallback_command: Sequence[str],
    *,
    data: str,
    timeout_seconds: float,
) -> dict[str, object] | None:
    try:
        result = subprocess.run(
            list(fallback_command),
            input=data,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    if not result.stdout.strip():
        return {}
    return _json_object(result.stdout.strip())


def _daemon_response(
    *,
    state_path: str | Path,
    fallback_daemon_url: str,
    query: str,
    data: str,
    timeout_seconds: float,
) -> dict[str, object] | None:
    endpoint = f"{_daemon_url(state_path, fallback_daemon_url)}/v1/hooks/codex?{query}"
    response = _post_to_loopback_daemon(
        endpoint,
        data,
        state_path=state_path,
        timeout_seconds=timeout_seconds,
    )
    return _json_object(response.strip())


def main(
    *,
    state_path: str | Path,
    fallback_daemon_url: str,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    query: str,
    hook_timeouts: Mapping[str, int],
) -> int:
    """Review one Codex hook through the resident daemon or a fail-safe fallback."""

    data = sys.stdin.read().strip() or "{}"
    event_name = _event_name(data)
    timeout_seconds = _request_timeout(event_name, hook_timeouts)
    response: dict[str, object] | None = None
    try:
        response = _daemon_response(
            state_path=state_path,
            fallback_daemon_url=fallback_daemon_url,
            query=query,
            data=data,
            timeout_seconds=timeout_seconds,
        )
    except (OSError, ValueError, urllib.error.URLError):
        if _run_daemon_start(start_command, timeout_seconds=timeout_seconds):
            try:
                response = _daemon_response(
                    state_path=state_path,
                    fallback_daemon_url=fallback_daemon_url,
                    query=query,
                    data=data,
                    timeout_seconds=timeout_seconds,
                )
            except (OSError, ValueError, urllib.error.URLError):
                response = None
    if response is None:
        response = _run_local_fallback(
            fallback_command,
            data=data,
            timeout_seconds=timeout_seconds,
        )
    if response is None:
        response = _fail_closed(event_name)
    sys.stdout.write(json.dumps(response, separators=(",", ":")))
    return 0


def _string_sequence(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"codex_daemon_hook_bridge config missing {label}")
    return tuple(value)


def _hook_timeout_mapping(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        raise SystemExit("codex_daemon_hook_bridge config missing hook_timeouts")
    timeouts = {
        str(key): timeout
        for key, timeout in value.items()
        if isinstance(key, str) and isinstance(timeout, int) and timeout > _HOOK_TIMEOUT_GRACE_SECONDS
    }
    if not timeouts:
        raise SystemExit("codex_daemon_hook_bridge config has no valid hook_timeouts")
    return timeouts


def _bridge_config_from_argv(argv: Sequence[str]) -> BridgeConfig:
    if len(argv) != 2:
        raise SystemExit("codex_daemon_hook_bridge expects one JSON config argument")
    payload = _json_object(argv[1])
    if payload is None:
        raise SystemExit("codex_daemon_hook_bridge config must be a JSON object")
    state_path = payload.get("state_path")
    fallback_daemon_url = payload.get("fallback_daemon_url")
    query = payload.get("query")
    if not isinstance(state_path, str):
        raise SystemExit("codex_daemon_hook_bridge config missing state_path")
    if not isinstance(fallback_daemon_url, str):
        raise SystemExit("codex_daemon_hook_bridge config missing fallback_daemon_url")
    if not isinstance(query, str):
        raise SystemExit("codex_daemon_hook_bridge config missing query")
    return BridgeConfig(
        state_path=state_path,
        fallback_daemon_url=fallback_daemon_url,
        fallback_command=_string_sequence(payload.get("fallback_command"), label="fallback_command"),
        start_command=_string_sequence(payload.get("start_command"), label="start_command"),
        query=query,
        hook_timeouts=_hook_timeout_mapping(payload.get("hook_timeouts")),
    )


if __name__ == "__main__":
    _config = _bridge_config_from_argv(sys.argv)
    raise SystemExit(
        main(
            state_path=_config["state_path"],
            fallback_daemon_url=_config["fallback_daemon_url"],
            fallback_command=_config["fallback_command"],
            start_command=_config["start_command"],
            query=_config["query"],
            hook_timeouts=_config["hook_timeouts"],
        )
    )
