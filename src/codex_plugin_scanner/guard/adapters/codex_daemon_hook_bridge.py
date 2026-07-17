"""Fast, authenticated bridge from Codex hooks to the local Guard daemon."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlparse

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_HOOK_TIMEOUT_GRACE_SECONDS = 2
_DAEMON_START_TIMEOUT_SECONDS = 8
_DISCOVERY_PROTOCOL_VERSION = 1
_DISCOVERY_CHALLENGE_TTL_SECONDS = 5
_MAX_DAEMON_RESPONSE_BYTES = 1_000_000
_FAIL_CLOSED_REASON = "HOL Guard could not authenticate the local daemon. Run `hol-guard daemon repair`, then retry."


class BridgeConfig(TypedDict):
    state_path: str
    fallback_command: tuple[str, ...]
    start_command: tuple[str, ...]
    query: str
    hook_timeouts: dict[str, int]


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


def _http_json_response(response: http.client.HTTPResponse, *, label: str) -> dict[str, object]:
    body = response.read(_MAX_DAEMON_RESPONSE_BYTES + 1)
    if len(body) > _MAX_DAEMON_RESPONSE_BYTES:
        raise ValueError(f"{label} response is too large")
    if response.status != 200:
        raise ValueError(f"{label} returned HTTP {response.status}")
    payload = _json_object(body.decode("utf-8", errors="replace").strip())
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
    query: str,
    data: str,
    timeout_seconds: float,
) -> dict[str, object] | None:
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
        challenge = _http_json_response(connection.getresponse(), label="daemon identity challenge")
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
        hook_path = f"/v1/hooks/codex?{query}"
        connection.request(
            "POST",
            hook_path,
            body=data.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Connection": "close",
                "X-Guard-Token": auth_token,
                "X-Guard-Daemon-Nonce": nonce,
                "X-Guard-Daemon-Proof": proof,
            },
        )
        return _http_json_response(connection.getresponse(), label="daemon hook")
    finally:
        connection.close()


def main(
    *,
    state_path: str | Path,
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
            query=query,
            data=data,
            timeout_seconds=timeout_seconds,
        )
    except (OSError, ValueError, http.client.HTTPException, urllib.error.URLError):
        if _run_daemon_start(start_command, timeout_seconds=timeout_seconds):
            try:
                response = _daemon_response(
                    state_path=state_path,
                    query=query,
                    data=data,
                    timeout_seconds=timeout_seconds,
                )
            except (OSError, ValueError, http.client.HTTPException, urllib.error.URLError):
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
    query = payload.get("query")
    if not isinstance(state_path, str):
        raise SystemExit("codex_daemon_hook_bridge config missing state_path")
    if not isinstance(query, str):
        raise SystemExit("codex_daemon_hook_bridge config missing query")
    return BridgeConfig(
        state_path=state_path,
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
            fallback_command=_config["fallback_command"],
            start_command=_config["start_command"],
            query=_config["query"],
            hook_timeouts=_config["hook_timeouts"],
        )
    )
