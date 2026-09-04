"""Authenticated same-connection transport for Claude daemon hooks."""

from __future__ import annotations

import http.client
import json
import secrets
import time
from collections.abc import Mapping
from pathlib import Path

from .codex_daemon_hook_auth import (
    _assert_loopback_http_url,
    _authenticated_state,
    _daemon_auth_token,
    _DaemonResponseError,
    _http_json_response,
    _verify_challenge_response,
)

_DISCOVERY_PROTOCOL_VERSION = 1
_MAX_DAEMON_RESPONSE_BYTES = 1_000_000
_MINIMUM_OPERATION_SECONDS = 0.01


class DaemonStateUnavailableError(OSError):
    """Authenticated daemon state is absent or cannot be used for transport."""


class DaemonIdentityError(ValueError):
    """A contacted listener failed authenticated daemon identity checks."""


def authenticated_claude_hook_response(
    *,
    state_path: str | Path,
    query: str,
    data: str,
    timeout_seconds: float,
) -> str:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    try:
        state, discovery_key = _authenticated_state(state_path)
    except ValueError as error:
        raise DaemonStateUnavailableError(str(error)) from error
    host = str(state["host"])
    port_value = state["port"]
    if not isinstance(port_value, int):
        raise ValueError("daemon state port is invalid")
    hook_path = f"/v1/hooks/claude-code?{query}"
    _assert_loopback_http_url(f"http://{_rendered_host(host)}:{port_value}{hook_path}")
    hook_event = _event_name(data)
    nonce = secrets.token_hex(32)
    connection = http.client.HTTPConnection(host, port_value, timeout=timeout_seconds)
    try:
        challenge = _request_identity_challenge(
            connection,
            state=state,
            nonce=nonce,
            hook_event=hook_event,
            deadline=deadline,
        )
        try:
            proof = _verify_challenge_response(
                challenge,
                state=state,
                discovery_key=discovery_key,
                nonce=nonce,
                hook_event=hook_event,
            )
            current_state, current_key = _authenticated_state(state_path)
        except ValueError as error:
            raise DaemonIdentityError(str(error)) from error
        if _daemon_generation_identity(current_state) != _daemon_generation_identity(
            state
        ) or not secrets.compare_digest(current_key, discovery_key):
            raise DaemonIdentityError("daemon state changed during identity verification")
        try:
            auth_token = _daemon_auth_token(state_path, state)
        except ValueError as error:
            raise DaemonIdentityError(str(error)) from error
        remaining = max(0.0, deadline - time.monotonic())
        if remaining < _MINIMUM_OPERATION_SECONDS:
            raise TimeoutError("daemon identity challenge exhausted the hook deadline")
        connection.timeout = remaining
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
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
        return _read_hook_response(connection.getresponse(), connection=connection, deadline=deadline)
    finally:
        connection.close()


def _request_identity_challenge(
    connection: http.client.HTTPConnection,
    *,
    state: Mapping[str, object],
    nonce: str,
    hook_event: str,
    deadline: float,
) -> dict[str, object]:
    body = json.dumps(
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
        body=body.encode("utf-8"),
        headers={"Content-Type": "application/json", "Connection": "keep-alive"},
    )
    return _http_json_response(
        connection.getresponse(),
        label="daemon identity challenge",
        connection=connection,
        deadline=deadline,
        authenticated=False,
    )


def _read_hook_response(
    response: http.client.HTTPResponse,
    *,
    connection: http.client.HTTPConnection,
    deadline: float,
) -> str:
    body = bytearray()
    while len(body) <= _MAX_DAEMON_RESPONSE_BYTES:
        remaining = max(0.0, deadline - time.monotonic())
        if remaining < _MINIMUM_OPERATION_SECONDS:
            raise TimeoutError("daemon hook response exceeded the hook deadline")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        try:
            chunk = response.read1(min(64 * 1024, _MAX_DAEMON_RESPONSE_BYTES + 1 - len(body)))
        except TimeoutError as error:
            raise TimeoutError("daemon hook response exceeded the hook deadline") from error
        if not chunk:
            break
        body.extend(chunk)
    if len(body) > _MAX_DAEMON_RESPONSE_BYTES:
        raise ValueError("daemon hook response is too large")
    text = bytes(body).decode("utf-8", errors="replace")
    if response.status != 200:
        raise _DaemonResponseError(response.status, text.strip(), authenticated=True)
    return text


def _daemon_generation_identity(state: Mapping[str, object]) -> tuple[object, ...]:
    return tuple(state.get(field) for field in ("state_id", "auth_token_id", "host", "port", "pid", "started_at"))


def _event_name(data: str) -> str:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        return "PreToolUse"
    value = payload.get("hook_event_name", payload.get("event")) if isinstance(payload, dict) else None
    return value.strip() if isinstance(value, str) and value.strip() else "PreToolUse"


def _rendered_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host
