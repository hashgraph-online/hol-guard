"""Authenticated daemon hook request transport."""

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
_MINIMUM_OPERATION_SECONDS = 0.01


class _DaemonGenerationChangedError(ValueError):
    """The authenticated daemon generation rotated during one hook request."""


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


def _event_name(data: str) -> str:
    payload = _json_object(data)
    if payload is None:
        return "PreToolUse"
    value = payload.get("hook_event_name", payload.get("event", "PreToolUse"))
    return value.strip() if isinstance(value, str) and value.strip() else "PreToolUse"


def _remaining_seconds(deadline: float, *, cap: float | None = None) -> float:
    remaining = max(0.0, deadline - time.monotonic())
    return remaining if cap is None else min(remaining, cap)


def _daemon_generation_identity(state: Mapping[str, object]) -> tuple[object, ...]:
    return tuple(state.get(field) for field in ("state_id", "auth_token_id", "host", "port", "pid", "started_at"))


def _daemon_response_once(
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
        if _daemon_generation_identity(current_state) != _daemon_generation_identity(
            state
        ) or not secrets.compare_digest(current_key, discovery_key):
            raise _DaemonGenerationChangedError("daemon state changed during identity verification")
        try:
            auth_token = _daemon_auth_token(state_path, state)
        except ValueError as error:
            current_state, current_key = _authenticated_state(state_path)
            if _daemon_generation_identity(current_state) != _daemon_generation_identity(
                state
            ) or not secrets.compare_digest(current_key, discovery_key):
                raise _DaemonGenerationChangedError("daemon state changed before token authentication") from error
            raise
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
        try:
            return _http_json_response(
                connection.getresponse(),
                label="daemon hook",
                connection=connection,
                deadline=deadline,
                authenticated=True,
            )
        except _DaemonResponseError as error:
            if error.status in {401, 403}:
                current_state, current_key = _authenticated_state(state_path)
                if _daemon_generation_identity(current_state) != _daemon_generation_identity(
                    state
                ) or not secrets.compare_digest(current_key, discovery_key):
                    raise _DaemonGenerationChangedError("daemon state changed before hook authentication") from error
            raise
    finally:
        connection.close()
