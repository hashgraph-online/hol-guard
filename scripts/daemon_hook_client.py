"""Authenticated Claude and Codex daemon hook clients for tests and CI tooling.

Guard's own hook bridges run in the native runtime
(``rust/crates/guard-runtime/src/claude_hook_bridge_transport.rs`` and
``codex_hook_bridge_transport.rs``). These Python clients send hook requests
through the same identity challenge for the installed SLO session, the
installed-wheel probes (``ci/native_runtime/installed_hook_client.py`` loads
this file by path) and the daemon transport tests. It imports only the
standard library and ``daemon_hook_auth.py``, which the installed-wheel probes
register before loading this file, so it loads under ``python -I``.
"""

from __future__ import annotations

import http.client
import json
import secrets
import time
from collections.abc import Mapping
from pathlib import Path

from scripts.daemon_hook_auth import (
    _assert_loopback_http_url,
    _authenticated_state,
    _daemon_auth_token,
    _DaemonResponseError,
    _http_json_response,
    _json_object,
    _remaining_seconds,
    _verify_challenge_response,
)

_DISCOVERY_PROTOCOL_VERSION = 1
_MINIMUM_OPERATION_SECONDS = 0.01
_MAX_DAEMON_RESPONSE_BYTES = 1_000_000
# Same ceiling as the hook stdin reader. A timing hint must not push a body the
# daemon would already have accepted over this limit.
_MAX_HOOK_REQUEST_BYTES = 1_000_000


class DaemonStateUnavailableError(OSError):
    """Authenticated daemon state is absent or cannot be used for transport."""


class DaemonIdentityError(ValueError):
    """A contacted listener failed authenticated daemon identity checks."""


class _DaemonGenerationChangedError(ValueError):
    """The authenticated daemon generation rotated during one hook request."""


def _with_remaining_hint(data: str, deadline: float) -> str:
    payload = _json_object(data)
    if payload is None:
        return data
    payload["guard_remaining_ms"] = min(60_000, max(1, int((deadline - time.monotonic()) * 1000)))
    hinted = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    try:
        hinted_bytes = hinted.encode("utf-8")
    except UnicodeEncodeError:
        return data
    if len(hinted_bytes) > _MAX_HOOK_REQUEST_BYTES:
        return data
    return hinted


def _codex_event_name(data: str) -> str:
    payload = _json_object(data)
    if payload is None:
        return "PreToolUse"
    value = payload.get("hook_event_name", payload.get("event", "PreToolUse"))
    return value.strip() if isinstance(value, str) and value.strip() else "PreToolUse"


def _claude_event_name(data: str) -> str:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        return "PreToolUse"
    value = payload.get("hook_event_name", payload.get("event")) if isinstance(payload, dict) else None
    return value.strip() if isinstance(value, str) and value.strip() else "PreToolUse"


def _rendered_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _daemon_generation_identity(state: Mapping[str, object]) -> tuple[object, ...]:
    return tuple(state.get(field) for field in ("state_id", "auth_token_id", "host", "port", "pid", "started_at"))


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


def authenticated_claude_hook_response(
    *,
    state_path: str | Path,
    query: str,
    data: str,
    timeout_seconds: float,
) -> str:
    """Send one Claude hook body through the daemon's identity challenge and return its text."""

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
    hook_event = _claude_event_name(data)
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
        remaining = max(0.0, deadline - time.monotonic())
        if remaining < _MINIMUM_OPERATION_SECONDS:
            raise TimeoutError("daemon identity challenge exhausted the hook deadline")
        connection.timeout = remaining
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        # The daemon times the hook from its own arrival, so tell it how long
        # this client will still wait; it must answer before that.
        connection.request(
            "POST",
            hook_path,
            body=_with_remaining_hint(data, deadline).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Connection": "close",
                "X-Guard-Daemon-Nonce": nonce,
                "X-Guard-Daemon-Proof": proof,
            },
        )
        return _read_hook_response(connection.getresponse(), connection=connection, deadline=deadline)
    finally:
        connection.close()


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


def _daemon_response_once(
    *,
    state_path: str | Path,
    query: str,
    data: str,
    timeout_seconds: float,
) -> dict[str, object] | None:
    """Send one Codex hook body through the daemon's identity challenge and token check."""

    deadline = time.monotonic() + max(0.0, timeout_seconds)
    state, discovery_key = _authenticated_state(state_path)
    host = str(state["host"])
    port_value = state["port"]
    if not isinstance(port_value, int):
        raise ValueError("daemon state port is invalid")
    port = port_value
    endpoint = f"http://{_rendered_host(host)}:{port}/v1/hooks/codex?{query}"
    _assert_loopback_http_url(endpoint)
    hook_event = _codex_event_name(data)
    nonce = secrets.token_hex(32)
    connection = http.client.HTTPConnection(host, port, timeout=timeout_seconds)
    try:
        challenge = _request_identity_challenge(
            connection,
            state=state,
            nonce=nonce,
            hook_event=hook_event,
            deadline=deadline,
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
