"""Authenticated transport primitives for the Codex daemon hook bridge."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import secrets
import stat
import time
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DISCOVERY_PROTOCOL_VERSION = 1
_DISCOVERY_CHALLENGE_TTL_SECONDS = 5
_MAX_DAEMON_RESPONSE_BYTES = 1_000_000
_MINIMUM_OPERATION_SECONDS = 0.01


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
    with response:
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


def _remaining_seconds(deadline: float, *, cap: float | None = None) -> float:
    remaining = max(0.0, deadline - time.monotonic())
    return remaining if cap is None else min(remaining, cap)
