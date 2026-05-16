"""Codex app-server continuation helpers for Guard approval resolution."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol


class _OperationStore(Protocol):
    def list_guard_operations(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, object]]: ...


_DEFAULT_PROXY_TIMEOUT_SECONDS = 5.0
_DEFAULT_SOCKET_PATH = Path.home() / ".codex" / "app-server-control" / "app-server-control.sock"
_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_THREAD_ID_KEYS = (
    "codex_thread_id",
    "thread_id",
    "threadId",
    "conversation_id",
    "conversationId",
    "session_id",
    "sessionId",
)
_TURN_ID_KEYS = ("codex_turn_id", "turn_id", "turnId")
_SOCKET_KEYS = ("codex_app_server_socket", "app_server_socket", "appServerSocket")


def codex_resume_metadata_from_hook_payload(
    payload: Mapping[str, object],
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Extract local-only Codex app-server continuation metadata from a hook payload."""

    env = environ or os.environ
    thread_id = _first_string(payload, _THREAD_ID_KEYS)
    if thread_id is None:
        return {}
    metadata: dict[str, object] = {
        "codex_thread_id": thread_id,
    }
    turn_id = _first_string(payload, _TURN_ID_KEYS)
    if turn_id is not None:
        metadata["codex_turn_id"] = turn_id
    socket_path = _first_string(payload, _SOCKET_KEYS) or _first_string_from_env(
        env,
        ("CODEX_APP_SERVER_SOCKET", "CODEX_APP_SERVER_CONTROL_SOCKET"),
    )
    if socket_path is not None:
        metadata["codex_app_server_socket"] = socket_path
    return metadata


def resume_codex_thread_for_request(
    *,
    store: _OperationStore,
    request_id: str,
    action: str,
    timeout_seconds: float = _DEFAULT_PROXY_TIMEOUT_SECONDS,
) -> dict[str, object] | None:
    """Send a guarded continuation prompt to the Codex thread that queued a request."""

    operation = _find_codex_operation_for_request(store, request_id)
    if operation is None:
        return None
    metadata = operation.get("metadata")
    if not isinstance(metadata, dict):
        return None
    thread_id = _first_string(metadata, ("codex_thread_id", "thread_id", "threadId", "session_id", "sessionId"))
    if thread_id is None:
        return None
    socket_path = _first_string(metadata, _SOCKET_KEYS) or str(_DEFAULT_SOCKET_PATH)
    if not _is_safe_local_socket_path(socket_path):
        return {
            "status": "skipped",
            "reason": "unsafe_socket_path",
            "thread_id": thread_id,
        }
    if not Path(socket_path).expanduser().exists():
        return {
            "status": "skipped",
            "reason": "socket_not_available",
            "thread_id": thread_id,
            "socket_path": socket_path,
        }
    prompt = _continuation_prompt(action)
    request_payloads = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "hol-guard",
                    "title": "HOL Guard",
                    "version": "1.0.0",
                },
                "capabilities": {
                    "experimentalApi": True,
                    "optOutNotificationMethods": [
                        "thread/status/changed",
                        "turn/started",
                        "turn/completed",
                    ],
                },
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "turn/start",
            "params": {
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt}],
                "responsesapiClientMetadata": {
                    "hol_guard_request_id": request_id,
                    "hol_guard_resolution": "allow" if action == "allow" else "block",
                },
            },
        },
    ]
    try:
        response = _send_app_server_websocket_messages(
            socket_path=socket_path,
            payloads=request_payloads,
            response_id=2,
            timeout_seconds=timeout_seconds,
        )
    except (OSError, TimeoutError, ValueError) as error:
        return {
            "status": "failed",
            "reason": type(error).__name__,
            "thread_id": thread_id,
            "socket_path": socket_path,
        }
    if response is None:
        return {
            "status": "failed",
            "reason": "missing_turn_start_response",
            "thread_id": thread_id,
            "socket_path": socket_path,
        }
    if isinstance(response.get("error"), dict):
        error = response["error"]
        message = error.get("message") if isinstance(error, dict) else None
        return {
            "status": "failed",
            "reason": "turn_start_error",
            "message": str(message) if isinstance(message, str) else "Codex app-server rejected the continuation.",
            "thread_id": thread_id,
            "socket_path": socket_path,
        }
    return {
        "status": "sent",
        "reason": "turn_start_sent",
        "thread_id": thread_id,
        "socket_path": socket_path,
    }


def _find_codex_operation_for_request(store: _OperationStore, request_id: str) -> dict[str, object] | None:
    for operation in store.list_guard_operations(limit=200):
        if str(operation.get("harness")) != "codex":
            continue
        request_ids = operation.get("approval_request_ids")
        if isinstance(request_ids, list) and request_id in {str(item) for item in request_ids}:
            return operation
    return None


def _continuation_prompt(action: str) -> str:
    if action == "allow":
        return (
            "HOL Guard approved the paused action. Continue from where you stopped, retry the same "
            "blocked action once, and do not repeat work that already succeeded."
        )
    return (
        "HOL Guard kept the paused action blocked. Continue from where you stopped with a safe "
        "alternative and do not retry the blocked action."
    )


def _send_app_server_websocket_messages(
    *,
    socket_path: str,
    payloads: list[dict[str, object]],
    response_id: int,
    timeout_seconds: float,
) -> dict[str, object] | None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout_seconds)
        client.connect(str(Path(socket_path).expanduser()))
        _send_websocket_handshake(client)
        for payload in payloads:
            _send_websocket_text(client, json.dumps(payload, separators=(",", ":")))
        while True:
            opcode, payload = _read_websocket_frame(client)
            if opcode == 0x8:
                return None
            if opcode == 0x9:
                _send_websocket_frame(client, 0xA, payload)
                continue
            if opcode != 0x1:
                continue
            try:
                message = json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and message.get("id") == response_id:
                return message
    return None


def _send_websocket_handshake(client: socket.socket) -> None:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    client.sendall(request.encode("ascii"))
    response = _recv_until(client, b"\r\n\r\n")
    header_text = response.decode("iso-8859-1", errors="replace")
    if not header_text.startswith("HTTP/1.1 101"):
        raise ValueError("websocket_upgrade_failed")
    expected_accept = base64.b64encode(hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
    headers = _parse_http_headers(header_text)
    if headers.get("sec-websocket-accept") != expected_accept:
        raise ValueError("websocket_accept_mismatch")


def _send_websocket_text(client: socket.socket, text: str) -> None:
    _send_websocket_frame(client, 0x1, text.encode("utf-8"))


def _send_websocket_frame(client: socket.socket, opcode: int, payload: bytes) -> None:
    mask = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes([0x80 | opcode, 0x80 | length])
    elif length < 65_536:
        header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack("!H", length)
    else:
        header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack("!Q", length)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    client.sendall(header + mask + masked)


def _read_websocket_frame(client: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(client, 2)
    first, second = header
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(client, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(client, 8))[0]
    mask = _recv_exact(client, 4) if second & 0x80 else None
    payload = _recv_exact(client, length) if length else b""
    if mask is not None:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def _recv_until(client: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = client.recv(4096)
        if not chunk:
            raise TimeoutError("socket_closed")
        data += chunk
    return data


def _recv_exact(client: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = client.recv(length - len(data))
        if not chunk:
            raise TimeoutError("socket_closed")
        data += chunk
    return data


def _parse_http_headers(header_text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in header_text.split("\r\n")[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def _is_safe_local_socket_path(socket_path: str) -> bool:
    path = Path(socket_path).expanduser()
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        return False
    home = Path.home().resolve()
    tmp = Path("/tmp").resolve()
    var_tmp = Path("/var/tmp").resolve()
    system_tmp = Path(tempfile.gettempdir()).resolve()
    return resolved.is_absolute() and (
        resolved.is_relative_to(home)
        or resolved.is_relative_to(tmp)
        or resolved.is_relative_to(var_tmp)
        or resolved.is_relative_to(system_tmp)
    )


def _first_string(payload: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_string_from_env(env: Mapping[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = env.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
