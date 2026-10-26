"""Codex app-server continuation helpers for Guard approval resolution."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import stat
import struct
import tempfile
from collections.abc import Mapping
from pathlib import Path

_DEFAULT_SOCKET_PATH = Path.home() / ".codex" / "app-server-control" / "app-server-control.sock"
_MAX_WEBSOCKET_HEADER_BYTES = 16_384
_MAX_WEBSOCKET_FRAME_BYTES = 1_000_000
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
_CODEX_HOME_KEYS = ("codex_home", "codexHome")
_COMMAND_TEXT_KEYS = ("command_text", "commandText")
_WORKSPACE_KEYS = ("workspace", "cwd", "working_directory", "workingDirectory")
_MODEL_KEYS = ("codex_model", "codexModel", "model")
_NESTED_COMMAND_TEXT_KEYS = ("command", "cmd", "shell_command", "shellCommand")
_NESTED_TOOL_INPUT_KEYS = ("tool_input", "toolInput", "arguments", "args")


class _WebSocketClosedError(TimeoutError):
    """Raised when the app-server closes without a websocket close frame."""


def default_codex_app_server_socket_path(*, environ: Mapping[str, str] | None = None) -> Path:
    """Return the default Codex app-server socket path for the active Codex home."""

    env = environ or os.environ
    codex_home = env.get("CODEX_HOME", "").strip()
    if not codex_home:
        return _DEFAULT_SOCKET_PATH
    return Path(codex_home).expanduser() / "app-server-control" / "app-server-control.sock"


def default_codex_app_server_socket_available(*, environ: Mapping[str, str] | None = None) -> bool:
    """Return whether the current Codex app-server control socket is reachable."""

    socket_path = default_codex_app_server_socket_path(environ=environ)
    if not _is_trusted_local_socket(socket_path):
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.2)
            client.connect(str(socket_path))
    except OSError:
        return False
    return True


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
    socket_path = _first_string_from_env(env, ("CODEX_APP_SERVER_SOCKET", "CODEX_APP_SERVER_CONTROL_SOCKET"))
    if socket_path is not None:
        metadata["codex_app_server_socket"] = socket_path
    codex_home = _first_string_from_env(env, ("CODEX_HOME",))
    if codex_home is not None:
        metadata["codex_home"] = codex_home
    model = _first_string(payload, _MODEL_KEYS)
    if model is not None:
        metadata["codex_model"] = model
    workspace = _first_string(payload, _WORKSPACE_KEYS)
    if workspace is not None:
        metadata["workspace"] = workspace
    command_text = _first_command_text(payload)
    if command_text is not None:
        metadata["command_text"] = command_text
    return metadata


def _send_websocket_handshake(client: socket.socket) -> bytes:
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
    response, leftover = _recv_until(
        client,
        b"\r\n\r\n",
        max_bytes=_MAX_WEBSOCKET_HEADER_BYTES,
    )
    header_text = response.decode("iso-8859-1", errors="replace")
    if not header_text.startswith("HTTP/1.1 101"):
        raise ValueError("websocket_upgrade_failed")
    # RFC 6455 requires SHA-1 for Sec-WebSocket-Accept handshake verification.
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    expected_accept = base64.b64encode(hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
    headers = _parse_http_headers(header_text)
    if headers.get("sec-websocket-accept") != expected_accept:
        raise ValueError("websocket_accept_mismatch")
    return leftover


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


def _read_websocket_frame(client: socket.socket, pending: bytearray) -> tuple[int, bytes]:
    header = _recv_exact(client, 2, pending)
    first, second = header
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(client, 2, pending))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(client, 8, pending))[0]
    if length > _MAX_WEBSOCKET_FRAME_BYTES:
        raise ValueError("websocket_frame_too_large")
    mask = _recv_exact(client, 4, pending) if second & 0x80 else None
    payload = _recv_exact(client, length, pending) if length else b""
    if mask is not None:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def _recv_until(
    client: socket.socket,
    marker: bytes,
    *,
    max_bytes: int | None = None,
) -> tuple[bytes, bytes]:
    data = b""
    while marker not in data:
        chunk = client.recv(4096)
        if not chunk:
            raise _WebSocketClosedError("socket_closed")
        if max_bytes is not None and len(data) + len(chunk) > max_bytes:
            raise ValueError("websocket_headers_too_large")
        data += chunk
    boundary = data.index(marker) + len(marker)
    return data[:boundary], data[boundary:]


def _recv_exact(client: socket.socket, length: int, pending: bytearray) -> bytes:
    data = b""
    if pending:
        take = min(length, len(pending))
        data += bytes(pending[:take])
        del pending[:take]
    while len(data) < length:
        chunk = client.recv(length - len(data))
        if not chunk:
            raise _WebSocketClosedError("socket_closed")
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


def _is_trusted_local_socket(path: Path) -> bool:
    if os.name == "nt" or not _is_safe_local_socket_path(str(path)):
        return False
    try:
        metadata = path.lstat()
        parent_metadata = path.parent.lstat()
    except OSError:
        return False
    return (
        stat.S_ISSOCK(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and not metadata.st_mode & 0o022
        and stat.S_ISDIR(parent_metadata.st_mode)
        and parent_metadata.st_uid == os.geteuid()
        and not parent_metadata.st_mode & 0o022
    )


def _is_safe_codex_thread_id(thread_id: str) -> bool:
    return (
        0 < len(thread_id) <= 256
        and not thread_id.startswith("-")
        and all(char.isalnum() or char in "-_" for char in thread_id)
    )


def _first_string(payload: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_command_text(payload: Mapping[str, object]) -> str | None:
    command_text = _first_string(payload, _COMMAND_TEXT_KEYS)
    if command_text is not None:
        return command_text
    for key in _NESTED_TOOL_INPUT_KEYS:
        value = payload.get(key)
        if isinstance(value, Mapping):
            command_text = _first_string(value, _NESTED_COMMAND_TEXT_KEYS)
            if command_text is not None:
                return command_text
    return None


def _first_string_from_env(env: Mapping[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = env.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
