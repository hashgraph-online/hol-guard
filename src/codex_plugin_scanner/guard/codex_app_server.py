"""Codex app-server continuation helpers for Guard approval resolution."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol


class _OperationStore(Protocol):
    def list_guard_operations(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, object]]: ...

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None: ...


_DEFAULT_PROXY_TIMEOUT_SECONDS = 5.0
_DEFAULT_COMPLETION_TIMEOUT_SECONDS = 90.0
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
    if not socket_path.exists():
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
    socket_path = _first_string(payload, _SOCKET_KEYS) or _first_string_from_env(
        env,
        ("CODEX_APP_SERVER_SOCKET", "CODEX_APP_SERVER_CONTROL_SOCKET"),
    )
    if socket_path is not None:
        metadata["codex_app_server_socket"] = socket_path
    codex_home = _first_string(payload, _CODEX_HOME_KEYS) or _first_string_from_env(env, ("CODEX_HOME",))
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
    codex_home = _first_string(metadata, _CODEX_HOME_KEYS)
    socket_path = _first_string(metadata, _SOCKET_KEYS) or str(
        default_codex_app_server_socket_path(environ={"CODEX_HOME": codex_home or ""})
    )
    if not _is_safe_local_socket_path(socket_path):
        return {
            "status": "skipped",
            "reason": "unsafe_socket_path",
            "thread_id": thread_id,
        }
    command_text = _first_string(metadata, _COMMAND_TEXT_KEYS)
    prompt = build_codex_continuation_prompt(action, request_id=request_id, command_text=command_text)
    if not Path(socket_path).expanduser().exists():
        return _resume_codex_thread_with_cli(
            metadata=metadata,
            thread_id=thread_id,
            prompt=prompt,
        )
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
        {"jsonrpc": "2.0", "method": "initialized", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "thread/resume",
            "params": {
                "threadId": thread_id,
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
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
    ready = threading.Event()
    result: dict[str, object] = {}
    worker = threading.Thread(
        target=_send_codex_resume_worker,
        kwargs={
            "socket_path": socket_path,
            "payloads": request_payloads,
            "response_id": 3,
            "thread_id": thread_id,
            "timeout_seconds": timeout_seconds,
            "completion_timeout_seconds": _DEFAULT_COMPLETION_TIMEOUT_SECONDS,
            "ready": ready,
            "result": result,
        },
        name="hol-guard-codex-resume",
        daemon=True,
    )
    worker.start()
    if not ready.wait(timeout_seconds):
        return {
            "status": "failed",
            "reason": "turn_start_timeout",
            "thread_id": thread_id,
        }
    error = result.get("error")
    if isinstance(error, BaseException):
        return {
            "status": "failed",
            "reason": type(error).__name__,
            "thread_id": thread_id,
        }
    response = result.get("response")
    if response is None:
        return {
            "status": "failed",
            "reason": "missing_turn_start_response",
            "thread_id": thread_id,
        }
    if not isinstance(response, dict):
        return {
            "status": "failed",
            "reason": "invalid_turn_start_response",
            "thread_id": thread_id,
        }
    if isinstance(response.get("error"), dict):
        error = response["error"]
        message = error.get("message") if isinstance(error, dict) else None
        return {
            "status": "failed",
            "reason": "turn_start_error",
            "message": str(message) if isinstance(message, str) else "Codex app-server rejected the continuation.",
            "thread_id": thread_id,
        }
    return {
        "status": "sent",
        "reason": "turn_start_sent",
        "thread_id": thread_id,
    }


def _send_codex_resume_worker(
    *,
    socket_path: str,
    payloads: list[dict[str, object]],
    response_id: int,
    thread_id: str,
    timeout_seconds: float,
    completion_timeout_seconds: float,
    ready: threading.Event,
    result: dict[str, object],
) -> None:
    try:
        response, completion_status = _send_app_server_websocket_messages(
            socket_path=socket_path,
            payloads=payloads,
            response_id=response_id,
            timeout_seconds=timeout_seconds,
            completion_thread_id=thread_id,
            completion_timeout_seconds=completion_timeout_seconds,
            ready=ready,
            result=result,
        )
        result["response"] = response
        result["completion_status"] = completion_status
    except (OSError, TimeoutError, ValueError) as error:
        result["error"] = error
    finally:
        ready.set()


def _resume_codex_thread_with_cli(
    *,
    metadata: Mapping[str, object],
    thread_id: str,
    prompt: str,
) -> dict[str, object]:
    """Resume a saved Codex exec thread when the live app-server socket is gone."""

    if not _is_safe_codex_thread_id(thread_id):
        return {
            "status": "skipped",
            "reason": "unsafe_thread_id",
            "thread_id": thread_id,
            "strategy": "codex-headless-exec",
            "supported": False,
        }
    workspace = _first_string(metadata, _WORKSPACE_KEYS)
    if workspace is None:
        return {
            "status": "skipped",
            "reason": "workspace_not_available",
            "thread_id": thread_id,
            "strategy": "codex-headless-exec",
            "supported": False,
        }
    workspace_path = Path(workspace).expanduser()
    if not workspace_path.is_dir():
        return {
            "status": "skipped",
            "reason": "workspace_not_available",
            "thread_id": thread_id,
            "strategy": "codex-headless-exec",
            "supported": False,
        }
    codex_home = _first_string(metadata, _CODEX_HOME_KEYS)
    if codex_home is not None and not Path(codex_home).expanduser().is_dir():
        return {
            "status": "skipped",
            "reason": "codex_home_not_available",
            "thread_id": thread_id,
            "strategy": "codex-headless-exec",
            "supported": False,
        }
    codex_binary = shutil.which("codex")
    if codex_binary is None:
        return {
            "status": "skipped",
            "reason": "codex_binary_not_found",
            "thread_id": thread_id,
            "strategy": "codex-headless-exec",
            "supported": False,
        }
    command = [
        codex_binary,
        "exec",
        "resume",
        "--json",
        "--skip-git-repo-check",
    ]
    model = _first_string(metadata, _MODEL_KEYS)
    if model is not None and _is_safe_codex_model(model):
        command.extend(["--model", model])
    command.append("--")
    command.extend([thread_id, prompt])
    env = os.environ.copy()
    if codex_home is not None:
        env["CODEX_HOME"] = str(Path(codex_home).expanduser())
    try:
        process = subprocess.Popen(
            command,
            cwd=workspace_path,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as error:
        return {
            "status": "failed",
            "reason": "headless_resume_launch_failed",
            "last_error": str(error),
            "thread_id": thread_id,
            "strategy": "codex-headless-exec",
            "supported": True,
        }
    return {
        "status": "sent",
        "reason": "headless_resume_started",
        "thread_id": thread_id,
        "strategy": "codex-headless-exec",
        "supported": True,
        "pid": process.pid,
    }


def _find_codex_operation_for_request(store: _OperationStore, request_id: str) -> dict[str, object] | None:
    operation = store.get_guard_operation_for_approval_request(request_id)
    if operation is not None and str(operation.get("harness")) == "codex":
        return operation
    for operation in store.list_guard_operations(limit=1000):
        if str(operation.get("harness")) != "codex":
            continue
        request_ids = operation.get("approval_request_ids")
        if isinstance(request_ids, list) and request_id in {str(item) for item in request_ids}:
            return operation
    return None


def build_codex_continuation_prompt(action: str, *, request_id: str, command_text: str | None = None) -> str:
    if action == "allow":
        if command_text is not None:
            return (
                f"HOL Guard approved request `{request_id}` for this exact command:\n"
                f"{command_text}\n"
                "Retry that exact command now using the existing saved approval."
            )
        return (
            f"HOL Guard approved request `{request_id}`. "
            "Retry the blocked action now using the existing saved approval."
        )
    if command_text is not None:
        return (
            f"HOL Guard blocked request `{request_id}` for this exact command:\n"
            f"{command_text}\n"
            "Do not retry it. Explain a safe alternative."
        )
    return f"HOL Guard blocked request `{request_id}`. Do not retry that action. Explain a safe alternative."


def _send_app_server_websocket_messages(
    *,
    socket_path: str,
    payloads: list[dict[str, object]],
    response_id: int,
    timeout_seconds: float,
    completion_thread_id: str | None = None,
    completion_timeout_seconds: float | None = None,
    ready: threading.Event | None = None,
    result: dict[str, object] | None = None,
) -> tuple[dict[str, object] | None, str]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout_seconds)
        client.connect(str(Path(socket_path).expanduser()))
        pending = bytearray(_send_websocket_handshake(client))
        for payload in payloads:
            _send_websocket_text(client, json.dumps(payload, separators=(",", ":")))
        response: dict[str, object] | None = None
        response_deadline = time.monotonic() + timeout_seconds
        completion_deadline = time.monotonic() + (completion_timeout_seconds or timeout_seconds)
        client.settimeout(1.0)
        while True:
            now = time.monotonic()
            if response is None and now >= response_deadline:
                raise TimeoutError("turn_start_timeout")
            if response is not None and completion_thread_id is not None and now >= completion_deadline:
                return response, "completion_timeout"
            try:
                opcode, payload = _read_websocket_frame(client, pending)
            except _WebSocketClosedError:
                if response is not None:
                    return response, "socket_closed"
                raise
            except TimeoutError:
                if response is None:
                    if time.monotonic() >= response_deadline:
                        raise
                    continue
                if response is not None and completion_thread_id is not None:
                    if time.monotonic() >= completion_deadline:
                        return response, "completion_timeout"
                    continue
                raise
            if opcode == 0x8:
                return response, "socket_closed"
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
                response = message
                if result is not None:
                    result["response"] = message
                if ready is not None:
                    ready.set()
                if isinstance(message.get("error"), dict) or completion_thread_id is None:
                    return message, "turn_start_response"
                continue
            if (
                response is not None
                and completion_thread_id is not None
                and _is_thread_completion_message(
                    message,
                    completion_thread_id,
                )
            ):
                return response, _completion_status(message)
    return None, "socket_closed"


def _is_thread_completion_message(message: object, thread_id: str) -> bool:
    if not isinstance(message, dict):
        return False
    method = message.get("method")
    params = message.get("params")
    if not isinstance(params, dict) or params.get("threadId") != thread_id:
        return False
    if method == "turn/completed":
        return True
    if method == "thread/status/changed":
        status = params.get("status")
        return isinstance(status, dict) and status.get("type") == "idle"
    return False


def _completion_status(message: object) -> str:
    if not isinstance(message, Mapping):
        return "completed"
    method = message.get("method")
    if method == "turn/completed":
        return "turn_completed"
    if method == "thread/status/changed":
        return "thread_idle"
    return "completed"


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
    response, leftover = _recv_until(client, b"\r\n\r\n")
    header_text = response.decode("iso-8859-1", errors="replace")
    if not header_text.startswith("HTTP/1.1 101"):
        raise ValueError("websocket_upgrade_failed")
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
    mask = _recv_exact(client, 4, pending) if second & 0x80 else None
    payload = _recv_exact(client, length, pending) if length else b""
    if mask is not None:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def _recv_until(client: socket.socket, marker: bytes) -> tuple[bytes, bytes]:
    data = b""
    while marker not in data:
        chunk = client.recv(4096)
        if not chunk:
            raise _WebSocketClosedError("socket_closed")
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


def _is_safe_codex_thread_id(thread_id: str) -> bool:
    return (
        0 < len(thread_id) <= 256
        and not thread_id.startswith("-")
        and all(char.isalnum() or char in "-_" for char in thread_id)
    )


def _is_safe_codex_model(model: str) -> bool:
    return (
        0 < len(model) <= 128
        and not model.startswith("-")
        and bool(model.strip())
        and all(char.isalnum() or char in "-_.:" for char in model)
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
