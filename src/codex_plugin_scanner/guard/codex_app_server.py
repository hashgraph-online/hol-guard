"""Codex app-server continuation helpers for Guard approval resolution."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol


class _OperationStore(Protocol):
    def list_guard_operations(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, object]]: ...


_DEFAULT_PROXY_TIMEOUT_SECONDS = 5.0
_DEFAULT_SOCKET_PATH = Path.home() / ".codex" / "app-server-control" / "app-server-control.sock"
_APP_BUNDLE_CODEX = Path("/Applications/Codex.app/Contents/Resources/codex")
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
    proxy_command: list[str] | None = None,
    environ: Mapping[str, str] | None = None,
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
    command = proxy_command or _default_proxy_command(socket_path, environ=environ)
    if command is None:
        return {
            "status": "skipped",
            "reason": "codex_command_not_found",
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
    input_bytes = "".join(json.dumps(payload, separators=(",", ":")) + "\n" for payload in request_payloads).encode(
        "utf-8"
    )
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "status": "failed",
            "reason": type(error).__name__,
            "thread_id": thread_id,
            "socket_path": socket_path,
        }
    response = _parse_jsonrpc_response(completed.stdout.decode("utf-8", errors="replace"))
    if completed.returncode != 0:
        return {
            "status": "failed",
            "reason": "proxy_failed",
            "thread_id": thread_id,
            "socket_path": socket_path,
            "returncode": completed.returncode,
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


def _default_proxy_command(socket_path: str, *, environ: Mapping[str, str] | None) -> list[str] | None:
    env = environ or os.environ
    configured = env.get("HOL_GUARD_CODEX_COMMAND")
    if configured:
        command_path = configured
    else:
        command_path = shutil.which("codex") or (str(_APP_BUNDLE_CODEX) if _APP_BUNDLE_CODEX.exists() else "")
    if not command_path:
        return None
    return [command_path, "app-server", "proxy", "--sock", socket_path]


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


def _parse_jsonrpc_response(stdout: str) -> dict[str, object] | None:
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("id") == 2:
            return payload
    return None


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
