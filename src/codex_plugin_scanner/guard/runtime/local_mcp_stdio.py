"""Stdio JSON-RPC exchange for MCP initialize + tools/list probes."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TypeGuard

_PROTOCOL = "2024-11-05"
MCP_PROBE_TIMEOUT_SECONDS = 6.0
MCP_PACKAGE_PROBE_TIMEOUT_SECONDS = 20.0
MCP_PROBE_OUTPUT_LIMIT = 1_000_000
MAX_MCP_PROBE_TOOLS = 80
_PROBE_ENV_LOCKED = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONBREAKPOINT",
        "__PYVENV_LAUNCHER__",
    }
)


def run_mcp_tools_list(
    argv: Sequence[str],
    *,
    timeout: float = MCP_PROBE_TIMEOUT_SECONDS,
    extra_env: Mapping[str, str] | None = None,
) -> list[dict[str, object]] | None:
    """Run initialize + tools/list against argv and return tool objects."""

    if not argv or any(not part or "\x00" in part for part in argv):
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="hol-guard-mcp-probe-") as tmp:
            return _exchange_tools_list(list(argv), tmp, timeout=timeout, extra_env=extra_env)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError, UnicodeError):
        return None


def probe_search_path() -> str:
    """PATH for MCP probes, without Guard package-shim wrappers."""

    fallback = os.environ.get("PATH", "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin")
    filtered = [entry for entry in fallback.split(os.pathsep) if entry and not _is_package_shim_dir(entry)]
    for extra in ("/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"):
        if extra not in filtered and Path(extra).is_dir():
            filtered.append(extra)
    return os.pathsep.join(filtered)


def is_package_shim_executable(path: str) -> bool:
    candidate = Path(path)
    parent = candidate.parent
    return parent.name == "bin" and parent.parent.name == "package-shims"


def _is_package_shim_dir(entry: str) -> bool:
    path = Path(entry)
    return path.name == "bin" and path.parent.name == "package-shims"


def probe_env(tmp: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": probe_search_path(),
        "HOME": tmp,
        "TMPDIR": tmp,
        "LANG": "C",
        "LC_ALL": "C",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "npm_config_update_notifier": "false",
        "npm_config_fund": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "npm_config_loglevel": "error",
    }
    env.update(_package_cache_env())
    if os.name == "nt":
        system_root = os.environ.get("SYSTEMROOT")
        if system_root:
            env["SYSTEMROOT"] = system_root
    if extra:
        for key, value in extra.items():
            name = key.strip()
            if not name or name.upper() in _PROBE_ENV_LOCKED:
                continue
            if "=" in name or "\x00" in name or "\x00" in value:
                continue
            env[name] = value
    return env


def _package_cache_env() -> dict[str, str]:
    extra: dict[str, str] = {}
    home = os.environ.get("HOME")
    npm_cache = _configured_cache("NPM_CONFIG_CACHE", "npm_config_cache")
    if not npm_cache and home:
        candidate = Path(home) / ".npm"
        if candidate.is_dir():
            npm_cache = str(candidate)
    if npm_cache:
        extra["npm_config_cache"] = npm_cache
        extra["NPM_CONFIG_CACHE"] = npm_cache
    uv_cache = _configured_cache("UV_CACHE_DIR")
    if not uv_cache and home:
        candidate = Path(home) / ".cache" / "uv"
        if candidate.is_dir():
            uv_cache = str(candidate)
    if uv_cache:
        extra["UV_CACHE_DIR"] = uv_cache
    bun_cache = _configured_cache("BUN_INSTALL_CACHE_DIR")
    if not bun_cache and home:
        candidate = Path(home) / ".bun" / "install" / "cache"
        if candidate.is_dir():
            bun_cache = str(candidate)
    if bun_cache:
        extra["BUN_INSTALL_CACHE_DIR"] = bun_cache
    return extra


def _configured_cache(*keys: str) -> str | None:
    raw = _first_env(*keys)
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    path = Path(stripped)
    if path.is_absolute():
        return stripped
    return str((Path.cwd() / path).resolve())


def _first_env(*keys: str) -> str | None:
    for key in keys:
        value = os.environ.get(key)
        if value:
            return value
    return None


def _exchange_tools_list(
    argv: list[str],
    tmp: str,
    *,
    timeout: float,
    extra_env: Mapping[str, str] | None = None,
) -> list[dict[str, object]] | None:
    process = subprocess.Popen(
        argv,
        cwd=tmp,
        env=probe_env(tmp, extra_env),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    session = _RpcSession(process)
    deadline = time.monotonic() + max(timeout, 0.05)
    try:
        session.write({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": _initialize_params()})
        initialize = _await_result(session, 1, deadline)
        if initialize is None or initialize.get("error") is not None:
            return None
        session.write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        collected: list[dict[str, object]] = []
        cursor: str | None = None
        request_id = 2
        for _ in range(8):
            params: dict[str, object] = {} if cursor is None else {"cursor": cursor}
            session.write({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params})
            listed = _await_result(session, request_id, deadline)
            if listed is None or listed.get("error") is not None:
                return None
            result = listed.get("result")
            if not isinstance(result, dict):
                return None
            tools = result.get("tools")
            if not isinstance(tools, list):
                return None
            collected.extend(item for item in tools if isinstance(item, dict))
            if len(collected) >= MAX_MCP_PROBE_TOOLS:
                return collected[:MAX_MCP_PROBE_TOOLS]
            next_cursor = result.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor.strip():
                return collected
            cursor = next_cursor.strip()
            request_id += 1
        return collected
    finally:
        _stop(process, session)


def _initialize_params() -> dict[str, object]:
    return {
        "protocolVersion": _PROTOCOL,
        "capabilities": {"roots": {"listChanged": False}},
        "clientInfo": {"name": "hol-guard", "version": "3.0"},
    }


def _await_result(session: _RpcSession, request_id: int, deadline: float) -> dict[str, object] | None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        message = session.read(timeout=remaining)
        if message is None:
            return None
        if message.get("id") == request_id:
            return message
        _reply_server_request(session, message)


def _reply_server_request(session: _RpcSession, message: dict[str, object]) -> None:
    method = message.get("method")
    req_id = message.get("id")
    if not isinstance(method, str) or req_id is None or "result" in message or "error" in message:
        return
    if method == "roots/list":
        session.write({"jsonrpc": "2.0", "id": req_id, "result": {"roots": []}})
        return
    if method == "ping":
        session.write({"jsonrpc": "2.0", "id": req_id, "result": {}})
        return
    session.write({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}})


class _RpcSession:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self._buffer = b""
        self._messages: list[dict[str, object]] = []
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._eof = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def write(self, message: dict[str, object]) -> None:
        stdin = self._process.stdin
        if stdin is None:
            return
        payload = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        with contextlib.suppress(OSError, ValueError):
            _ = os.write(stdin.fileno(), payload)

    def read(self, *, timeout: float) -> dict[str, object] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._messages:
                    return self._messages.pop(0)
            if self._process.poll() is not None and self._eof.is_set():
                with self._lock:
                    return self._messages.pop(0) if self._messages else None
            time.sleep(0.01)
        return None

    def close(self) -> None:
        self._closed.set()
        stdout = self._process.stdout
        if stdout is not None:
            with contextlib.suppress(OSError):
                stdout.close()
        self._thread.join(1)

    def _drain(self) -> None:
        try:
            self._drain_stream()
        finally:
            self._eof.set()

    def _drain_stream(self) -> None:
        stdout = self._process.stdout
        if stdout is None:
            return
        fd = stdout.fileno()
        while not self._closed.is_set():
            try:
                chunk = os.read(fd, 8192)
            except OSError:
                return
            if chunk == b"":
                return
            with self._lock:
                self._buffer += chunk
                while True:
                    parsed = _pop_json_message(self._buffer)
                    if parsed is None:
                        break
                    message, rest = parsed
                    self._buffer = rest
                    if _is_rpc_message(message):
                        self._messages.append(message)
                if len(self._buffer) > MCP_PROBE_OUTPUT_LIMIT:
                    self._buffer = b""
                    return


def _is_rpc_message(message: dict[str, object] | None) -> TypeGuard[dict[str, object]]:
    if message is None:
        return False
    if "result" in message or "error" in message:
        return True
    return "method" in message and "id" in message


def _pop_json_message(buffer: bytes) -> tuple[dict[str, object] | None, bytes] | None:
    if buffer.startswith(b"Content-Length:"):
        header, sep, rest = buffer.partition(b"\r\n\r\n")
        if not sep:
            header, sep, rest = buffer.partition(b"\n\n")
        if not sep:
            return None
        try:
            length = int(header.split(b":", 1)[1].strip().splitlines()[0])
        except ValueError:
            return None
        if length > MCP_PROBE_OUTPUT_LIMIT:
            return (None, b"")
        if len(rest) < length:
            return None
        try:
            payload = json.loads(rest[:length].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return (None, rest[length:])
        return (payload if isinstance(payload, dict) else None, rest[length:])
    line, sep, rest = buffer.partition(b"\n")
    if not sep:
        return None
    stripped = line.strip()
    if not stripped:
        return _pop_json_message(rest) if rest else None
    try:
        payload = json.loads(stripped.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return (None, rest)
    return (payload if isinstance(payload, dict) else None, rest)


def _stop(process: subprocess.Popen[bytes], session: _RpcSession | None = None) -> None:
    if session is not None:
        session.close()
    if process.poll() is not None:
        return
    try:
        if os.name != "nt" and process.pid:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except (ProcessLookupError, PermissionError, OSError):
            return
    with contextlib.suppress(subprocess.TimeoutExpired):
        _ = process.wait(timeout=1)
