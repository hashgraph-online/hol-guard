"""MCP tools the native runtime serves.

The runtime owns their names, descriptions, schemas, the private pairing
session and every result. This module starts one ``hol-guard-runtime
context-mcp`` process for the MCP server's life and carries JSON lines to and
from it; it never reads a tool's meaning or sees the pairing credential.

The process holds the resident up while it runs, so the memory-only pairing
survives between calls. Once it has been asked for tools or a call it may have
begun a pairing, so it is never replaced: a lost pairing needs a fresh MCP
process and a person to pair it again.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import IO, Any

FEATURE = "native-context-cli-v1"
_COMMAND = "context-mcp"
_TIMEOUT_SECONDS = 30.0
_CLOSE_SECONDS = 2.0
_RETRY_SECONDS = 30.0
_PAIRING_OPS = frozenset({"tools", "call"})
_UNAVAILABLE = {
    "ok": False,
    "error": {"code": "native_runtime_unavailable", "message": "Guard's native runtime is unavailable."},
}


def _read_lines(stream: IO[bytes], replies: queue.Queue[bytes | None]) -> None:
    for line in iter(stream.readline, b""):
        replies.put(line)
    replies.put(None)


class NativeToolSession:
    """One MCP process's native tools, served by one runtime process."""

    def __init__(self, guard_home: Path) -> None:
        self._home = guard_home
        self._process: subprocess.Popen[bytes] | None = None
        self._replies: queue.Queue[bytes | None] = queue.Queue()
        self._spent = False
        self._retry_at = 0.0
        self._catalog: list[dict[str, Any]] | None = None
        self._lock = threading.RLock()

    def _start(self) -> bool:
        if self._process is not None:
            return True
        if self._spent or time.monotonic() < self._retry_at:
            return False
        from ..native_context import ensure_resident_prerequisite
        from ..native_recovery_store import recovery_runtime_path

        try:
            if not ensure_resident_prerequisite(self._home):
                raise RuntimeError("prerequisite")
            process = subprocess.Popen(
                [recovery_runtime_path(FEATURE), _COMMAND, "--guard-home", str(self._home)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, RuntimeError, ValueError):
            self._retry_at = time.monotonic() + _RETRY_SECONDS
            return False
        self._replies = queue.Queue()
        assert process.stdout is not None
        threading.Thread(target=_read_lines, args=(process.stdout, self._replies), daemon=True).start()
        self._process = process
        return True

    def _stop(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        try:
            process.kill()
            process.wait(timeout=_CLOSE_SECONDS)
        except (OSError, subprocess.SubprocessError):
            pass

    def _send(self, message: dict[str, object]) -> dict[str, Any] | None:
        with self._lock:
            if not self._start():
                return None
            process = self._process
            assert process is not None and process.stdin is not None
            if message.get("op") in _PAIRING_OPS:
                self._spent = True
            try:
                process.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
                process.stdin.flush()
                line = self._replies.get(timeout=_TIMEOUT_SECONDS)
                answer = json.loads(line) if line is not None else None
            except (OSError, ValueError, queue.Empty):
                answer = None
            if not isinstance(answer, dict):
                self._stop()
                return None
            return answer

    def catalog(self) -> list[dict[str, Any]]:
        """Every tool the runtime can serve, whether or not it is allowed now."""
        with self._lock:
            if self._catalog is None:
                answer = self._send({"op": "catalog"})
                tools = answer.get("tools") if answer is not None else None
                if not isinstance(tools, list):
                    return []
                self._catalog = [tool for tool in tools if isinstance(tool, dict)]
            return self._catalog

    def names(self) -> frozenset[str]:
        return frozenset(str(tool.get("name")) for tool in self.catalog())

    def allowed(self) -> list[dict[str, Any]]:
        """The tools this connection may use now."""
        answer = self._send({"op": "tools"})
        tools = answer.get("tools") if answer is not None else None
        return [tool for tool in tools if isinstance(tool, dict)] if isinstance(tools, list) else []

    def call(self, name: str, arguments: dict[str, object]) -> str:
        """The tool's text result, passed through as the runtime wrote it."""
        answer = self._send({"op": "call", "name": name, "arguments": arguments})
        text = answer.get("text") if answer is not None else None
        if isinstance(text, str):
            return text
        return json.dumps(_UNAVAILABLE, separators=(",", ":"))

    def close(self) -> None:
        """End the pairing and let the runtime process exit."""
        with self._lock:
            process, self._process = self._process, None
            self._spent = True
            if process is None or process.stdin is None:
                return
            try:
                process.stdin.write(b'{"op":"close"}\n')
                process.stdin.flush()
                process.stdin.close()
                process.wait(timeout=_CLOSE_SECONDS)
            except (OSError, ValueError, subprocess.SubprocessError):
                process.kill()
