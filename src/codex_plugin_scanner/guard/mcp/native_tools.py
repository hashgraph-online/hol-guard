"""MCP tools the native runtime serves.

The runtime owns their names, descriptions, schemas, the private pairing
session and every result. This module only carries JSON between the MCP
server and ``hol-guard-runtime <command>``; it never reads a tool's meaning.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from threading import RLock
from typing import Any

FEATURE = "native-context-cli-v1"
_TIMEOUT_SECONDS = 30.0
_UNAVAILABLE = {
    "ok": False,
    "error": {"code": "native_runtime_unavailable", "message": "Guard's native runtime is unavailable."},
}


class NativeToolSession:
    """One MCP process's native tools and the opaque session they share."""

    def __init__(self, guard_home: Path, command: str = "context-mcp") -> None:
        self._home = guard_home
        self._command = command
        self._session: object = None
        self._catalog: list[dict[str, Any]] | None = None
        self._lock = RLock()

    def _send(self, request: dict[str, object]) -> dict[str, Any] | None:
        from ..native_recovery_store import recovery_runtime_path

        try:
            completed = subprocess.run(
                [recovery_runtime_path(FEATURE), self._command, "--guard-home", str(self._home)],
                input=json.dumps(request).encode("utf-8"),
                capture_output=True,
                timeout=_TIMEOUT_SECONDS,
                check=False,
            )
            answer = json.loads(completed.stdout) if completed.returncode == 0 else None
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            return None
        return answer if isinstance(answer, dict) else None

    def _exchange(self, request: dict[str, object]) -> dict[str, Any] | None:
        answer = self._send({**request, "session": self._session})
        if answer is not None and "session" in answer:
            self._session = answer["session"]
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
        with self._lock:
            answer = self._exchange({"op": "tools"})
            tools = answer.get("tools") if answer is not None else None
            return [tool for tool in tools if isinstance(tool, dict)] if isinstance(tools, list) else []

    def call(self, name: str, arguments: dict[str, object]) -> str:
        """The tool's text result, passed through as the runtime wrote it."""
        with self._lock:
            answer = self._exchange({"op": "call", "name": name, "arguments": arguments})
            text = answer.get("text") if answer is not None else None
            if isinstance(text, str):
                return text
            return json.dumps(_UNAVAILABLE, separators=(",", ":"))

    def close(self) -> None:
        with self._lock:
            if self._session is not None:
                self._exchange({"op": "close"})
