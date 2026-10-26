"""Native MCP stdio session child transport adapters (RTM-022/023).

``_NativeMcpChildIo`` quacks like the pipe pair the proxy relay drives:
``write``/``flush`` frame a client→child message via ``send``; ``next_frame``
surfaces the next inbound child event via ``recv``; ``exchange`` rides the
fused quiet-edge/write/response op. ``_NativeChildProcess`` wraps that
transport in a ``Popen``-shaped lifecycle. The resident owns the real
subprocess, newline framing, correlation, and teardown; these adapters only
marshal frames.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from ..native_execution import (
    mcp_stdio_session_close_native,
    mcp_stdio_session_recv_native,
    mcp_stdio_session_send_native,
)
from ..native_mcp_stdio_exchange import mcp_stdio_session_exchange_native
from .stdio import ProxyIoTimeoutError


@dataclass(frozen=True, slots=True)
class _ChildOutputFrame:
    line: str | None = None
    error: BaseException | None = None


class _NativeMcpChildIo:
    """Child-side transport over the native MCP stdio session ops (RTM-022/023).

    Quacks like the pipe pair ``_forward_message``/``_drain_child_messages``
    use: ``write``/``flush`` frame a client→child message via ``send``;
    ``next_frame`` surfaces the next inbound child event via ``recv``. The
    resident owns the subprocess, newline framing, correlation, and teardown;
    this adapter only marshals frames. Returned ``line`` values are re-parsed
    by the relay so the existing catalog-poison/quarantine gate is preserved.
    """

    def __init__(self, session_id: str, guard_home: Path) -> None:
        self._session_id = session_id
        self._guard_home = guard_home
        self._pending: deque[str] = deque()
        self._injected: deque[_ChildOutputFrame] = deque()
        self.exit_code: int | None = None

    # stdin side ------------------------------------------------------------
    def write(self, data: str) -> int:
        """Accept a ``json.dumps(message) + "\\n"`` write like a text pipe."""
        text = data.rstrip("\n")
        try:
            message = json.loads(text)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise RuntimeError("native MCP session received a non-JSON frame") from exc
        result = mcp_stdio_session_send_native(self._session_id, message, guard_home=self._guard_home)
        if result is None or result.get("status") != "sent":
            raise RuntimeError("native MCP session send failed")
        return len(data)

    def flush(self) -> None:  # resident op is already synchronous/flushed
        return None

    def idle(self) -> bool:
        """No locally queued frame is waiting to be delivered."""
        return not self._pending and not self._injected

    def exchange(
        self,
        message: Mapping[str, object],
        *,
        quiet_seconds: float,
        response_timeout_seconds: float,
    ) -> dict[str, Any] | bool:
        """Quiet edge, write and response in one resident round trip.

        Returns the correlated response, or whether ``message`` was written.
        Whatever else the child said is queued so the relay reads it exactly as
        it would have read it from separate ``send`` and ``recv`` calls.
        """
        outcome = mcp_stdio_session_exchange_native(
            self._session_id,
            message,
            guard_home=self._guard_home,
            quiet_seconds=quiet_seconds,
            response_timeout_seconds=response_timeout_seconds,
        )
        if outcome is None:
            raise RuntimeError("native MCP session exchange failed")
        kind = outcome["outcome"]
        written = outcome.get("written") is True
        frame = outcome.get("frame")
        if kind == "response" and isinstance(frame, dict):
            return cast("dict[str, Any]", frame)
        if kind in {"boundary", "event"} and frame is not None:
            self._pending.append(json.dumps(frame) + "\n")
        elif kind == "timeout":
            self._injected.append(
                _ChildOutputFrame(
                    error=ProxyIoTimeoutError(source="child_response", timeout_seconds=response_timeout_seconds)
                )
            )
        elif kind == "eof" and written:
            code = outcome.get("exit_code")
            if isinstance(code, int) and not isinstance(code, bool):
                self.exit_code = code
            self._injected.append(_ChildOutputFrame())
        return written

    def writelines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.write(line)

    def close(self) -> None:
        mcp_stdio_session_close_native(self._session_id, guard_home=self._guard_home)

    # stdout side -----------------------------------------------------------
    def next_frame(self, timeout_seconds: float, required: bool) -> _ChildOutputFrame | None:
        # Test/injection seam: locally-queued frames are delivered before the
        # resident so callers can synthesize inbound child events (e.g.
        # `tools/list_changed`) without a native inject op.
        if self._injected:
            return self._injected.popleft()
        if self._pending:
            return _ChildOutputFrame(line=self._pending.popleft())
        result = mcp_stdio_session_recv_native(
            self._session_id,
            guard_home=self._guard_home,
            timeout_seconds=timeout_seconds,
        )
        if result is None:
            return _ChildOutputFrame(error=RuntimeError("native MCP session recv transport failure"))
        status = str(result.get("status", ""))
        if status == "event":
            payload = result.get("payload")
            return _ChildOutputFrame(line=json.dumps(payload) + "\n")
        if status in {"exited", "eof"}:
            code = result.get("exit_code")
            if isinstance(code, int) and not isinstance(code, bool):
                self.exit_code = code
            return _ChildOutputFrame()
        if status == "timeout":
            if required:
                return _ChildOutputFrame(
                    error=ProxyIoTimeoutError(source="child_response", timeout_seconds=timeout_seconds)
                )
            return None
        # "error" status — surface as a frame error so the relay fails closed.
        code = result.get("payload")
        return _ChildOutputFrame(error=RuntimeError(f"native MCP session error: {code}"))

    def readline(self) -> str:  # pragma: no cover - compatibility sink
        return ""


class _NativeChildProcess:
    """Popen-shaped adapter over a resident-owned MCP stdio session.

    ``serve``/``run_session`` only touch ``stdin``/``stdout``/teardown; the
    resident owns the real subprocess, so ``stdin``/``stdout`` share one
    ``_NativeMcpChildIo`` transport and lifecycle calls delegate to ``close``.
    ``returncode`` is available after the resident reports child exit; clean
    close returns ``0`` and quarantine/cancel returns ``-9``.
    """

    def __init__(self, session_id: str, guard_home: Path) -> None:
        self._session_id = session_id
        self._guard_home = guard_home
        io = _NativeMcpChildIo(session_id, guard_home)
        self.stdin: _NativeMcpChildIo = io
        self.stdout: _NativeMcpChildIo = io
        self.stderr = None
        self._closed = False
        self._cancelled = False
        self._returncode: int | None = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        mcp_stdio_session_close_native(self._session_id, guard_home=self._guard_home)

    def terminate(self) -> None:
        self.close()

    def kill(self) -> None:
        self._cancelled = True
        self.close()

    def poll(self) -> int | None:
        if self._returncode is not None:
            return self._returncode
        if self.stdin.exit_code is not None:
            self._returncode = self.stdin.exit_code
            return self._returncode
        if self._cancelled:
            return -9
        if self._closed:
            return 0
        result = mcp_stdio_session_recv_native(
            self._session_id,
            guard_home=self._guard_home,
            timeout_seconds=1.0,
            poll_only=True,
        )
        if result is not None and result.get("status") == "exited":
            exit_code = result.get("exit_code")
            self._returncode = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else -1
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        self.close()
        returncode = self.returncode
        if returncode is None:
            raise RuntimeError("Native MCP session closed without an exit status.")
        return returncode

    @property
    def returncode(self) -> int | None:
        return self.poll()
