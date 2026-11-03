"""Helpers the runtime MCP proxy shares for stdio child I/O and timeout responses."""

from __future__ import annotations

import io
import queue
import select
import threading
from collections.abc import Mapping
from contextlib import suppress
from typing import Any, Protocol

_PROXY_TERMINATION_TIMEOUT_SECONDS = 1.0
_GUARD_PROXY_TIMEOUT_ERROR_CODE = -32800


def _approval_surface_policy_for_browser(configured_policy: object, approval_flow: Mapping[str, object]) -> str:
    if approval_flow.get("tier") != "approval-center":
        return "notify-only"
    if approval_flow.get("auto_open_browser") is False:
        return "never-auto-open"
    policy = str(configured_policy or "auto-open-once")
    if policy == "native-only":
        return "never-auto-open"
    return policy


class ProxyIoTimeoutError(TimeoutError):
    def __init__(self, *, source: str, timeout_seconds: float) -> None:
        super().__init__(f"timeout waiting for {source}")
        self.source = source
        self.timeout_seconds = timeout_seconds


def _redact_json(value: Any) -> Any:
    """Redact recorded traffic for display; native authority only.

    The resident `mcp_redact_json` op owns the scalar/query/map-key fragment
    tables. A native failure is terminal — silent Python fallback could persist
    secrets unredacted.
    """
    from ..native_context import context_mcp_redact_json

    return context_mcp_redact_json(value)


def _blocked_tool_response(
    message_id: Any,
    tool_name: str,
    reason: str | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": -32001,
            "message": reason or f"Guard blocked tool call for {tool_name}.",
        },
    }
    if data:
        payload["error"]["data"] = data
    return payload


def _timeout_response(
    message_id: Any,
    *,
    source: str,
    timeout_seconds: float,
    message: str,
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": _GUARD_PROXY_TIMEOUT_ERROR_CODE,
            "message": message,
            "data": {
                "guard_timeout": True,
                "source": source,
                "timeout_seconds": timeout_seconds,
            },
        },
    }


def _is_timeout_response(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    error = payload.get("error")
    if not isinstance(error, dict):
        return False
    data = error.get("data")
    return (
        error.get("code") == _GUARD_PROXY_TIMEOUT_ERROR_CODE
        and isinstance(data, dict)
        and data.get("guard_timeout") is True
    )


def _stream_fileno(stream: Any) -> int | None:
    try:
        fileno = stream.fileno()
    except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
        return None
    return fileno if isinstance(fileno, int) and fileno >= 0 else None


def _readline_with_timeout(
    stream: Any,
    timeout_seconds: float,
    *,
    source: str,
    allow_background_wait: bool = True,
) -> str:
    fileno = None if allow_background_wait else _stream_fileno(stream)
    if fileno is not None:
        try:
            ready, _, _ = select.select([fileno], [], [], timeout_seconds)
        except (OSError, ValueError) as exc:
            raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds) from exc
        if not ready:
            raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds)
        return stream.readline()
    if not allow_background_wait:
        if isinstance(stream, io.StringIO):
            return stream.readline()
        raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds)
    result_queue: queue.Queue[tuple[bool, str | BaseException]] = queue.Queue(maxsize=1)

    def _reader() -> None:
        try:
            result_queue.put((True, stream.readline()))
        except BaseException as exc:  # pragma: no cover - surfaced through queue
            result_queue.put((False, exc))

    threading.Thread(target=_reader, daemon=True).start()
    try:
        ok, result = result_queue.get(timeout=timeout_seconds)
    except queue.Empty as exc:
        raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds) from exc
    if ok:
        return result if isinstance(result, str) else ""
    if isinstance(result, BaseException):
        raise result
    raise RuntimeError("guard_proxy_io_failed")


class _ChildLifecycle(Protocol):
    """Lifecycle operations shared by native sessions and stdio children."""

    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...


def _quarantine_process(process: _ChildLifecycle) -> None:
    if process.poll() is not None:
        return
    with suppress(Exception):
        process.terminate()
    try:
        process.wait(timeout=_PROXY_TERMINATION_TIMEOUT_SECONDS)
        return
    except Exception:
        pass
    with suppress(Exception):
        process.kill()
    with suppress(Exception):
        process.wait(timeout=_PROXY_TERMINATION_TIMEOUT_SECONDS)
