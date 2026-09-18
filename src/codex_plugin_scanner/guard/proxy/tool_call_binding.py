"""Private immutable wire intent for one admitted MCP tool request."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, cast

from . import framing


class _UnsupportedPlainJsonError(ValueError):
    """An intentional unsupported-input decision, never a failed capture."""


def changed_tool_call() -> framing.ProxyIoLimitError:
    return framing.ProxyIoLimitError(source="tool_call_binding", reason="tool_call_request_changed")


def require_tool_call_method(message: dict[str, Any]) -> None:
    # The caller's immutable authority tuple selects this check. Never consult
    # a mutable method to decide whether a tool request needs a bound writer.
    method = dict.get(message, "method")
    if type(method) is not str or method != "tools/call":
        raise changed_tool_call()


def _own_plain_json(value: object) -> object:
    kind = type(value)
    if value is None or kind is bool or kind is str or kind is int:
        return value
    if kind is float and math.isfinite(cast(float, value)):
        return value
    if kind is list:
        return [_own_plain_json(item) for item in cast(list[object], value)]
    if kind is dict:
        result: dict[str, object] = {}
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise _UnsupportedPlainJsonError("tool_call_binding_requires_plain_json")
            result[cast(str, key)] = _own_plain_json(item)
        return result
    raise _UnsupportedPlainJsonError("tool_call_binding_requires_plain_json")


def _json_parts(value: object) -> Iterator[bytes]:
    """Compare the standard compact wire encoding without building another frame.

    Dispatch on exact types before any iteration or scalar conversion. This
    prevents caller-defined callbacks during checks of a mutated request.
    """

    kind = type(value)
    if value is None:
        yield b"null"
    elif kind is bool:
        yield b"true" if value else b"false"
    elif kind is str:
        yield json.dumps(value, ensure_ascii=False).encode("utf-8")
    elif kind is int:
        yield str(value).encode("ascii")
    elif kind is float and math.isfinite(cast(float, value)):
        yield repr(value).encode("ascii")
    elif kind is list:
        yield b"["
        for index, item in enumerate(cast(list[object], value)):
            if index:
                yield b","
            yield from _json_parts(item)
        yield b"]"
    elif kind is dict:
        yield b"{"
        for index, (key, item) in enumerate(cast(dict[object, object], value).items()):
            if type(key) is not str:
                raise ValueError("tool_call_binding_requires_plain_json")
            if index:
                yield b","
            yield json.dumps(key, ensure_ascii=False).encode("utf-8")
            yield b":"
            yield from _json_parts(item)
        yield b"}"
    else:
        raise ValueError("tool_call_binding_requires_plain_json")


def _matches_frame(value: object, frame: bytes) -> bool:
    if type(frame) is not bytes or len(frame) > framing.MAX_LINE_BYTES or not frame.endswith(b"\n"):
        return False
    position = 0
    try:
        for part in _json_parts(value):
            if not frame.startswith(part, position):
                return False
            position += len(part)
    except (TypeError, ValueError, UnicodeError, RecursionError, RuntimeError):
        return False
    return position == len(frame) - 1


@dataclass(frozen=True, repr=False, slots=True)
class ToolCallBinding:
    live_message: dict[str, Any]
    owned_message: dict[str, Any]
    frame: bytes = field(repr=False)
    parent: ToolCallBinding | None = field(default=None, repr=False)

    def check(self) -> None:
        if self.parent is not None:
            self.parent.check()
        if not _matches_frame(self.live_message, self.frame) or not _matches_frame(self.owned_message, self.frame):
            raise changed_tool_call()

    def checked_frame(self, message: dict[str, Any]) -> bytes:
        if message is not self.owned_message:
            raise changed_tool_call()
        self.check()
        return self.frame


def bind_tool_call(message: dict[str, Any], *, parent: ToolCallBinding | None = None) -> ToolCallBinding | None:
    """Own supported JSON without changing the existing unsupported-input path."""

    if type(message) is not dict:
        return None
    try:
        owned = cast(dict[str, Any], _own_plain_json(message))
    except _UnsupportedPlainJsonError:
        return None
    except (TypeError, ValueError, RecursionError, RuntimeError) as error:
        # A failed traversal of otherwise plain JSON can indicate concurrent
        # mutation. It must not silently remove the request's final binding.
        raise changed_tool_call() from error
    require_tool_call_method(owned)
    binding = ToolCallBinding(message, owned, framing.encoded_line(owned), parent)
    binding.check()
    return binding


_CURRENT: ContextVar[ToolCallBinding | None] = ContextVar("guard_mcp_tool_call_binding", default=None)
_BOUND_WRITE: ContextVar[dict[str, Any] | None] = ContextVar("guard_mcp_tool_call_bound_write", default=None)
_BOUND_AUTHORITY: ContextVar[Callable[[], None] | None] = ContextVar(
    "guard_mcp_tool_call_bound_authority", default=None
)


def current_tool_call_binding() -> ToolCallBinding | None:
    return _CURRENT.get()


@contextmanager
def use_tool_call_binding(binding: ToolCallBinding | None) -> Iterator[None]:
    token = _CURRENT.set(binding)
    try:
        yield
    finally:
        _CURRENT.reset(token)


@contextmanager
def bind_tool_call_write(
    message: dict[str, Any], *, authority_check: Callable[[], None] | None = None
) -> Iterator[None]:
    token = _BOUND_WRITE.set(message)
    authority_token = _BOUND_AUTHORITY.set(authority_check)
    try:
        yield
    finally:
        _BOUND_AUTHORITY.reset(authority_token)
        _BOUND_WRITE.reset(token)


def tool_call_write_frame(message: dict[str, Any], *, source: str) -> bytes | None:
    """Select by bound object identity, then authorize complete immutable bytes."""

    if source != "child_write" or message is not _BOUND_WRITE.get():
        return None
    authority_check = _BOUND_AUTHORITY.get()
    if authority_check is not None:
        authority_check()
    require_tool_call_method(message)
    binding = current_tool_call_binding()
    if binding is not None:
        return binding.checked_frame(message)
    # Unsupported Python-only inputs retain the old encoder. Still validate
    # the tool method in those actual bytes and never reopen method dispatch.
    frame = framing.encoded_line(message)
    payload = json.loads(frame)
    if type(payload) is not dict:
        raise changed_tool_call()
    require_tool_call_method(payload)
    require_tool_call_method(message)
    return frame
