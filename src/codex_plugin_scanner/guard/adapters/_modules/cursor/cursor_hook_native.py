"""Native runtime launcher for Cursor hooks."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

NATIVE_CURSOR_HOOK_COMMAND = "cursor-hook-bridge"
NATIVE_CURSOR_HOOK_FEATURE = "cursor-hook-bridge-v1"


class CursorNativeBridgeUnavailableError(RuntimeError):
    """No native runtime on this machine can answer Cursor's hooks."""


def python_client_pinned() -> bool:
    """True when Guard's own suite pinned the client argv for a contract test.

    ``HOL_GUARD_CURSOR_HOOK_BRIDGE=python`` drops the runtime prefix so a
    subprocess install and its parent verifier agree on one argv. Unlike the
    bounded-CLI bridge, the Cursor client is not a second evaluator: it answers
    only the hook no runtime answered, which means an ``after*`` observer
    continues and every gated hook is denied. A pin outside Guard's test mode
    would therefore install that denial, so it is ignored there and install
    refuses instead.
    """

    return os.environ.get("HOL_GUARD_CURSOR_HOOK_BRIDGE") == "python" and os.environ.get("HOL_GUARD_TEST_MODE") == "1"


def native_cursor_hook_bridge(guard_home: Path | None = None) -> Path | None:
    """The native runtime that answers Cursor hooks before Python starts, or None.

    The runtime answers each hook from the daemon and fails closed without
    one; it reads the client script the argv after its subcommand names. A
    frozen build names the runtime's durable copy under ``guard_home``.
    """

    if python_client_pinned():
        return None
    from ...native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(NATIVE_CURSOR_HOOK_FEATURE, guard_home=guard_home)


def require_cursor_hook_bridge(guard_home: Path | None = None) -> Path | None:
    """The runtime the managed hook runs behind, or None under the suite's pin.

    Raises :class:`CursorNativeBridgeUnavailableError` when no runtime can answer
    Cursor's hooks. Writing the hook anyway would register a command that
    denies every shell, read and MCP action Cursor gates, so there is no
    install to write and no healthy state to report.
    """

    bridge = native_cursor_hook_bridge(guard_home)
    if bridge is None and not python_client_pinned():
        raise CursorNativeBridgeUnavailableError("guard_cursor_native_bridge_unavailable")
    return bridge


def client_hook_tokens(tokens: Sequence[str]) -> list[str]:
    """The client argv inside a native bridge prefix, else ``tokens``."""

    values = list(tokens)
    if len(values) > 2 and values[0] and values[1] == NATIVE_CURSOR_HOOK_COMMAND:
        return values[2:]
    return values
