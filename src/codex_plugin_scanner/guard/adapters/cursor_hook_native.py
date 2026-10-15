"""Native runtime launcher for Cursor's managed hook client."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

NATIVE_CURSOR_HOOK_COMMAND = "cursor-hook-bridge"
NATIVE_CURSOR_HOOK_FEATURE = "cursor-hook-bridge-v1"


def native_cursor_hook_bridge() -> Path | None:
    """The native runtime that answers Cursor hooks before Python starts, or None.

    The runtime answers a hook a live resident allows and runs the client argv
    that follows its subcommand for everything else.
    HOL_GUARD_CURSOR_HOOK_BRIDGE=python keeps the client argv, so a subprocess
    install and its verifier agree.
    """

    if os.environ.get("HOL_GUARD_CURSOR_HOOK_BRIDGE") == "python":
        return None
    from .native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(NATIVE_CURSOR_HOOK_FEATURE)


def client_hook_tokens(tokens: Sequence[str]) -> list[str]:
    """The client argv inside a native bridge prefix, else ``tokens``."""

    values = list(tokens)
    if len(values) > 2 and values[0] and values[1] == NATIVE_CURSOR_HOOK_COMMAND:
        return values[2:]
    return values


__all__ = [
    "NATIVE_CURSOR_HOOK_COMMAND",
    "NATIVE_CURSOR_HOOK_FEATURE",
    "client_hook_tokens",
    "native_cursor_hook_bridge",
]
