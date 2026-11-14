"""Native runtime launcher for bounded CLI hooks."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

NATIVE_BOUNDED_HOOK_COMMAND = "bounded-hook-bridge"
NATIVE_BOUNDED_HOOK_FEATURE = "bounded-hook-bridge-v1"
# A runtime without this feature refuses a Muse config, so Muse keeps the
# Python bridge until the runtime that answers it is installed.
NATIVE_MUSE_HOOK_FEATURE = "bounded-hook-bridge-muse-v1"
# Harnesses whose hook the native runtime answers from the daemon itself.
_NATIVE_BOUNDED_HOOK_HARNESSES = frozenset(
    {"copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "opencode", "grok", "muse"}
)


def bounded_python_argv(argv: Sequence[object]) -> list[object]:
    """The Python bridge argv inside a native launcher prefix, else ``argv``.

    The native runtime answers a bounded hook from the daemon itself and never
    runs the Python bridge argv that follows its subcommand; the argv keeps a
    native and a Python registration of one hook naming the same bridge.
    """
    values = list(argv)
    if len(values) > 2 and isinstance(values[0], str) and values[0] and values[1] == NATIVE_BOUNDED_HOOK_COMMAND:
        return values[2:]
    return values


def native_bridge_executable(harness: str, *, guard_home: Path | None = None) -> Path | None:
    """The native runtime that launches ``harness`` hooks, or None for Python.

    A frozen build names its runtime's durable copy under ``guard_home``.
    """

    # HOL_GUARD_BOUNDED_HOOK_BRIDGE=python keeps the Python bridge argv. Contract
    # tests set it so a subprocess install and the parent verifier agree. The
    # Python bridge is the same fallback used when the native runtime is absent.
    if harness not in _NATIVE_BOUNDED_HOOK_HARNESSES or os.environ.get("HOL_GUARD_BOUNDED_HOOK_BRIDGE") == "python":
        return None
    from .native_hook_bridge import native_hook_bridge_executable

    feature = NATIVE_MUSE_HOOK_FEATURE if harness == "muse" else NATIVE_BOUNDED_HOOK_FEATURE
    return native_hook_bridge_executable(feature, guard_home=guard_home)


__all__ = [
    "NATIVE_BOUNDED_HOOK_COMMAND",
    "NATIVE_BOUNDED_HOOK_FEATURE",
    "NATIVE_MUSE_HOOK_FEATURE",
    "bounded_python_argv",
    "native_bridge_executable",
]
