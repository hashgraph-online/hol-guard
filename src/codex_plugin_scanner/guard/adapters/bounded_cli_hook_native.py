"""Native runtime launcher for bounded CLI hooks."""

from __future__ import annotations

from pathlib import Path

NATIVE_BOUNDED_HOOK_COMMAND = "bounded-hook-bridge"
NATIVE_BOUNDED_HOOK_FEATURE = "bounded-hook-bridge-v1"
# A runtime without this feature refuses a Muse config, so a Muse install
# asks for repair until the runtime that answers it is installed.
NATIVE_MUSE_HOOK_FEATURE = "bounded-hook-bridge-muse-v1"
# Harnesses whose hook the native runtime answers from the daemon itself.
_NATIVE_BOUNDED_HOOK_HARNESSES = frozenset(
    {"copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "opencode", "grok", "muse"}
)


def native_bridge_executable(harness: str, *, guard_home: Path | None = None) -> Path | None:
    """The native runtime that launches ``harness`` hooks, or None when it is missing.

    A frozen build names its runtime's durable copy under ``guard_home``.
    """

    if harness not in _NATIVE_BOUNDED_HOOK_HARNESSES:
        return None
    from .native_hook_bridge import native_hook_bridge_executable

    feature = NATIVE_MUSE_HOOK_FEATURE if harness == "muse" else NATIVE_BOUNDED_HOOK_FEATURE
    return native_hook_bridge_executable(feature, guard_home=guard_home)


__all__ = [
    "NATIVE_BOUNDED_HOOK_COMMAND",
    "NATIVE_BOUNDED_HOOK_FEATURE",
    "NATIVE_MUSE_HOOK_FEATURE",
    "native_bridge_executable",
]
