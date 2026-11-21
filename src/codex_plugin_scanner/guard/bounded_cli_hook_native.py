"""Native runtime launcher for bounded CLI hooks."""

from __future__ import annotations

NATIVE_BOUNDED_HOOK_COMMAND = "bounded-hook-bridge"
NATIVE_BOUNDED_HOOK_FEATURE = "bounded-hook-bridge-v1"
# A runtime without this feature refuses a Muse config, so a Muse install
# asks for repair until the runtime that answers it is installed.
NATIVE_MUSE_HOOK_FEATURE = "bounded-hook-bridge-muse-v1"
__all__ = [
    "NATIVE_BOUNDED_HOOK_COMMAND",
    "NATIVE_BOUNDED_HOOK_FEATURE",
    "NATIVE_MUSE_HOOK_FEATURE",
]
