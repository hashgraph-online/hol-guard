"""Native hook bridge for generated Pi-family extensions.

The extension runs the compiled runtime's ``pi-hook-bridge`` once per hook
instead of posting to the daemon itself. The runtime asks a live resident
first and posts everything else to the daemon with the extension's own path,
query and token, then prints the status and body the extension would have
read from the daemon. The extension keeps its loopback ``fetch`` when the
runtime is absent, on Windows, or when the runtime cannot be started.
"""

from __future__ import annotations

import os
from pathlib import Path

PI_HOOK_BRIDGE_FEATURE = "pi-hook-bridge-v1"
# `fetch` keeps every Pi hook on the extension's own daemon request. Contract
# tests set it so a subprocess install and the parent verifier agree.
PI_HOOK_BRIDGE_SWITCH = "HOL_GUARD_PI_HOOK_BRIDGE"


def pi_native_hook_runtime(*, guard_home: Path, platform_name: str = os.name) -> Path | None:
    """The native runtime the extension spawns for each hook, or ``None``."""

    if platform_name == "nt" or os.environ.get(PI_HOOK_BRIDGE_SWITCH) == "fetch":
        return None
    from ...native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(PI_HOOK_BRIDGE_FEATURE, guard_home=guard_home)


__all__ = [
    "PI_HOOK_BRIDGE_FEATURE",
    "PI_HOOK_BRIDGE_SWITCH",
    "pi_native_hook_runtime",
]
