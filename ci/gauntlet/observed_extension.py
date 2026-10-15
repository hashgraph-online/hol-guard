"""The Guard extension each live case loads, on the transport the observer records.

Generated extensions answer each hook through the native runtime's
``pi-hook-bridge`` when the installed runtime advertises it. The bridge child
posts to the daemon itself, so ``observer.ts``, which wraps the extension's
loopback ``fetch``, records nothing and every case reads as a harness error
("host/Guard call inventories disagree"). Whether a run chose the bridge varied
with the wheel and the host, so the transport is pinned here instead.
"""

from __future__ import annotations

import os
from pathlib import Path

from ci.native_runtime import probe_installed_pi_output as probe


def generate_observed_extension(extension: Path, *, guard_home: Path, home: Path, settings_path: Path) -> None:
    """Write the extension with its hooks posted over the observed loopback ``fetch``."""
    from codex_plugin_scanner.guard.adapters.pi_extension_native_hook import PI_HOOK_BRIDGE_SWITCH

    previous = os.environ.get(PI_HOOK_BRIDGE_SWITCH)
    os.environ[PI_HOOK_BRIDGE_SWITCH] = "fetch"
    try:
        probe._generate_extension(extension, guard_home=guard_home, home=home, settings_path=settings_path)
    finally:
        if previous is None:
            os.environ.pop(PI_HOOK_BRIDGE_SWITCH, None)
        else:
            os.environ[PI_HOOK_BRIDGE_SWITCH] = previous
