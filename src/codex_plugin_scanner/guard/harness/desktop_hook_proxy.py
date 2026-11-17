"""Signed macOS Desktop proxy launch check for frozen bounded hooks.

The native ``desktop_hook_proxy`` kind checks the proxy, Core and app bundle,
verifies their Apple Team ID and renders the launch script that checks them
again before every hook. The native ``harness_adapter`` kind asks it for the
hook argv at install time; this module only asks it to verify a stored launch.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

# Three `codesign` verifications of up to 5s each, one of them a whole bundle.
_TIMEOUT_SECONDS = 45.0


def _ask(request: dict[str, object]) -> dict[str, object] | None:
    # Imported here so the module stays off the native runtime client until it asks.
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("desktop_hook_proxy", request, timeout_seconds=_TIMEOUT_SECONDS)
    except (NativeRunnerAuthorityError, OSError):
        return None


def verified_desktop_proxy_launch(args: Sequence[str]) -> tuple[str, str] | None:
    """The config and Core path of a stored proxy launch the kind verified, or ``None``."""

    if sys.platform != "darwin":
        return None
    answer = _ask({"op": "verify", "args": list(args)})
    config = answer.get("config") if answer is not None else None
    core = answer.get("core") if answer is not None else None
    return (config, core) if isinstance(config, str) and isinstance(core, str) else None
