"""Signed macOS Desktop proxy launch for frozen bounded hooks.

The native ``desktop_hook_proxy`` kind checks the proxy, Core and app bundle,
verifies their Apple Team ID and renders the launch script that checks them
again before every hook. This module sends the Desktop launch environment and
keeps the frozen-process check, which only this process knows. A resident that
cannot answer keeps the Core bridge.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

_DESKTOP_PROXY_ENV = "HOL_GUARD_DESKTOP_HOOK_PROXY"
# Three `codesign` verifications of up to 5s each, one of them a whole bundle.
_TIMEOUT_SECONDS = 45.0


def _ask(request: dict[str, object]) -> dict[str, object] | None:
    try:
        return native_runner_authority("desktop_hook_proxy", request, timeout_seconds=_TIMEOUT_SECONDS)
    except (NativeRunnerAuthorityError, OSError):
        return None


def _trusted_desktop_hook_proxy_command(
    python_executable: str,
    config_json: str,
    *,
    require_proxy: bool = False,
) -> tuple[str, ...] | None:
    """Return a runtime-verified signed macOS proxy command or retain Core."""

    # Only a frozen Core on macOS launched with a proxy can have one to check.
    if not getattr(sys, "frozen", False) or sys.platform != "darwin" or not os.environ.get(_DESKTOP_PROXY_ENV):
        return None
    answer = _ask(
        {
            "op": "command",
            "core": python_executable,
            "config": config_json,
            "require_proxy": require_proxy,
            "desktop": os.environ.get("HOL_GUARD_DESKTOP"),
            "proxy": os.environ.get(_DESKTOP_PROXY_ENV),
        }
    )
    argv = answer.get("argv") if answer is not None else None
    return tuple(str(part) for part in argv) if isinstance(argv, list) else None


def verified_desktop_proxy_launch(args: Sequence[str]) -> tuple[str, str] | None:
    """The config and Core path of a stored proxy launch the kind verified, or ``None``."""

    if sys.platform != "darwin":
        return None
    answer = _ask({"op": "verify", "args": list(args)})
    config = answer.get("config") if answer is not None else None
    core = answer.get("core") if answer is not None else None
    return (config, core) if isinstance(config, str) and isinstance(core, str) else None
