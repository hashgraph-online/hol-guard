"""Process facts a generated Pi-family extension binds.

The native ``harness_adapter`` kind renders the extension and picks the CLI
it runs. Only the Guard process knows its own ``hol-guard`` entry points, its
native hook runtime and, on Windows, its interpreter, contained-run sink and
``taskkill`` path, so it sends them with each request that renders.
"""

from __future__ import annotations

import os
import site
import sys
import sysconfig
from pathlib import Path

PI_HOOK_BRIDGE_FEATURE = "pi-hook-bridge-v1"
# `fetch` keeps every Pi hook on the extension's own daemon request. Contract
# tests set it so a subprocess install and the parent verifier agree.
PI_HOOK_BRIDGE_SWITCH = "HOL_GUARD_PI_HOOK_BRIDGE"


def installing_runtime_cli_candidates() -> list[str]:
    """The ``hol-guard`` entry points that belong to this interpreter."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    scripts = [sysconfig.get_path("scripts")]
    user_site = site.getusersitepackages() if site.ENABLE_USER_SITE else None
    if user_site and Path(__file__).resolve().is_relative_to(Path(user_site).resolve()):
        # A user install's own entry point outranks an unrelated one beside
        # the interpreter.
        scripts.insert(0, sysconfig.get_path("scripts", sysconfig.get_preferred_scheme("user")))
    name = "hol-guard.exe" if os.name == "nt" else "hol-guard"
    return [str(Path(directory) / name) for directory in scripts if directory]


def pi_native_hook_runtime(*, guard_home: Path, platform_name: str = os.name) -> Path | None:
    """The native runtime the extension spawns for each hook, or ``None``."""
    if platform_name == "nt" or os.environ.get(PI_HOOK_BRIDGE_SWITCH) == "fetch":
        return None
    from .native_hook_bridge import native_hook_bridge_executable

    return native_hook_bridge_executable(PI_HOOK_BRIDGE_FEATURE, guard_home=guard_home)


def _windows_facts(platform_name: str = os.name) -> dict[str, object] | None:
    """The interpreter, sink and request root Claude Code's Windows route uses."""
    if platform_name != "nt":
        return None
    from ..codex_hook_windows_job import windows_system_executable_path
    from ..contained_sink_command import contained_sink_command_prefix
    from ..windows_paths import trusted_windows_local_temp

    package_root = Path(__file__).resolve().parents[3]
    python = str(Path(sys.executable).expanduser().absolute())
    try:
        taskkill: str | None = windows_system_executable_path("taskkill.exe")
    except (OSError, ValueError):
        taskkill = None
    # Without a profile Temp directory, protected runs stay denied.
    try:
        request_root = str(trusted_windows_local_temp())
    except (OSError, RuntimeError, ValueError):
        request_root = ""
    sink = [*contained_sink_command_prefix(python, package_root), "guard"] if request_root else []
    return {
        "python": python,
        "package_root": str(package_root),
        "sink_command": sink,
        "request_root": request_root,
        "taskkill": taskkill,
    }


def extension_runtime(guard_home: Path) -> dict[str, object]:
    """The ``runtime`` field of a request that renders a Pi-family extension."""
    native = pi_native_hook_runtime(guard_home=guard_home)
    return {
        "installing_cli": installing_runtime_cli_candidates(),
        "native_hook_runtime": None if native is None else str(native),
        "windows": _windows_facts(),
    }


__all__ = [
    "PI_HOOK_BRIDGE_FEATURE",
    "PI_HOOK_BRIDGE_SWITCH",
    "extension_runtime",
    "installing_runtime_cli_candidates",
    "pi_native_hook_runtime",
]
