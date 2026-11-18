"""Process facts a generated Pi-family extension binds.

The native ``harness_adapter`` kind renders the extension and picks the CLI
it runs and the native hook runtime, both from the caller stamp. Only the Guard
process knows its own ``hol-guard`` entry points and, on Windows, its
interpreter, contained-run sink and ``taskkill`` path, so it sends them with
each request that renders. ``HOL_GUARD_PI_HOOK_BRIDGE=fetch`` keeps every hook
on the extension's own daemon request; contract tests set it so a subprocess
install and the parent verifier agree.
"""

from __future__ import annotations

import os
import site
import sys
import sysconfig
from pathlib import Path


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


def _windows_facts(platform_name: str = os.name) -> dict[str, object] | None:
    """The sink, request root and ``taskkill`` path the Windows route uses."""
    if platform_name != "nt":
        return None
    from .codex_hook_launch_runtime import windows_system_executable_path
    from .contained_sink_command import contained_sink_command_prefix
    from .windows_paths import trusted_windows_local_temp

    package_root = Path(__file__).resolve().parents[2]
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
        "sink_command": sink,
        "request_root": request_root,
        "taskkill": taskkill,
    }


def extension_runtime() -> dict[str, object]:
    """The ``runtime`` field of a request that renders a Pi-family extension."""
    return {
        "installing_cli": installing_runtime_cli_candidates(),
        "windows": _windows_facts(),
    }


__all__ = [
    "extension_runtime",
    "installing_runtime_cli_candidates",
]
