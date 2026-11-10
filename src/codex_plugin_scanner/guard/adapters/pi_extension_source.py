"""Generated Pi managed extension source.

The native runtime renders the source from its recorded template; this
module only resolves what the template binds: runtime ownership, the taskkill
path, the native hook runtime and the daemon compatibility version.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from ..codex_hook_windows_job import windows_system_executable_path
from ..native_context import _resolve_existing_digest_home
from ..native_daemon_manage import GUARD_DAEMON_COMPATIBILITY_VERSION
from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from ._modules.pi.pi_extension_native_hook import pi_native_hook_runtime
from .pi_extension_runtime_ownership import resolve_pi_extension_runtime_ownership


def render_pi_extension_source(
    variant: Literal["active", "previous"],
    *,
    guard_home: Path,
    home_dir: Path,
    settings_path: Path,
    harness: str,
    display_name: str,
    package_source: Path,
    taskkill_lookup: Callable[[str], str | None],
) -> str:
    """Render the ``variant`` extension source natively."""

    runtime = resolve_pi_extension_runtime_ownership(
        guard_home=guard_home,
        home_dir=home_dir,
        harness=harness,
        package_source=package_source,
    )
    try:
        taskkill_path = taskkill_lookup("taskkill.exe") if os.name == "nt" else None
    except (OSError, ValueError):
        taskkill_path = None
    args: dict[str, object] = {
        "variant": variant,
        "harness": harness,
        "display_name": display_name,
        "guard_args": list(runtime.guard_args),
        "guard_home": str(guard_home),
        "home_dir": str(home_dir),
        "home_dir_is_default": home_dir.resolve() == Path.home().resolve(),
        "config_path": str(settings_path),
        "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
        "cli_command": runtime.cli_command,
        "cli_args": list(runtime.cli_args),
        "cli_accepts_json_args": runtime.cli_accepts_json_args,
        "recovery_command": runtime.recovery_command,
        "recovery_args": list(runtime.recovery_args),
        "recovery_accepts_failure_kind": runtime.recovery_accepts_failure_kind,
        "taskkill_path": taskkill_path,
    }
    if variant == "active":
        native_runtime = pi_native_hook_runtime(guard_home=guard_home)
        args["native_hook_runtime"] = None if native_runtime is None else str(native_runtime)
        args["contained_sink_command"] = list(runtime.contained_sink_command)
        args["contained_request_root"] = runtime.contained_request_root
    # Rendering is pure: it must not create the Guard home before install publishes it.
    answer = native_runner_authority("pi_extension_render", args, guard_home=_resolve_existing_digest_home(guard_home))
    source = answer.get("source")
    if not isinstance(source, str):
        raise NativeRunnerAuthorityError("Pi extension render answer is malformed")
    return source


def managed_extension_source(
    *,
    guard_home: Path,
    home_dir: Path,
    settings_path: Path,
    harness: str = "pi",
    display_name: str = "Pi",
) -> str:
    return render_pi_extension_source(
        "active",
        guard_home=guard_home,
        home_dir=home_dir,
        settings_path=settings_path,
        harness=harness,
        display_name=display_name,
        package_source=Path(__file__),
        taskkill_lookup=windows_system_executable_path,
    )
