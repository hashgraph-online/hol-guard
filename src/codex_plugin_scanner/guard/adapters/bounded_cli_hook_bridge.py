"""Hook command for harnesses whose hooks the native runtime answers.

The native runtime reads the install-time config, asks the daemon and fails
closed on its own. Python only writes the config and names the runtime; when
there is no runtime it refuses the install and asks for ``hol-guard repair``.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from ..stable_guard_cli import prune_safe_cli_executable
from .bounded_cli_hook_failure import failure_payload
from .bounded_cli_hook_native import (
    NATIVE_BOUNDED_HOOK_COMMAND,
    NATIVE_BOUNDED_HOOK_FEATURE,
    NATIVE_MUSE_HOOK_FEATURE,
    native_bridge_executable,
)
from .desktop_hook_proxy import _trusted_desktop_hook_proxy_command

RUNTIME_MISSING = "HOL Guard's native runtime is missing, so Guard blocked this hook. Run `hol-guard repair`."
_TRAILING_MANAGED_MARKERS = frozenset({"HOL_GUARD_MANAGED_ZCODE"})
_FROZEN_BRIDGE_COMMAND = "__guard-bounded-hook"
_BOUNDED_HOOK_SCRIPT_DIR = ("managed", "bounded-hooks")
# The native bridge answers within the hook deadline; this only bounds a
# runtime that stopped answering.
_NATIVE_EXIT_GRACE_SECONDS = 2.0


def bounded_hook_script_path(guard_home: Path, harness: str) -> Path | None:
    """The managed hook client path older installs wrote, so it can be recognised and removed."""

    stem = harness.strip().lower().replace("_", "-")
    if not stem or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in stem):
        return None
    return guard_home.joinpath(*_BOUNDED_HOOK_SCRIPT_DIR, f"{stem}.py")


def bounded_cli_hook_command(
    *,
    python_executable: str,
    package_root: Path,
    guard_home: Path,
    cli_args: Sequence[str],
    harness: str,
    timeout_seconds: float,
    require_desktop_proxy: bool = False,
) -> tuple[str, ...]:
    """The ``[runtime, "bounded-hook-bridge", config]`` hook command, or the signed Desktop proxy."""

    frozen_launcher = bool(getattr(sys, "frozen", False))
    if frozen_launcher:
        python_executable = prune_safe_cli_executable(python_executable)
    config = {
        "python_executable": python_executable,
        "package_root": str(package_root.resolve()),
        "guard_home": str(guard_home.resolve(strict=False)),
        "cli_args": list(cli_args),
        "harness": harness,
        "timeout_seconds": timeout_seconds,
        "frozen_launcher": frozen_launcher,
    }
    config_json = json.dumps(config, ensure_ascii=True, separators=(",", ":"))
    return bounded_hook_command_for_config(config_json, require_desktop_proxy=require_desktop_proxy)


def bounded_hook_command_for_config(config_json: str, *, require_desktop_proxy: bool = False) -> tuple[str, ...]:
    """Wrap a hook config the native runtime built in the bounded bridge or the signed Desktop proxy."""

    config = json.loads(config_json)
    frozen_launcher = config["frozen_launcher"] is True
    harness = str(config["harness"])
    guard_home = Path(str(config["guard_home"]))
    if frozen_launcher:
        desktop_proxy = _trusted_desktop_hook_proxy_command(
            str(config["python_executable"]), config_json, require_proxy=require_desktop_proxy
        )
        if desktop_proxy is not None:
            return desktop_proxy
        if require_desktop_proxy:
            raise RuntimeError("trusted Desktop hook proxy is unavailable")
    elif require_desktop_proxy:
        raise RuntimeError("trusted Desktop hook proxy requires a frozen launcher")
    native = native_bridge_executable(harness, guard_home=guard_home if frozen_launcher else None)
    if native is None:
        raise RuntimeError(RUNTIME_MISSING)
    return (str(native), NATIVE_BOUNDED_HOOK_COMMAND, config_json)


def _config_argv(argv: Sequence[str]) -> dict[str, object] | None:
    # ZCode hook commands end with "# <marker>". POSIX shells drop that comment,
    # but cmd.exe has no comment syntax and passes both words as arguments.
    if not (len(argv) == 1 or (len(argv) == 3 and argv[1] == "#" and argv[2] in _TRAILING_MANAGED_MARKERS)):
        return None
    try:
        config = json.loads(argv[0])
    except ValueError:
        return None
    return config if isinstance(config, dict) else None


def _refuse(harness: str) -> int:
    payload, returncode = failure_payload(
        harness=harness, event_name="PreToolUse", reason=RUNTIME_MISSING, recording_only=False
    )
    _ = sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    return returncode


def main_from_argv(argv: Sequence[str]) -> int:
    """Hand a frozen Guard's ``__guard-bounded-hook`` call to the native runtime.

    The signed Desktop proxy falls back to this when its proxy cannot run.
    The runtime reads the hook from the inherited stdin; without one the hook
    is blocked with a repair message.
    """

    started = time.monotonic()
    config = _config_argv(argv)
    harness = config.get("harness") if config is not None else None
    harness = harness if isinstance(harness, str) else "unknown"
    timeout = config.get("timeout_seconds") if config is not None else None
    if config is None or isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        return _refuse(harness)
    if not math.isfinite(timeout) or timeout <= 0:
        return _refuse(harness)
    guard_home = config.get("guard_home")
    deadline = started + float(timeout)
    from .native_hook_bridge import native_hook_bridge_executable

    feature = NATIVE_MUSE_HOOK_FEATURE if harness == "muse" else NATIVE_BOUNDED_HOOK_FEATURE
    try:
        native = native_hook_bridge_executable(
            feature,
            guard_home=Path(guard_home) if isinstance(guard_home, str) and guard_home else None,
            deadline_monotonic=deadline,
        )
    except (OSError, RuntimeError, ValueError):
        native = None
    remaining = deadline - time.monotonic()
    if native is None or remaining <= 0:
        return _refuse(harness)
    budgeted = json.dumps({**config, "timeout_seconds": remaining}, ensure_ascii=True, separators=(",", ":"))
    sys.stdout.flush()
    try:
        completed = subprocess.run(
            [str(native), NATIVE_BOUNDED_HOOK_COMMAND, budgeted, *argv[1:]],
            timeout=remaining + _NATIVE_EXIT_GRACE_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return _refuse(harness)
    return completed.returncode


__all__ = [
    "NATIVE_BOUNDED_HOOK_COMMAND",
    "NATIVE_BOUNDED_HOOK_FEATURE",
    "RUNTIME_MISSING",
    "_FROZEN_BRIDGE_COMMAND",
    "bounded_cli_hook_command",
    "bounded_hook_command_for_config",
    "bounded_hook_script_path",
    "main_from_argv",
]
