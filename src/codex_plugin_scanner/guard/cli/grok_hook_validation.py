"""Recognize the exact native Grok hook launch forms produced by Guard."""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import cast

from ..adapters.base import HarnessContext, _shell_command
from ..stable_guard_cli import prune_safe_cli_executable


def _arguments(command: str) -> tuple[str, ...]:
    """Parse the host's serialized argv and reject noncanonical shell syntax."""
    if os.name == "nt":
        from ..windows_paths import windows_command_line_to_argv

        args = tuple(windows_command_line_to_argv(command) or ())
    else:
        args = tuple(shlex.split(command))
    # This also rejects shell expansions/operators outside quoted arguments.
    return args if args and _shell_command(args) == command.strip() else ()


def _native_client(args: tuple[str, ...], *, trusted: bool, guard_home: Path | None = None) -> tuple[str, ...] | None:
    """Split a native runtime launch into its own argv.

    ``[runtime, "bounded-hook-bridge", config]`` is the form Guard installs now
    and comes back unchanged. Older installs wrapped a Python client in the
    runtime; those come back as the client argv. Returns ``args`` unchanged
    without a runtime and None for a runtime that is not this host's validated
    native runtime when ``trusted`` is required. A frozen build's runtime is
    its durable copy under ``guard_home``.
    """
    from ..adapters.bounded_cli_hook_native import NATIVE_BOUNDED_HOOK_COMMAND, native_bridge_executable

    if len(args) < 2 or args[1] != NATIVE_BOUNDED_HOOK_COMMAND:
        return args
    if len(args) not in {3, 6} or (len(args) == 6 and args[3] != "-I") or not Path(args[0]).is_absolute():
        return None
    if trusted:
        runtime = native_bridge_executable("grok", guard_home=guard_home)
        if runtime is None or Path(args[0]).resolve() != runtime.resolve():
            return None
    return args if len(args) == 3 else args[2:]


def _native_launch(args: tuple[str, ...]) -> bool:
    from ..adapters.bounded_cli_hook_native import NATIVE_BOUNDED_HOOK_COMMAND

    return len(args) == 3 and args[1] == NATIVE_BOUNDED_HOOK_COMMAND


def _config(text: str, executable: str, *, frozen: bool, context: HarnessContext | None) -> dict[str, object] | None:
    """Bind the bridge configuration to its executable and Grok hook invocation."""
    config = json.loads(text)
    if not isinstance(config, dict) or config.get("harness") != "grok":
        return None
    if config.get("frozen_launcher") is not frozen or config.get("python_executable") != executable:
        return None
    guard_home = config.get("guard_home")
    package_root = config.get("package_root")
    args = config.get("cli_args")
    timeout = config.get("timeout_seconds")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 120:
        return None
    if not isinstance(guard_home, str) or not Path(guard_home).is_absolute():
        return None
    if not isinstance(package_root, str) or not Path(package_root).is_absolute():
        return None
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return None
    if args[:2] != ["guard", "hook"] or args[-1:] != ["--json"]:
        return None
    options = args[2:-1]
    if len(options) % 2 or len(set(options[::2])) != len(options[::2]):
        return None
    parsed = dict(zip(options[::2], options[1::2], strict=True))
    if parsed.get("--harness") != "grok" or not set(parsed) <= {"--harness", "--guard-home", "--home", "--workspace"}:
        return None
    configured_home = parsed.get("--guard-home")
    if not configured_home or Path(configured_home).resolve() != Path(guard_home).resolve():
        return None
    if any(not Path(value).is_absolute() for key, value in parsed.items() if key != "--harness"):
        return None
    if context is not None and not _matches_context(parsed, context):
        return None
    return config


def _matches_context(options: dict[str, str], context: HarnessContext) -> bool:
    """Require the bridge's store, effective home, and workspace to match its owner."""
    expected = {"--guard-home": context.guard_home, "--home": context.home_dir}
    actual = {"--guard-home": options["--guard-home"], "--home": options.get("--home", str(Path.home()))}
    if any(Path(actual[key]).resolve() != path.resolve() for key, path in expected.items()):
        return False
    workspace = options.get("--workspace")
    if context.workspace_dir is None:
        return workspace is None
    return workspace is not None and Path(workspace).resolve() == context.workspace_dir.resolve()


def _desktop_proxy(args: tuple[str, ...], context: HarnessContext | None) -> bool:
    """Accept only the generated macOS script and its verified same-team app paths."""
    from ..adapters.desktop_hook_proxy import verified_desktop_proxy_launch

    launch = verified_desktop_proxy_launch(args)
    return launch is not None and _config(launch[0], launch[1], frozen=True, context=context) is not None


def is_grok_hook_command(command: str, context: HarnessContext | None = None) -> bool:
    """Reject marker-only commands without executing untrusted hook text or code."""
    try:
        guard_home = None if context is None else context.guard_home
        args = _native_client(_arguments(command), trusted=True, guard_home=guard_home)
        if args is None:
            return False
        if len(args) == 10:
            return _desktop_proxy(args, context)
        if not _native_launch(args):
            return False
        frozen = bool(getattr(sys, "frozen", False))
        executable = prune_safe_cli_executable(sys.executable) if frozen else sys.executable
        config = _config(args[2], executable, frozen=frozen, context=context)
        return config is not None and (frozen or config["package_root"] == str(Path(__file__).resolve().parents[3]))
    except (OSError, ValueError, TypeError, RuntimeError):
        return False


def is_missing_grok_hook_command(command: str, replacement: str) -> bool:
    """Recognize an orphaned generated client for the same user home.

    This is migration recognition only, never proof that a hook is operational.
    Parse canonical argv without executing either command or loading old code.
    """

    def binding(text: str, *, old_client: bool) -> tuple[Path | None, dict[str, str]] | None:
        args = _native_client(_arguments(text), trusted=False)
        if not args or not Path(args[0]).is_absolute():
            return None
        script = None
        if len(args) == 4 and args[1] == "-I":
            # Migration must work even when the old interpreter is gone or
            # isolated Python is unavailable to the new launcher.
            if not re.fullmatch(r"python(?:\d+(?:\.\d+)*)?(?:\.exe)?", Path(args[0]).name, re.IGNORECASE):
                return None
            script = Path(args[2])
            serialized = args[3]
        elif old_client:
            return None
        elif _native_launch(args):
            serialized = args[2]
        elif len(args) == 10 and _desktop_proxy(args, None):
            serialized = args[7]
        else:
            return None
        raw = json.loads(serialized)
        if not isinstance(raw, dict) or not isinstance(raw.get("frozen_launcher"), bool):
            return None
        executable = raw.get("python_executable")
        if not isinstance(executable, str) or not Path(executable).is_absolute():
            return None
        config = _config(serialized, executable, frozen=raw["frozen_launcher"], context=None)
        if config is None:
            return None
        expected = Path(cast(str, config["guard_home"])) / "managed" / "bounded-hooks" / "grok.py"
        if script is not None and (not script.is_absolute() or script != expected):
            return None
        cli_args = cast(list[str], config["cli_args"])
        options = dict(zip(cli_args[2:-1:2], cli_args[3:-1:2], strict=True))
        scope = {"--home": str(Path(options.get("--home", str(Path.home()))).resolve())}
        # Workspace is a fallback for hosts without cwd, not an ownership
        # boundary: these commands all live in the same global Grok config.
        return script, scope

    try:
        old, new = binding(command, old_client=True), binding(replacement, old_client=False)
        return bool(old and new and old[0] is not None and old[1] == new[1] and not old[0].exists())
    except (OSError, ValueError, TypeError, RuntimeError):
        return False
