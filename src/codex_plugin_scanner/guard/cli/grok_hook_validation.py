"""Recognize the exact native Grok hook launch forms produced by Guard."""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

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
    from ..adapters import desktop_hook_proxy as proxy

    if sys.platform != "darwin" or len(args) != 9:
        return False
    if args[:4] != ("/bin/sh", "-c", proxy._DESKTOP_PROXY_LAUNCH_SCRIPT, "hol-guard-desktop-proxy"):
        return False
    candidate, team, bundle, config, core = args[4:]
    candidate_path, core_path, bundle_path = Path(candidate), Path(core), Path(bundle)
    if not all(path.is_absolute() for path in (candidate_path, core_path, bundle_path)):
        return False
    if not proxy._trusted_desktop_path(candidate_path) or not proxy._trusted_desktop_path(core_path):
        return False
    if candidate_path.parent != core_path.parent or proxy._bundle_for_executable(candidate_path) != bundle_path:
        return False
    if proxy._bundle_for_executable(core_path) != bundle_path or not team or team == "not set":
        return False
    if not _config(config, core, frozen=True, context=context):
        return False
    return all(proxy._codesign_team(path) == team for path in (candidate_path, core_path, bundle_path))


def is_grok_hook_command(command: str, context: HarnessContext | None = None) -> bool:
    """Reject marker-only commands without executing untrusted hook text or code."""
    try:
        args = _arguments(command)
        if len(args) == 9:
            return _desktop_proxy(args, context)
        if len(args) == 3 and args[1] == "__guard-bounded-hook":
            expected = Path(prune_safe_cli_executable(sys.executable)).resolve()
            return (
                bool(getattr(sys, "frozen", False))
                and Path(args[0]).is_absolute()
                and Path(args[0]).resolve() == expected
                and _config(args[2], args[0], frozen=True, context=context) is not None
            )
        if len(args) != 5 or args[1:3] != ("-I", "-c"):
            return False
        config = _config(args[4], args[0], frozen=False, context=context)
        if (
            config is None
            or not Path(args[0]).is_absolute()
            or Path(args[0]).resolve() != Path(sys.executable).resolve()
        ):
            return False
        package_root = Path(__file__).resolve().parents[3]
        if config["package_root"] != str(package_root):
            return False
        bootstrap = (
            "import sys;"
            f"sys.path.insert(0,{str(package_root)!r});"
            "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import main_from_argv;"
            "raise SystemExit(main_from_argv(sys.argv[1:]))"
        )
        return args[3] == bootstrap
    except (OSError, ValueError, TypeError, RuntimeError):
        return False
