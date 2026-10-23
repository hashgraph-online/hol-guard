"""Shell-free Claude hook argv construction and SessionStart entry point."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from urllib.parse import urlencode

from ..runtime.harness_attribution import cursor_hook_query_extras
from ..stable_guard_cli import guard_cli_launcher
from ._modules.claude.claude_frozen_hook import FROZEN_CLAUDE_HOOK_COMMAND
from .base import HarnessContext
from .claude_hook_config import (
    CLAUDE_GUARD_DAEMON_HOOK_MARKER,
    CLAUDE_GUARD_SESSION_START_CONTEXT,
    CLAUDE_GUARD_SESSION_START_HOOK_MARKER,
)
from .native_hook_bridge import native_hook_bridge_executable

NATIVE_CLAUDE_HOOK_COMMAND = "claude-hook-bridge"
NATIVE_CLAUDE_HOOK_FEATURE = "claude-hook-bridge-v1"
NATIVE_CLAUDE_SESSION_START_MODE = "session-start"
NATIVE_CLAUDE_SESSION_START_FEATURE = "claude-session-start-v1"
_SESSION_START_ERROR = (
    "claude_session_start_argv_invalid: reinstall the managed Claude hooks with `hol-guard install claude`"
)


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _native_bridge_executable(guard_home: Path) -> Path | None:
    """The validated native runtime when it can proxy Claude hooks itself.

    The native bridge ports ``claude_daemon_hook_bridge`` so each hook call
    skips the Python interpreter start. A frozen build names the runtime's
    durable copy under ``guard_home``.
    """

    return native_hook_bridge_executable(NATIVE_CLAUDE_HOOK_FEATURE, guard_home=guard_home)


def run_session_start_from_argv(
    argv: Sequence[str],
    *,
    ensure_guard_daemon: Callable[[Path], object],
    refresh_installed_hook_urls: Callable[..., object],
) -> int:
    """Refresh managed hook URLs from a validated, shell-free path vector."""

    if len(argv) not in {2, 3} or any(not value or "\x00" in value for value in argv):
        raise SystemExit(_SESSION_START_ERROR)

    guard_home = Path(argv[0])
    home_dir = Path(argv[1])
    workspace_dir = Path(argv[2]) if len(argv) == 3 else None
    ensure_guard_daemon(guard_home)
    refresh_installed_hook_urls(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
    )
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": CLAUDE_GUARD_SESSION_START_CONTEXT,
                }
            },
            separators=(",", ":"),
        )
    )
    return 0


def guard_hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    guard_args = [
        "guard",
        "hook",
        f"--guard-home={context.guard_home}",
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        guard_args.append(f"--home={context.home_dir}")
    if context.workspace_dir is not None:
        guard_args.append(f"--workspace={context.workspace_dir}")
    if _is_frozen():
        # The frozen binary is the hol-guard program, where `hook` is a top-level command.
        return (guard_cli_launcher(), *guard_args[1:])
    package_root = Path(__file__).resolve().parents[3]
    code = (
        "import sys;"
        f"sys.path.insert(0, {str(package_root)!r});"
        "from codex_plugin_scanner.cli import main;"
        "raise SystemExit(main(sys.argv[1:]))"
    )
    return (sys.executable, "-c", code, *guard_args)


def bridge_config_template(context: HarnessContext, query: str, *, native: bool) -> dict[str, object]:
    """The daemon hook bridge config, less ``fallback_daemon_url``."""

    state_path = context.guard_home / "daemon-state.json"
    config: dict[str, object] = {
        "state_path": str(state_path),
        "fallback_command": list(guard_hook_command_parts(context)),
        "query": query,
    }
    if native:
        from .claude_daemon_hook_bridge import _recovery_command

        config["recovery_command"] = list(_recovery_command(state_path, query))
    return config


def bridge_config_text(template: Mapping[str, object], fallback_daemon_url: str) -> str:
    """The bridge config argument, with the daemon URL second as installed."""

    config = {"state_path": template["state_path"], "fallback_daemon_url": fallback_daemon_url}
    config.update((key, value) for key, value in template.items() if key != "state_path")
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


def daemon_hook_command_parts(
    context: HarnessContext,
    *,
    fallback_daemon_url: str,
) -> tuple[str, ...]:
    package_root = Path(__file__).resolve().parents[3]
    query = urlencode(_hook_query(context, cursor_hook_query_extras()))
    native_bridge = _native_bridge_executable(context.guard_home)
    template = bridge_config_template(context, query, native=native_bridge is not None)
    bridge_config = bridge_config_text(template, fallback_daemon_url)
    if native_bridge is not None:
        return (str(native_bridge), NATIVE_CLAUDE_HOOK_COMMAND, CLAUDE_GUARD_DAEMON_HOOK_MARKER, bridge_config)
    if _is_frozen():
        return (guard_cli_launcher(), FROZEN_CLAUDE_HOOK_COMMAND, CLAUDE_GUARD_DAEMON_HOOK_MARKER, bridge_config)
    code = (
        f"_HOL_GUARD_CLAUDE_DAEMON_HOOK_MARKER = {CLAUDE_GUARD_DAEMON_HOOK_MARKER!r};"
        "import sys;"
        f"sys.path.insert(0, {str(package_root)!r});"
        "from codex_plugin_scanner.guard.adapters.claude_daemon_hook_bridge import _bridge_config_from_argv,main;"
        "_config=_bridge_config_from_argv(sys.argv);"
        "raise SystemExit(main(state_path=_config['state_path'], "
        "fallback_daemon_url=_config['fallback_daemon_url'], "
        "fallback_command=_config['fallback_command'], query=_config['query']))"
    )
    return (sys.executable, "-c", code, bridge_config)


def session_start_command_parts(context: HarnessContext) -> tuple[str, ...]:
    python_argv = _python_session_start_command_parts(context)
    return _native_session_start_command_parts(context, python_argv) or python_argv


def _native_session_start_command_parts(
    context: HarnessContext,
    python_argv: tuple[str, ...],
) -> tuple[str, ...] | None:
    """The native SessionStart lane, which answers the no-op case in Rust.

    The runtime prints the context only when the daemon is verified live and
    the managed entries already equal what the Python refresh would write;
    otherwise it execs ``python_argv`` unchanged. The lane reproduces the
    refresh only for the installing user's own home, so other homes keep the
    Python command. Windows has no ``exec``, so there the runtime runs
    ``python_argv`` as a child with the same stdio and exits with its status.
    """

    runtime = native_hook_bridge_executable(NATIVE_CLAUDE_SESSION_START_FEATURE, guard_home=context.guard_home)
    if runtime is None or runtime != _native_bridge_executable(context.guard_home):
        return None
    home = Path.home()
    if context.home_dir.resolve() != home.resolve():
        return None
    from ..native_runtime import native_runtime_status

    capabilities = native_runtime_status().capabilities
    if capabilities is None:
        return None
    query = urlencode(_hook_query(context, {}))
    config = {
        "fallback_command": list(python_argv),
        "home": str(home),
        "home_dir": str(context.home_dir),
        "runtime_build": f"{capabilities.runtime_version}+{capabilities.build_sha}",
        "daemon_hook_command": [str(runtime), NATIVE_CLAUDE_HOOK_COMMAND, CLAUDE_GUARD_DAEMON_HOOK_MARKER],
        "bridge_config": bridge_config_template(context, query, native=True),
    }
    return (
        str(runtime),
        NATIVE_CLAUDE_HOOK_COMMAND,
        NATIVE_CLAUDE_SESSION_START_MODE,
        CLAUDE_GUARD_SESSION_START_HOOK_MARKER,
        json.dumps(config, ensure_ascii=False, separators=(",", ":")),
    )


def _python_session_start_command_parts(context: HarnessContext) -> tuple[str, ...]:
    if _is_frozen():
        path_argv = (str(context.guard_home), str(context.home_dir))
        if context.workspace_dir is not None:
            path_argv = (*path_argv, str(context.workspace_dir))
        return (guard_cli_launcher(), FROZEN_CLAUDE_HOOK_COMMAND, CLAUDE_GUARD_SESSION_START_HOOK_MARKER, *path_argv)
    package_root = Path(__file__).resolve().parents[3]
    code = (
        f"_HOL_GUARD_CLAUDE_SESSION_START_HOOK_MARKER = {CLAUDE_GUARD_SESSION_START_HOOK_MARKER!r};"
        "import sys;"
        f"sys.path.insert(0, {str(package_root)!r});"
        "from codex_plugin_scanner.guard.adapters.claude_code import _run_session_start_from_argv;"
        "raise SystemExit(_run_session_start_from_argv(sys.argv[1:]))"
    )
    path_argv = (str(context.guard_home), str(context.home_dir))
    if context.workspace_dir is not None:
        path_argv = (*path_argv, str(context.workspace_dir))
    return (sys.executable, "-c", code, *path_argv)


def _hook_query(context: HarnessContext, extras: Mapping[str, str]) -> dict[str, str]:
    query = {"guard-home": str(context.guard_home)}
    if context.home_dir.resolve() != Path.home().resolve():
        query["home"] = str(context.home_dir)
    if context.workspace_dir is not None:
        query["workspace"] = str(context.workspace_dir)
    query.update(extras)
    return query
