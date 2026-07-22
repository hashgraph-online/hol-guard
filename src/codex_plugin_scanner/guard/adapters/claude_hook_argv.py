"""Shell-free Claude hook argv construction and SessionStart entry point."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from urllib.parse import urlencode

from ..runtime.harness_attribution import cursor_hook_query_extras
from .base import HarnessContext
from .claude_hook_config import (
    CLAUDE_GUARD_DAEMON_HOOK_MARKER,
    CLAUDE_GUARD_SESSION_START_HOOK_MARKER,
)

_SESSION_START_ERROR = (
    "claude_session_start_argv_invalid: reinstall the managed Claude hooks with `hol-guard install claude`"
)


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
                    "additionalContext": "HOL Guard protection is active for this workspace.",
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
    package_root = Path(__file__).resolve().parents[3]
    code = (
        "import sys;"
        f"sys.path.insert(0, {str(package_root)!r});"
        "from codex_plugin_scanner.cli import main;"
        "raise SystemExit(main(sys.argv[1:]))"
    )
    return (sys.executable, "-c", code, *guard_args)


def daemon_hook_command_parts(
    context: HarnessContext,
    *,
    fallback_daemon_url: str,
) -> tuple[str, ...]:
    state_path = context.guard_home / "daemon-state.json"
    fallback_command = guard_hook_command_parts(context)
    package_root = Path(__file__).resolve().parents[3]
    bridge_config = json.dumps(
        {
            "state_path": str(state_path),
            "fallback_daemon_url": fallback_daemon_url,
            "fallback_command": list(fallback_command),
            "query": urlencode(_hook_query(context, cursor_hook_query_extras())),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
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


def hook_http_url(context: HarnessContext, *, daemon_url: str) -> str:
    return f"{daemon_url}/v1/hooks/claude-code?{urlencode(_hook_query(context, cursor_hook_query_extras()))}"


def _hook_query(context: HarnessContext, extras: Mapping[str, str]) -> dict[str, str]:
    query = {"guard-home": str(context.guard_home)}
    if context.home_dir.resolve() != Path.home().resolve():
        query["home"] = str(context.home_dir)
    if context.workspace_dir is not None:
        query["workspace"] = str(context.workspace_dir)
    query.update(extras)
    return query
