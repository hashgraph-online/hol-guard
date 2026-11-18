"""The Claude Code hook entry points and the facts only the Guard process knows.

The native ``harness_adapter`` kind owns Claude's settings, hook argv and the
SessionStart path vector. A Claude op that needs the daemon URL replies
``{"facts": null}``; :func:`claude_facts` answers it. The SessionStart hook
starts the daemon and asks the runtime to rewrite the managed hooks.
"""

from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .harness.base import HarnessContext
    from .harness.native_harness import NativeHarnessAdapter

CLAUDE_GUARD_DAEMON_HOOK_MARKER = "HOL_GUARD_CLAUDE_DAEMON_HOOK"
CLAUDE_GUARD_SESSION_START_HOOK_MARKER = "HOL_GUARD_CLAUDE_SESSION_START_HOOK"
_HARNESS = "claude-code"
_STALE_DAEMON_HOOK = (
    "This HOL Guard hook predates the native runtime, so Guard blocked the call. Run `hol-guard repair`."
)


def _daemon_module():
    return importlib.import_module(".native_daemon_manage", __package__)


def guard_daemon_url_for_home(guard_home: Path) -> str:
    return _daemon_module().guard_daemon_url_for_home(guard_home)


def load_guard_daemon_url(guard_home: Path) -> str | None:
    return _daemon_module().load_guard_daemon_url(guard_home)


def claude_facts(guard_home: Path) -> str:
    """What only this process knows about the daemon the hooks reach."""
    return json.dumps({"daemon_url": load_guard_daemon_url(guard_home) or guard_daemon_url_for_home(guard_home)})


def _claude_adapter() -> NativeHarnessAdapter:
    from .harness.native_harness import NativeHarnessAdapter
    from .harness.registry import get_adapter

    adapter = get_adapter(_HARNESS)
    if not isinstance(adapter, NativeHarnessAdapter):
        raise RuntimeError("claude-code adapter is not registered")
    return adapter


def claude_argv(which: str, context: HarnessContext) -> tuple[str, ...]:
    """One of Claude's hook argv (``hook``, ``daemon``, ``session_start``) as an install writes it."""
    return tuple(str(part) for part in _claude_adapter().run_op("argv", context, which=which)["argv"])


def claude_hook_command(context: HarnessContext) -> str:
    """The fallback hook argv as one shell command line."""
    from .harness.base import _shell_command

    return _shell_command(claude_argv("hook", context))


def _refresh_owned(adapter: NativeHarnessAdapter, context: HarnessContext) -> None:
    from .native_owned import owned_adapter_mutation

    # The native SessionStart lane hands off to this refresh whenever its
    # recorded runtime build differs from the installed one, which is true
    # after every package upgrade. The runtime rewrites the entries, which
    # moves the next session back onto the native lane.
    def refresh_runtime_hook_urls(adapter: NativeHarnessAdapter, context: HarnessContext) -> None:
        adapter.run_op("refresh", context)

    owned_adapter_mutation(refresh_runtime_hook_urls)(adapter, context)


def refresh_claude_hooks(*, home_dir: Path, workspace_dir: Path | None, guard_home: Path) -> None:
    """Rewrite the managed Claude hooks with this build's argv, under the install lock."""
    from .harness.base import HarnessContext

    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
    _refresh_owned(_claude_adapter(), context)


def _run_session_start_from_argv(argv: Sequence[str]) -> int:
    """Start the daemon and refresh the managed hooks from the hook's path vector."""
    from .harness.base import HarnessContext
    from .harness.native_harness import ask
    from .native_context import bound_context_digest_home

    home = Path.home()
    # Every native request here, the description included, answers for the
    # hook's Guard home rather than the default one. A vector the runtime would
    # refuse binds the default home, so nothing is provisioned under it.
    well_formed = 2 <= len(argv) <= 3 and all(part and "\x00" not in part for part in argv)
    claimed = Path(argv[0]) if well_formed and Path(argv[0]).is_absolute() else home / ".hol-guard"
    context = HarnessContext(home_dir=home, guard_home=claimed, workspace_dir=None)
    with bound_context_digest_home(claimed):
        try:
            paths = ask("session_start", context, harness=_HARNESS, argv=list(argv))
        except ValueError as error:
            raise SystemExit(str(error)) from error
        guard_home = Path(paths["guard_home"])
        workspace = paths.get("workspace")
        _daemon_module().ensure_guard_daemon(guard_home)
        refresh_claude_hooks(
            home_dir=Path(paths["home"]),
            workspace_dir=None if workspace is None else Path(workspace),
            guard_home=guard_home,
        )
    output = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": paths["context"]}}
    print(json.dumps(output, separators=(",", ":")))
    return 0


def run_frozen_claude_hook(argv: Sequence[str]) -> int:
    """Dispatch ``<marker> <args...>`` to the SessionStart refresh.

    A daemon hook command written by an older frozen build has no Python
    launcher left to run it: Claude Code blocks the call on exit code 2 and
    shows the repair hint, and SessionStart or repair rewrites the command.
    """
    if not argv:
        raise SystemExit("claude_frozen_hook expects a hook marker")
    marker, rest = argv[0], list(argv[1:])
    if marker == CLAUDE_GUARD_DAEMON_HOOK_MARKER:
        sys.stderr.write(_STALE_DAEMON_HOOK + "\n")
        return 2
    if marker == CLAUDE_GUARD_SESSION_START_HOOK_MARKER:
        return _run_session_start_from_argv(rest)
    raise SystemExit("claude_frozen_hook received an unknown hook marker")


__all__ = [
    "CLAUDE_GUARD_DAEMON_HOOK_MARKER",
    "CLAUDE_GUARD_SESSION_START_HOOK_MARKER",
    "claude_facts",
    "guard_daemon_url_for_home",
    "load_guard_daemon_url",
    "refresh_claude_hooks",
    "run_frozen_claude_hook",
]
