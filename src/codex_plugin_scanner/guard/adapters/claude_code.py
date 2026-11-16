"""Claude Code through the native ``harness_adapter`` kind.

The kind owns Claude's paths, detection, the hook entries in
``~/.claude/settings.json`` (the SessionStart refresh, every runtime group the
contract names and the prune that removes them), the hook argv in its native,
frozen and source-checkout forms, the diagnostics that notice the entries gone
and the SessionStart path vector. An op that needs what only the Guard process
knows replies ``facts``, and this module answers it and asks again. The shim,
the daemon start the SessionStart hook runs, the ``claude --help`` probe and
the file publication stay here.
"""

from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..shims import prepare_guard_shim
from .base import HarnessContext, PreparedHarnessInstall, _owned_adapter_mutation, _run_command_probe, _shell_command
from .native_harness import NativeHarnessAdapter, ask, planned_files

_HARNESS = "claude-code"
CLAUDE_GUARD_DAEMON_HOOK_MARKER = "HOL_GUARD_CLAUDE_DAEMON_HOOK"
_STALE_DAEMON_HOOK = (
    "This HOL Guard hook predates the native runtime, so Guard blocked the call. Run `hol-guard repair`."
)
CLAUDE_GUARD_SESSION_START_HOOK_MARKER = "HOL_GUARD_CLAUDE_SESSION_START_HOOK"
# One reply, ``facts``, settles every op.
_REPLY_LIMIT = 2


def _daemon_module():
    return importlib.import_module("..native_daemon_manage", __package__)


def guard_daemon_url_for_home(guard_home: Path) -> str:
    return _daemon_module().guard_daemon_url_for_home(guard_home)


def load_guard_daemon_url(guard_home: Path) -> str | None:
    return _daemon_module().load_guard_daemon_url(guard_home)


def _facts(context: HarnessContext) -> str:
    """What only this process knows about the daemon the hooks reach."""
    from ..runtime.harness_attribution import cursor_hook_query_extras

    guard_home = context.guard_home
    return json.dumps(
        {
            "daemon_url": load_guard_daemon_url(guard_home) or guard_daemon_url_for_home(guard_home),
            "query_extras": [[str(key), str(value)] for key, value in cursor_hook_query_extras().items()],
        }
    )


def _claude_ask(op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    """Run one op, answering its ``facts`` reply."""
    for _ in range(_REPLY_LIMIT):
        answer = ask(op, context, harness=_HARNESS, **fields)
        if set(answer) != {"reply"}:
            return answer
        if answer["reply"] != {"facts": None}:
            raise ValueError("Claude Code adapter reply is malformed")
        fields["facts"] = _facts(context)
    raise RuntimeError("Claude Code adapter request did not settle")


def _argv(which: str, context: HarnessContext) -> tuple[str, ...]:
    return tuple(str(part) for part in _claude_ask("argv", context, which=which)["argv"])


def _run_session_start_from_argv(argv: Sequence[str]) -> int:
    """Start the daemon and refresh the managed hooks from the hook's path vector."""
    from ..native_context import bound_context_digest_home

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
        ClaudeCodeHarnessAdapter.refresh_installed_hook_urls(
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


class ClaudeCodeHarnessAdapter(NativeHarnessAdapter):
    """Claude Code's settings, hooks and workspace agents."""

    harness = _HARNESS
    executable = "claude"
    legacy_launcher_names = ("claude-code",)

    def __init__(self) -> None:
        super().__init__(_HARNESS, ("claude",), "claude")
        self.executable = "claude"

    def _ask(self, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
        return _claude_ask(op, context, **fields)

    @staticmethod
    def _hook_command(context: HarnessContext) -> str:
        return _shell_command(ClaudeCodeHarnessAdapter._hook_command_parts(context))

    @staticmethod
    def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        return _argv("hook", context)

    @staticmethod
    def _daemon_hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
        return _argv("daemon", context)

    @staticmethod
    def _session_start_command_parts(context: HarnessContext) -> tuple[str, ...]:
        return _argv("session_start", context)

    @classmethod
    def refresh_installed_hook_urls(cls, *, home_dir: Path, workspace_dir: Path | None, guard_home: Path) -> None:
        cls().refresh_runtime_hook_urls(
            HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
        )

    @_owned_adapter_mutation
    def refresh_runtime_hook_urls(self, context: HarnessContext) -> None:
        # The native SessionStart lane hands off to this refresh whenever its
        # recorded runtime build differs from the installed one, which is true
        # after every package upgrade. Rewriting the entry moves the next
        # session back onto the native lane.
        answer = self._ask("refresh", context)
        text = answer.get("text")
        if not isinstance(text, str):
            return
        settings_path = Path(answer["path"])
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(text, encoding="utf-8")

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        resolved_executable = self.resolved_executable(context)
        if resolved_executable is None:
            return None
        return _run_command_probe([resolved_executable, "--help"], timeout_seconds=5)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        shim = prepare_guard_shim(self.harness, context, **self._shim_names())
        answer = self._ask("prepare_install", context, shim=json.dumps(shim.manifest))
        return PreparedHarnessInstall((*shim.files, *planned_files(answer)), json.loads(answer["manifest"]))
