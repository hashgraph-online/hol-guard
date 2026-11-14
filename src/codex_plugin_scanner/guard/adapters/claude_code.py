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
from .native_hook_bridge import native_hook_bridge_executable

_HARNESS = "claude-code"
CLAUDE_GUARD_DAEMON_HOOK_MARKER = "HOL_GUARD_CLAUDE_DAEMON_HOOK"
CLAUDE_GUARD_SESSION_START_HOOK_MARKER = "HOL_GUARD_CLAUDE_SESSION_START_HOOK"
NATIVE_CLAUDE_HOOK_FEATURE = "claude-hook-bridge-v1"
NATIVE_CLAUDE_SESSION_START_FEATURE = "claude-session-start-v1"
# One reply, ``facts``, settles every op.
_REPLY_LIMIT = 2


def _daemon_module():
    return importlib.import_module("..native_daemon_manage", __package__)


def guard_daemon_url_for_home(guard_home: Path) -> str:
    return _daemon_module().guard_daemon_url_for_home(guard_home)


def load_guard_daemon_url(guard_home: Path) -> str | None:
    return _daemon_module().load_guard_daemon_url(guard_home)


def _native_bridge_executable(guard_home: Path) -> Path | None:
    """The validated native runtime when it can proxy Claude hooks itself."""
    return native_hook_bridge_executable(NATIVE_CLAUDE_HOOK_FEATURE, guard_home=guard_home)


def _recovery(guard_home: Path, home_dir: Path) -> list[str]:
    from ..codex_hook_launch_runtime import isolated_daemon_start_command
    from ..frozen_runtime_commands import frozen_daemon_recovery_command, is_frozen_guard_runtime

    if is_frozen_guard_runtime():
        # A frozen desktop core cannot run the Python ``-I -c`` bootstrap.
        return list(frozen_daemon_recovery_command(guard_home, home_dir))
    package_root = Path(__file__).resolve().parents[3]
    return list(isolated_daemon_start_command(sys.executable, package_root, guard_home, home_dir))


def _facts(context: HarnessContext) -> str:
    """What this process knows about the runtimes and CLI the hooks launch."""
    from ..runtime.harness_attribution import cursor_hook_query_extras
    from ..stable_guard_cli import guard_cli_launcher

    bridge = _native_bridge_executable(context.guard_home)
    session = native_hook_bridge_executable(NATIVE_CLAUDE_SESSION_START_FEATURE, guard_home=context.guard_home)
    runtime_build = None
    if session is not None and session == bridge:
        from ..native_runtime import native_runtime_status

        capabilities = native_runtime_status().capabilities
        if capabilities is not None:
            runtime_build = f"{capabilities.runtime_version}+{capabilities.build_sha}"
    frozen = bool(getattr(sys, "frozen", False))
    guard_home = context.guard_home
    return json.dumps(
        {
            "bridge": None if bridge is None else str(bridge),
            "session_runtime": None if session is None else str(session),
            "runtime_build": runtime_build,
            "frozen": frozen,
            "launcher": guard_cli_launcher() if frozen else None,
            "python": sys.executable,
            "package_root": str(Path(__file__).resolve().parents[3]),
            "daemon_url": load_guard_daemon_url(guard_home) or guard_daemon_url_for_home(guard_home),
            "query_extras": [[str(key), str(value)] for key, value in cursor_hook_query_extras().items()],
            "recovery_home": None if bridge is None else _recovery(guard_home, Path.home()),
            "recovery_context": None if bridge is None else _recovery(guard_home, context.home_dir),
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
    """Dispatch ``<marker> <args...>`` to the daemon bridge or the SessionStart refresh."""
    if not argv:
        raise SystemExit("claude_frozen_hook expects a hook marker")
    marker, rest = argv[0], list(argv[1:])
    if marker == CLAUDE_GUARD_DAEMON_HOOK_MARKER:
        from .claude_daemon_hook_bridge import _bridge_config_from_argv, main

        config = _bridge_config_from_argv(["claude_daemon_hook_bridge", *rest])
        return main(
            state_path=config["state_path"],
            fallback_daemon_url=config["fallback_daemon_url"],
            fallback_command=config["fallback_command"],
            query=config["query"],
        )
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
