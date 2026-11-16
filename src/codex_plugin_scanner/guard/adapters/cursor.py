"""Cursor through the native ``harness_adapter`` kind.

The kind owns Cursor's paths, detection, the editor MCP plan and its state,
the hooks merge, the hook script, the attestation key, the install file plans,
the uninstall restores, hook health and the rebind decision. An op that needs
something only the Guard process knows replies with one key, and this module
answers it and asks again: ``facts`` (the attested Guard CLI, the native hook
bridge and the interpreters), ``probe`` (whether ``cursor agent --help``
runs) and ``servers`` (which detected servers Guard manages, with
their proxy entries). ``install`` and ``uninstall`` run every surface in
one native apply op each; the frozen hook script stays here.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .base import HarnessContext, PreparedHarnessInstall
from .native_harness import NativeHarnessAdapter, ask, detection_from, planned_files

_HARNESS = "cursor"
_AGENT_SHIM = {"launcher_name": "cursor-agent", "display_name": "Cursor CLI (cursor-agent)"}
_CURSOR_SHIM = {"launcher_name": "cursor", "display_name": "Cursor CLI (cursor agent)"}


def _dumps(value: object) -> str:
    return json.dumps(value, default=str)


def _cursor_ask(
    op: str, context: HarnessContext, *, timeout_seconds: float | None = None, **fields: Any
) -> dict[str, Any]:
    """Run one op; the native runtime probes the Cursor CLI itself."""
    return ask(op, context, harness=_HARNESS, timeout_seconds=timeout_seconds, **fields)


def _prepared(answer: dict[str, Any]) -> PreparedHarnessInstall:
    from ..runtime_transition import RuntimeTransition, TransitionError, TransitionFile

    if set(answer) == {"transition_error"}:
        raise TransitionError(str(answer["transition_error"]))
    keys = [TransitionFile.identity_dependency(Path(path)) for path in answer.get("identity", ())]
    prepared = PreparedHarnessInstall((*keys, *planned_files(answer)), json.loads(str(answer["manifest"])))
    RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
    return prepared


def _manifest(answer: dict[str, Any]) -> dict[str, object]:
    return json.loads(str(answer["manifest"]))


def _install_hooks(context: HarnessContext, op: str) -> dict[str, object]:
    """Publish the plan, then require the hooks Cursor now reads to be Guard's."""
    from .. import native_transition_files
    from ..codex_install_transaction import require_codex_install_owner
    from ..runtime_transition import assert_transition_mutation_allowed

    require_codex_install_owner(context.guard_home)
    assert_transition_mutation_allowed(context.guard_home)
    # The plan also retires the project-local hooks an older install wrote.
    answer = _cursor_ask(
        "apply_plan",
        context,
        plan_op=op,
        removals=True,
        transition=native_transition_files.transition_context(),
    )
    native_transition_files.settle(answer.get("publish"))
    _cursor_ask("verify", context)
    return _manifest(answer)


def install_cursor_hooks(context: HarnessContext, *, actor: str = "cursor-hooks") -> dict[str, object]:
    """Install only Cursor's native hooks and the script they run."""
    from ..codex_install_transaction import codex_install_transaction

    with codex_install_transaction(context.guard_home, context.guard_home / "managed", actor=actor):
        return _install_hooks(context, "hooks_install")


def rebind_stale_cursor_hooks(guard_home: Path, *, home_dir: Path) -> dict[str, object]:
    """Rewrite managed Cursor hooks that still bake a pruneable Core path or an outdated script."""
    from ..runtime_transition import TransitionError

    context = HarnessContext(home_dir=home_dir, guard_home=guard_home, workspace_dir=None)
    answer = _cursor_ask("rebind", context)
    if answer.get("install") is not True:
        return answer
    try:
        install_cursor_hooks(context, actor="cursor-hook-rebind")
    except (OSError, RuntimeError, ValueError, TransitionError) as error:
        return {"rebound": False, "reason": "cursor_hook_script_rebind_failed", "error": str(error)}
    return {"rebound": True, "reason": "cursor_hook_script_rebound"}


def cursor_native_hook_state(context: HarnessContext) -> dict[str, object]:
    """Cursor's registration, scripts and the attested CLI identity they name."""
    return json.loads(str(_cursor_ask("hook_state", context)["state"]))


def cursor_runtime_hooks_verified(context: HarnessContext) -> bool | None:
    """Whether live Cursor hooks still intercept Guard's blocking events."""
    verified = _cursor_ask("health", context)["verified"]
    return verified if isinstance(verified, bool) else None


def cursor_cli_detected(context: HarnessContext) -> bool:
    return _cursor_ask("cli_detected", context)["value"] is True


def cursor_cli_shim_installed(context: HarnessContext) -> bool:
    return _cursor_ask("cli_shim_installed", context)["value"] is True


def run_frozen_cursor_hook(argv: Sequence[str]) -> int:
    """Execute the installed Cursor hook script from a frozen Guard binary."""
    import runpy

    if not argv:
        return 2
    home = Path.home()
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    # A runtime that cannot answer refuses the script the way a bad path does.
    # Gated events are ``failClosed``, so Cursor still blocks them.
    try:
        accepted = ask("frozen_hook_script", context, harness=_HARNESS, script=str(argv[0])).get("accepted")
    except (OSError, RuntimeError, ValueError):
        return 3
    if accepted is not True:
        return 3
    try:
        runpy.run_path(str(argv[0]), run_name="__main__")
    except SystemExit as error:
        code = error.code
        if code is None:
            return 0
        return code if isinstance(code, int) else 1
    return 0


class CursorHarnessAdapter(NativeHarnessAdapter):
    """Cursor's editor MCP config, its native hooks and the ``cursor-agent`` CLI."""

    legacy_launcher_names = ("cursor",)
    # The editor runs Guard's hooks on its own, so a missing `cursor-agent` says
    # nothing about whether Cursor is installed.
    command_absence_proves_uninstalled = False

    def __init__(self) -> None:
        super().__init__(_HARNESS, (), "cursor-agent")
        self.executable = "cursor-agent"

    def _ask(self, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
        return _cursor_ask(op, context, **fields)

    def detect(self, context: HarnessContext) -> Any:
        from ..aibom_detection import _AIBOM_DISCOVERY_TIMEOUT_SECONDS, NativeAibomError
        from ..native_runner_authority import NativeRunnerAuthorityError

        # Discovery walks the workspace, so it keeps the longer AIBOM deadline.
        try:
            answer = _cursor_ask("detect", context, timeout_seconds=_AIBOM_DISCOVERY_TIMEOUT_SECONDS)
        except NativeRunnerAuthorityError as error:
            raise NativeAibomError(str(error)) from error
        return detection_from(self.harness, context, answer)

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        return [str(part) for part in self._ask("launch_command", context, args=passthrough_args)["argv"]]

    def _surface(self, context: HarnessContext, surface: str) -> str:
        return str(self._ask("surface", context, surface=surface)["surface"])

    def prepare_install(self, context: HarnessContext, *, surface: str = "editor") -> PreparedHarnessInstall:
        """Prepare every selected surface before any binding or profile publication."""
        from ..runtime_transition import RuntimeTransition

        surface = self._surface(context, surface)
        if surface == "cli":
            return self._prepare_cli(context)
        editor = _prepared(self._ask("prepare_install", context))
        if surface == "editor":
            return editor
        cli = self._prepare_cli(context)
        prepared = PreparedHarnessInstall(
            (*editor.files, *cli.files), self._all(context, editor.manifest, cli.manifest, active=True)
        )
        RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
        return prepared

    def _all(
        self, context: HarnessContext, editor: dict[str, object], cli: dict[str, object], *, active: bool
    ) -> dict[str, object]:
        return _manifest(self._ask("all_manifest", context, editor=_dumps(editor), cli=_dumps(cli), active=active))

    def _prepare_cli(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..runtime_transition import RuntimeTransition
        from ..shims import prepare_guard_shim, prepare_guard_shim_shell_profile

        agent = prepare_guard_shim(_HARNESS, context, **_AGENT_SHIM)
        cursor = prepare_guard_shim(_HARNESS, context, **_CURSOR_SHIM)
        profile = prepare_guard_shim_shell_profile(context)
        files = (*agent.files, *cursor.files, *profile.files)
        RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
        manifest = self._cli_manifest(context, agent.manifest, cursor.manifest, profile.manifest)
        return PreparedHarnessInstall(files, manifest)

    def _cli_manifest(
        self, context: HarnessContext, agent: dict[str, object], cursor: dict[str, object], profile: dict[str, object]
    ) -> dict[str, object]:
        fields = {"agent_shim": _dumps(agent), "cursor_shim": _dumps(cursor), "profile": _dumps(profile)}
        return _manifest(self._ask("cli_manifest", context, **fields))


__all__ = [
    "CursorHarnessAdapter",
    "cursor_cli_detected",
    "cursor_cli_shim_installed",
    "cursor_native_hook_state",
    "cursor_runtime_hooks_verified",
    "install_cursor_hooks",
    "rebind_stale_cursor_hooks",
    "run_frozen_cursor_hook",
]
