"""Cursor through the native ``harness_adapter`` kind.

The kind owns Cursor's paths, detection, the editor MCP plan and its state,
the hooks merge, the hook script, the attestation key, the install file plans,
the uninstall restores, hook health and the rebind decision. An op that needs
something only the Guard process knows replies with one key, and this module
answers it and asks again: ``facts`` (the attested Guard CLI, the native hook
bridge and the interpreters), ``probe`` (whether ``cursor agent --help``
runs), ``expand`` (8.3 short names), ``render`` (Windows hook command lines),
``relaunch`` (Guard's proxy argv) and ``servers`` (which detected servers
Guard manages, with their proxy entries). The shims, the ``mcp list`` probe
and the frozen hook script also stay here.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from .base import HarnessContext, PreparedHarnessInstall, _run_command_probe
from .native_harness import NativeHarnessAdapter, ask, detection_from, planned_files

_HARNESS = "cursor"
_PROXY = "cursor-mcp-proxy"
_NATIVE_BRIDGE_FEATURE = "cursor-hook-bridge-v1"
# Each reply names something new, so an op settles within a handful of rounds.
_REPLY_LIMIT = 32
_AGENT_SHIM = {"launcher_name": "cursor-agent", "display_name": "Cursor CLI (cursor-agent)"}
_CURSOR_SHIM = {"launcher_name": "cursor", "display_name": "Cursor CLI (cursor agent)"}


@lru_cache(maxsize=8)
def _cursor_agent_subcommand_available(cursor_path: str) -> bool:
    probe = _run_command_probe([cursor_path, "agent", "--help"], timeout_seconds=5)
    return probe.get("ok") is True or probe.get("return_code") == 0


def _dumps(value: object) -> str:
    return json.dumps(value, default=str)


def _facts(context: HarnessContext) -> str:
    """What this process knows about the Guard CLI the hooks launch."""
    from ..frozen_runtime_commands import frozen_daemon_recovery_command
    from ..stable_guard_cli import frozen_cli_path_is_runnable, frozen_launcher_is_prune_safe, resolve_frozen_guard_cli
    from .guard_cli_attestation import resolve_attested_guard_cli
    from .isolated_hook_python import isolated_cursor_hook_python
    from .native_hook_bridge import native_hook_bridge_executable

    bridge = native_hook_bridge_executable(_NATIVE_BRIDGE_FEATURE, guard_home=context.guard_home)
    attestation: dict[str, object]
    recovery: list[str] | None = None
    try:
        attested = resolve_attested_guard_cli(context)
    except RuntimeError as error:
        attestation = {"error": str(error)}
    else:
        python = attested.python
        attestation = {
            "command": list(attested.command),
            "identity": attested.manifest_payload(),
            "python": None
            if python is None
            else {
                "executable": str(python.executable),
                "target": str(python.identity.target_path),
                "import_roots": [str(root) for root in python.import_roots],
            },
        }
        if python is None:
            recovery = list(frozen_daemon_recovery_command(context.guard_home, context.home_dir))
    frozen = bool(getattr(sys, "frozen", False))
    launcher = resolve_frozen_guard_cli() if frozen else None
    return _dumps(
        {
            "bridge": None if bridge is None else str(bridge),
            "attestation": attestation,
            "interpreter": isolated_cursor_hook_python(),
            "frozen": frozen,
            "frozen_launcher": launcher,
            "executable": sys.executable,
            "frozen_recovery": recovery,
            "can_rebind": launcher is not None
            and frozen_launcher_is_prune_safe(launcher)
            and frozen_cli_path_is_runnable(Path(launcher)),
        }
    )


def _rendered(argv: list[str]) -> str | None:
    from ..codex_hook_command_line import render_hook_command

    try:
        return render_hook_command(argv, windows=True)
    except ValueError:
        return None


def _relaunch(args: list[str]) -> list[object]:
    from ..stable_guard_cli import guard_cli_launcher
    from .mcp_relay_native import mcp_proxy_launch, python_proxy_launch

    _, python_args = python_proxy_launch(None, tuple(args))
    command, launch_args = mcp_proxy_launch(guard_cli_launcher(), python_args)
    return [command, list(launch_args)]


def _servers(context: HarnessContext, detected: dict[str, Any]) -> str:
    """The servers Guard manages in a detection, with Guard's entry for each."""
    from .mcp_servers import (
        managed_stdio_servers,
        observable_stdio_servers_with_proxy,
        proxy_launcher_entry,
        skipped_stdio_server_names,
    )

    detection = detection_from(_HARNESS, context, detected)
    managed = []
    for server in managed_stdio_servers(detection):
        entry = proxy_launcher_entry(proxy_command=_PROXY, context=context, server=server)
        env = entry.pop("env", None)
        entry["type"] = "stdio"
        if env is not None:
            entry["env"] = env
        managed.append([server.name, server.source_scope, server.config_path, entry])
    observed = [
        [server.name, server.source_scope, server.config_path]
        for server in observable_stdio_servers_with_proxy(detection)
    ]
    skipped = list(skipped_stdio_server_names(detection))
    return _dumps({"detect": detected, "managed": managed, "skipped": skipped, "observed": observed})


def _answer(context: HarnessContext, op: str, key: str, value: Any, fields: dict[str, Any]) -> None:
    """Merge this process's answer to one reply into the request."""
    from ..codex_hook_command_line import _expand_short_token
    from .hook_python import disposable_guard_hook_probe

    if key == "facts":
        if op == "prepare_install":
            with disposable_guard_hook_probe():
                fields["facts"] = _facts(context)
        else:
            fields["facts"] = _facts(context)
    elif key == "probe":
        fields["cursor_probe"] = _cursor_agent_subcommand_available(str(value))
    elif key == "expand":
        fields["long_paths"] = {**fields.get("long_paths", {}), **{str(t): _expand_short_token(str(t)) for t in value}}
    elif key == "render":
        fields["rendered"] = [*fields.get("rendered", []), *([argv, _rendered(argv)] for argv in value)]
    elif key == "relaunch":
        fields["relaunch"] = [*fields.get("relaunch", []), *([args, _relaunch(args)] for args in value)]
    elif key == "servers":
        fields["servers"] = _servers(context, value)
    else:
        raise ValueError("Cursor adapter reply is malformed")


def _cursor_ask(op: str, context: HarnessContext, *, timeout_seconds: float | None = None, **fields: Any) -> dict:
    """Run one op, answering each reply until it settles."""
    for _ in range(_REPLY_LIMIT):
        answer = ask(op, context, harness=_HARNESS, timeout_seconds=timeout_seconds, **fields)
        reply = answer.get("reply")
        if set(answer) != {"reply"}:
            return answer
        if not isinstance(reply, dict) or len(reply) != 1:
            raise ValueError("Cursor adapter reply is malformed")
        ((key, value),) = reply.items()
        _answer(context, op, key, value, fields)
    raise RuntimeError("Cursor adapter request did not settle")


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
    manifest = _prepared(_cursor_ask(op, context)).publish(context.guard_home)
    _cursor_ask("verify", context)
    return manifest


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
    if ask("frozen_hook_script", context, harness=_HARNESS, script=str(argv[0])).get("accepted") is not True:
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

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        argv = self._ask("runtime_probe", context)["argv"]
        if argv is None:
            return None
        payload = _run_command_probe([str(part) for part in argv])
        payload["reported_artifacts"] = self._ask("runtime_probe", context, stdout=payload.get("stdout"))[
            "reported_artifacts"
        ]
        return payload

    def _surface(self, context: HarnessContext, surface: str) -> str:
        return str(self._ask("surface", context, surface=surface)["surface"])

    def install(self, context: HarnessContext, *, surface: str = "editor") -> dict[str, object]:
        surface = self._surface(context, surface)
        if surface == "cli":
            return self._install_cli(context)
        editor = _install_hooks(context, "install")
        if surface == "editor":
            return editor
        return self._all(context, editor, self._install_cli(context), active=True)

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

    def uninstall(self, context: HarnessContext, *, surface: str = "editor") -> dict[str, object]:
        surface = self._surface(context, surface)
        if surface == "editor":
            return _manifest(self._ask("uninstall", context))
        cli = self._uninstall_cli(context)
        if surface == "cli":
            return cli
        editor = _manifest(self._ask("uninstall", context))
        return self._all(context, editor, cli, active=False)

    def _all(
        self, context: HarnessContext, editor: dict[str, object], cli: dict[str, object], *, active: bool
    ) -> dict[str, object]:
        return _manifest(self._ask("all_manifest", context, editor=_dumps(editor), cli=_dumps(cli), active=active))

    def _install_cli(self, context: HarnessContext) -> dict[str, object]:
        from ..shims import ensure_guard_shim_path_in_shell_profile, install_guard_shim

        agent = install_guard_shim(_HARNESS, context, **_AGENT_SHIM)
        cursor = install_guard_shim(_HARNESS, context, **_CURSOR_SHIM)
        return self._cli_manifest(context, agent, cursor, ensure_guard_shim_path_in_shell_profile(context))

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

    def _uninstall_cli(self, context: HarnessContext) -> dict[str, object]:
        from ..shims import remove_guard_shim

        shim = remove_guard_shim(
            _HARNESS,
            context,
            launcher_name="cursor-agent",
            legacy_launcher_names=self.legacy_launcher_names,
            display_name="Cursor CLI",
        )
        return _manifest(self._ask("cli_uninstalled", context, shim=_dumps(shim)))


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
