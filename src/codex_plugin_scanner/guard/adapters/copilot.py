"""Microsoft Copilot through the native ``harness_adapter`` kind.

The kind owns Copilot's paths, detection, the lifecycle locks and signed
state, which hook entries are Guard's, the MCP plan, the install file plan
and the uninstall restores and rewrites. This module keeps what must run in
the Guard process: the bounded hook argv and the hook script it stages, the
isolated hook interpreter, the launcher environment, Guard's proxy argv for
each server, the shim and the ``--help`` probe subprocess.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..native_runner_authority import NativeRunnerAuthorityError
from .base import HarnessContext, PreparedHarnessInstall, _run_command_probe
from .native_harness import NativeHarnessAdapter, ask, detection_from, planned_files

if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile

_HARNESS = "copilot"
_PROXY = "copilot-mcp-proxy"
_GUARD_HOOK_INTERNAL_TIMEOUT_SECONDS = 25
_UNANSWERED = (
    "Guard could not read which Copilot hooks it installed; the native Guard runtime did not answer. "
    "Run `hol-guard doctor copilot` and try again."
)
# Ops that read or rewrite Guard's hook entries; without the runtime none of them may touch a file.
_HOOK_OPS = frozenset({"hook_spec", "install_detection", "prepare_install", "uninstall"})


class CopilotHookOwnershipError(RuntimeError):
    """The native runtime could not say which Copilot hook commands Guard wrote."""


def _ask(op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    try:
        return ask(op, context, harness=_HARNESS, **fields)
    except NativeRunnerAuthorityError as error:
        if op in _HOOK_OPS:
            raise CopilotHookOwnershipError(_UNANSWERED) from error
        raise
    except RuntimeError as error:
        if str(error) == _UNANSWERED:
            raise CopilotHookOwnershipError(_UNANSWERED) from error
        raise


def _hook_fields(context: HarnessContext, staged: list[TransitionFile]) -> dict[str, object]:
    """Guard's bounded hook argv for each hooks object, and the isolated bridge."""
    from .bounded_cli_hook_bridge import bounded_cli_hook_command, bounded_hook_script_path
    from .isolated_hook_python import isolated_cursor_hook_python

    spec = _ask("hook_spec", context)

    def argv(cli_args: list[str]) -> list[str]:
        return list(
            bounded_cli_hook_command(
                python_executable=sys.executable,
                package_root=Path(__file__).resolve().parents[3],
                guard_home=context.guard_home,
                cli_args=[str(part) for part in cli_args],
                harness=_HARNESS,
                timeout_seconds=int(spec["timeout_seconds"]),
                prepared_files=staged,
            )
        )

    workspace = spec["workspace_cli_args"]
    script = bounded_hook_script_path(context.guard_home, _HARNESS)
    return {
        "config_argv": argv(spec["cli_args"]),
        "workspace_argv": None if workspace is None else argv(workspace),
        "interpreter": isolated_cursor_hook_python(),
        "script": None if script is None else str(script),
    }


def _server_fields(context: HarnessContext, found: dict[str, Any]) -> dict[str, object]:
    """Guard's entry for each managed server and the relaunch of each proxy entry."""
    from ..launcher import merge_guard_launcher_env
    from ..stable_guard_cli import guard_cli_launcher
    from .mcp_relay_native import mcp_proxy_launch
    from .mcp_servers import managed_stdio_servers, proxy_launcher_entry, skipped_stdio_server_names

    detection = detection_from(_HARNESS, context, found)
    managed = [
        [
            server.name,
            server.source_scope,
            server.config_path,
            proxy_launcher_entry(proxy_command=_PROXY, context=context, server=server),
        ]
        for server in managed_stdio_servers(detection)
    ]
    refresh = []
    for rows in found["refresh"]:
        launches = []
        for python_args, env in rows:
            command, args = mcp_proxy_launch(guard_cli_launcher(), python_args)
            launches.append({"command": command, "args": args, "env": merge_guard_launcher_env(env)})
        refresh.append(launches)
    return {
        "managed": json.dumps(managed),
        "refresh": json.dumps(refresh),
        "skipped": json.dumps(list(skipped_stdio_server_names(detection))),
        "hook_env": json.dumps(merge_guard_launcher_env()),
    }


class CopilotHarnessAdapter(NativeHarnessAdapter):
    """Copilot CLI's inline hooks, the VS Code workspace hook file and the MCP configs."""

    def __init__(self) -> None:
        super().__init__(_HARNESS, (), "")

    def install(self, context: HarnessContext) -> dict[str, object]:
        return self._prepared_install(context, create_key=True).publish(context.guard_home)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Prepare a rebind using existing enrolled lifecycle authority; never create a key."""
        return self._prepared_install(context, create_key=False)

    def _prepared_install(self, context: HarnessContext, *, create_key: bool) -> PreparedHarnessInstall:
        from ..runtime_transition import RuntimeTransition, TransitionError, TransitionFile
        from ..shims import prepare_guard_shim

        found = _ask("install_detection", context, create_key=create_key)
        if set(found) == {"transition_error"}:
            raise TransitionError(str(found["transition_error"]))
        staged: list[TransitionFile] = []
        fields = {**_hook_fields(context, staged), **_server_fields(context, found)}
        shim = prepare_guard_shim(_HARNESS, context)
        answer = _ask(
            "prepare_install",
            context,
            create_key=create_key,
            digest=found["digest"],
            shim=json.dumps(shim.manifest, default=str),
            **fields,
        )
        if set(answer) == {"transition_error"}:
            raise TransitionError(str(answer["transition_error"]))
        key = TransitionFile.identity_dependency(context.guard_home / "managed/adapter-state.key")
        unique: dict[Path, TransitionFile] = {}
        for change in (key, *staged, *planned_files(answer), *shim.files):
            if change.path in unique and change != unique[change.path]:
                raise TransitionError("adapter_preparation_generation_conflict")
            unique[change.path] = change
        prepared = PreparedHarnessInstall(tuple(unique.values()), json.loads(str(answer["manifest"])))
        RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
        return prepared

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        from ..shims import remove_guard_shim

        # Uninstall only reads which entries Guard owns; the staged hook script is never written.
        finish = _ask("uninstall", context, **_hook_fields(context, []))["finish"]
        shim = remove_guard_shim(_HARNESS, context)
        answer = _ask("finish_uninstall", context, shim=json.dumps(shim, default=str), finish=finish)
        return json.loads(str(answer["manifest"]))

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        return [str(part) for part in _ask("launch_command", context, args=passthrough_args)["argv"]]

    def preview_launch_commands(self, context: HarnessContext, passthrough_args: list[str]) -> tuple[list[str], ...]:
        return (self.launch_command(context, passthrough_args),)

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        argv = _ask("runtime_probe", context)["argv"]
        return None if argv is None else _run_command_probe([str(part) for part in argv])


__all__ = ["CopilotHarnessAdapter", "CopilotHookOwnershipError"]
