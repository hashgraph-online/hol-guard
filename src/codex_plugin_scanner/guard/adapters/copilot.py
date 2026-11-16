"""Microsoft Copilot through the native ``harness_adapter`` kind.

The kind owns Copilot's paths, detection, the lifecycle locks and signed
state, the bounded hook argv, which hook entries are Guard's, the MCP plan,
the shim and the install and uninstall publishes (``apply_install`` and
``apply_uninstall``). This module maps an unanswered hook op to the doctor
error, prepares a rebind and runs the ``--help`` probe subprocess.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..native_runner_authority import NativeRunnerAuthorityError
from .base import HarnessContext, PreparedHarnessInstall, _run_command_probe
from .native_harness import NativeHarnessAdapter, ask, planned_files

if TYPE_CHECKING:
    from ..runtime_transition import TransitionFile

_HARNESS = "copilot"
_UNANSWERED = (
    "Guard could not read which Copilot hooks it installed; the native Guard runtime did not answer. "
    "Run `hol-guard doctor copilot` and try again."
)
# Ops that read or rewrite Guard's hook entries; without the runtime none of them may touch a file.
_HOOK_OPS = frozenset({"install_detection", "prepare_install", "apply_install", "apply_uninstall"})


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


class CopilotHarnessAdapter(NativeHarnessAdapter):
    """Copilot CLI's inline hooks, the VS Code workspace hook file and the MCP configs."""

    def __init__(self) -> None:
        super().__init__(_HARNESS, (), "")

    def _ask(self, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
        return _ask(op, context, **fields)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Prepare a rebind using existing enrolled lifecycle authority; never create a key."""
        return self._prepared_install(context, create_key=False)

    def _prepared_install(self, context: HarnessContext, *, create_key: bool) -> PreparedHarnessInstall:
        from ..runtime_transition import RuntimeTransition, TransitionError, TransitionFile
        from ..shims import prepare_guard_shim

        found = _ask("install_detection", context, create_key=create_key)
        if set(found) == {"transition_error"}:
            raise TransitionError(str(found["transition_error"]))
        shim = prepare_guard_shim(_HARNESS, context)
        answer = _ask(
            "prepare_install",
            context,
            create_key=create_key,
            digest=found["digest"],
            shim=json.dumps(shim.manifest, default=str),
        )
        if set(answer) == {"transition_error"}:
            raise TransitionError(str(answer["transition_error"]))
        key = TransitionFile.identity_dependency(context.guard_home / "managed/adapter-state.key")
        unique: dict[Path, TransitionFile] = {}
        for change in (key, *planned_files(answer), *shim.files):
            if change.path in unique and change != unique[change.path]:
                raise TransitionError("adapter_preparation_generation_conflict")
            unique[change.path] = change
        prepared = PreparedHarnessInstall(tuple(unique.values()), json.loads(str(answer["manifest"])))
        RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
        return prepared

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        return [str(part) for part in _ask("launch_command", context, args=passthrough_args)["argv"]]

    def preview_launch_commands(self, context: HarnessContext, passthrough_args: list[str]) -> tuple[list[str], ...]:
        return (self.launch_command(context, passthrough_args),)

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        argv = _ask("runtime_probe", context)["argv"]
        return None if argv is None else _run_command_probe([str(part) for part in argv])


__all__ = ["CopilotHarnessAdapter", "CopilotHookOwnershipError"]
