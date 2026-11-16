"""Spec-driven steps of the generic native harness client.

``describe`` names which of these a harness takes: a hook-ownership failure
worded by the runtime, and a rebind planned from what the runtime detected.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..models import HarnessDetection

if TYPE_CHECKING:
    from .base import HarnessContext, PreparedHarnessInstall
    from .native_harness import NativeHarnessAdapter


class HookOwnershipError(RuntimeError):
    """The native runtime could not say which hook commands Guard wrote."""


def owned_ask(harness: str, owned: object, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    """``ask``, naming a hook-ownership failure as the harness's spec words it."""
    from ..native_runner_authority import NativeRunnerAuthorityError
    from .native_harness import ask

    if not isinstance(owned, dict):
        return ask(op, context, harness=harness, **fields)
    message = str(owned["message"])
    try:
        return ask(op, context, harness=harness, **fields)
    except NativeRunnerAuthorityError as error:
        if op in owned["ops"]:
            raise HookOwnershipError(message) from error
        raise
    except RuntimeError as error:
        if str(error) == message:
            raise HookOwnershipError(message) from error
        raise


def prepared_from_detection(
    adapter: NativeHarnessAdapter, context: HarnessContext, *, create_key: bool
) -> PreparedHarnessInstall:
    """A rebind planned from what the runtime detected, using existing enrolled authority."""
    from ..runtime_transition import RuntimeTransition, TransitionError, TransitionFile
    from ..shims import prepare_guard_shim
    from .base import PreparedHarnessInstall
    from .native_harness import planned_files

    found = adapter._ask("install_detection", context, create_key=create_key)
    if set(found) == {"transition_error"}:
        raise TransitionError(str(found["transition_error"]))
    shim = prepare_guard_shim(adapter.harness, context)
    answer = adapter._ask(
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


def detection_from(harness: str, context: HarnessContext, answer: dict[str, Any]) -> HarnessDetection:
    """The detection a ``detect``-shaped answer describes."""
    from ..aibom_detection import _artifacts_from_payload, extend_detection_with_workspace_aibom

    artifacts = _artifacts_from_payload(answer)
    if answer.get("firewall") is True:
        from ..runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall

        artifacts = tuple(enrich_artifact_with_mcp_skill_firewall(artifact) for artifact in artifacts)
    detection = HarnessDetection(
        harness=harness,
        installed=answer.get("installed") is True,
        command_available=answer.get("command_available") is True,
        config_paths=tuple(str(path) for path in answer.get("config_paths", ())),
        artifacts=artifacts,
        warnings=tuple(str(warning) for warning in answer.get("warnings", ())),
    )
    if answer.get("workspace_aibom") is not True:
        return detection
    return extend_detection_with_workspace_aibom(
        detection, home_dir=context.home_dir, workspace_dir=context.workspace_dir
    )


__all__ = ["HookOwnershipError", "detection_from", "owned_ask", "prepared_from_detection"]
