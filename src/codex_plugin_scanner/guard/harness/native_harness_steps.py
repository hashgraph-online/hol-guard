"""Spec-driven steps of the generic native harness client.

``describe`` names which of these a harness takes: a hook-ownership failure
worded by the runtime, and a rebind planned from what the runtime detected.
"""

from __future__ import annotations

import base64
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


def prepared_surfaces(
    adapter: NativeHarnessAdapter, context: HarnessContext, **surface: object
) -> PreparedHarnessInstall:
    """Every surface the runtime selects, planned in one op before any publication."""
    from ..runtime_transition import RuntimeTransition, TransitionError, TransitionFile
    from ..shims import shell_profile_facts, shim_interpreter
    from .base import PreparedHarnessInstall

    answer = adapter._ask(
        "prepare_surfaces",
        context,
        interpreter=shim_interpreter(),
        shell_profile=shell_profile_facts(context),
        **surface,
    )
    if set(answer) == {"transition_error"}:
        raise TransitionError(str(answer["transition_error"]))
    keys = [TransitionFile.identity_dependency(Path(path)) for path in answer.get("identity", ())]
    prepared = PreparedHarnessInstall((*keys, *planned_files(answer)), json.loads(str(answer["manifest"])))
    RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
    return prepared


def detection_from(harness: str, context: HarnessContext, answer: dict[str, Any]) -> HarnessDetection:
    """The detection a ``detect``-shaped answer describes."""
    from ..aibom_detection import _artifacts_from_payload, extend_detection_with_workspace_aibom

    artifacts = _artifacts_from_payload(answer)
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


__all__ = ["HookOwnershipError", "detection_from", "owned_ask", "planned_files", "prepared_from_detection"]


def native_warnings(
    adapter: NativeHarnessAdapter,
    detection: HarnessDetection,
    runtime_probe: dict[str, object] | None,
) -> list[str]:
    """The doctor warnings a harness's own ``diagnostic_warnings`` op words."""
    from .base import HarnessContext

    answer = adapter._ask(
        "diagnostic_warnings",
        HarnessContext(home_dir=Path.home(), workspace_dir=None, guard_home=Path.home()),
        warnings=list(detection.warnings),
        probe=None if runtime_probe is None else json.loads(json.dumps(runtime_probe, default=str)),
    )
    return [str(warning) for warning in answer["warnings"]]


def runner_launch_environment(runner: str, context: HarnessContext) -> dict[str, str]:
    """The launch environment a harness's own runner kind renders (OpenCode's inline config)."""
    import os

    from ..native_runner_authority import native_runner_authority

    request = {"op": "environment", "inline": os.getenv("OPENCODE_CONFIG_CONTENT")}
    content = native_runner_authority(runner, request, guard_home=context.guard_home).get("content")
    return {"OPENCODE_CONFIG_CONTENT": content} if isinstance(content, str) else {}


def runner_launch_argv(runner: str, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
    """The launch argv a harness's own runner kind builds around the caller's arguments."""
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    workspace = str(context.workspace_dir) if context.workspace_dir is not None else None
    request = {"op": "argv", "args": "\0".join(passthrough_args), "count": len(passthrough_args)}
    answer = native_runner_authority(runner, request | {"workspace": workspace}, context.guard_home)
    argv, count = answer.get("argv"), answer.get("count")
    if not isinstance(argv, str) or not isinstance(count, int) or len(command := argv.split("\0")) != count:
        raise NativeRunnerAuthorityError("native_opencode_launch_invalid")
    return command


def _decoded(value: object) -> bytes | None:
    return None if value is None else base64.b64decode(str(value))


def planned_files(answer: dict[str, Any]) -> list[Any]:
    """The transition files a ``prepare_install`` answer plans."""
    from ..runtime_transition import TransitionFile

    files = [
        TransitionFile(
            Path(change["path"]),
            _decoded(change["before"]),
            _decoded(change["after"]),
            before_mode=change["before_mode"],
            after_mode=change["after_mode"],
            no_follow=change["no_follow"],
        )
        for change in answer["files"]
    ]
    for planned in files:
        planned.payload()
    return files
