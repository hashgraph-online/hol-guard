"""Spec-driven steps of the generic native harness client.

``describe`` names which of these a harness takes: a hook-ownership failure
worded by the runtime, and a rebind planned from what the runtime detected.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import HarnessDetection
from .native_harness_client import HookOwnershipError, owned_ask, run_op

if TYPE_CHECKING:
    from .harness_context import HarnessContext, PreparedHarnessInstall


def prepared_from_detection(harness: str, context: HarnessContext, *, create_key: bool) -> PreparedHarnessInstall:
    """A rebind planned from what the runtime detected, using existing enrolled authority."""
    from .harness_context import PreparedHarnessInstall
    from .runtime_transition import RuntimeTransition, TransitionError, TransitionFile
    from .shims import prepare_guard_shim

    found = run_op(harness, "install_detection", context, create_key=create_key)
    if set(found) == {"transition_error"}:
        raise TransitionError(str(found["transition_error"]))
    shim = prepare_guard_shim(harness, context)
    answer = run_op(
        harness,
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


def prepared_surfaces(harness: str, context: HarnessContext, **surface: object) -> PreparedHarnessInstall:
    """Every surface the runtime selects, planned in one op before any publication."""
    from .harness_context import PreparedHarnessInstall
    from .runtime_transition import RuntimeTransition, TransitionError, TransitionFile
    from .shims import shell_profile_facts, shim_interpreter

    answer = run_op(
        harness,
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


def detection_from(harness: str, answer: dict[str, Any]) -> HarnessDetection:
    """The detection a ``detect``-shaped answer describes; the runtime has already merged the workspace AIBOM."""
    from .aibom_detection import _artifacts_from_payload

    return HarnessDetection(
        harness=harness,
        installed=answer.get("installed") is True,
        command_available=answer.get("command_available") is True,
        config_paths=tuple(str(path) for path in answer.get("config_paths", ())),
        artifacts=_artifacts_from_payload(answer),
        warnings=tuple(str(warning) for warning in answer.get("warnings", ())),
    )


__all__ = ["HookOwnershipError", "detection_from", "owned_ask", "planned_files", "prepared_from_detection"]


def native_warnings(
    harness: str,
    detection: HarnessDetection,
    runtime_probe: dict[str, object] | None,
) -> list[str]:
    """The doctor warnings a harness's own ``diagnostic_warnings`` op words."""
    from .harness_context import HarnessContext

    answer = run_op(
        harness,
        "diagnostic_warnings",
        HarnessContext(home_dir=Path.home(), workspace_dir=None, guard_home=Path.home()),
        warnings=list(detection.warnings),
        probe=None if runtime_probe is None else json.loads(json.dumps(runtime_probe, default=str)),
    )
    return [str(warning) for warning in answer["warnings"]]


def runner_launch_environment(runner: str, context: HarnessContext) -> dict[str, str]:
    """The launch environment a harness's own runner kind renders (OpenCode's inline config)."""
    import os

    from .native_runner_authority import native_runner_authority

    request = {"op": "environment", "inline": os.getenv("OPENCODE_CONFIG_CONTENT")}
    content = native_runner_authority(runner, request, guard_home=context.guard_home).get("content")
    return {"OPENCODE_CONFIG_CONTENT": content} if isinstance(content, str) else {}


def runner_launch_argv(runner: str, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
    """The launch argv a harness's own runner kind builds around the caller's arguments."""
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

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
    from .runtime_transition import TransitionFile

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
