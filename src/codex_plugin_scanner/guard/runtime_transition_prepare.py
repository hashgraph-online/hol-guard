"""Assemble all enrolled bindings before authorizing one exact transition.

The caller supplies reviewed artifact identities and prepared selection
files. This module does not accept arbitrary serialized file plans from a
CLI, verify release signatures, publish files, or obtain approval.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, cast

from .codex_hook_file_integrity import CodexHookIntegrityError, hook_validation_deadline
from .harness_context import HarnessContext
from .native_harness_install_ops import prepare_install
from .native_owned import require_codex_install_owner
from .native_transition_files import pin_executable, prepare_request, require_deadline
from .runtime_transition import (
    RuntimeTransition,
    TransitionError,
    TransitionFile,
    TransitionInstall,
    TransitionPlan,
    assert_transition_mutation_allowed,
    inverse_recovery_budget,
    merge_transition_dependency,
)


class PreparationStore(Protocol):
    def list_managed_installs(self) -> list[dict[str, object]]: ...


@dataclass(frozen=True)
class RuntimeTransitionPreparation:
    operation_id: str
    predecessor: Mapping[str, object]
    candidate: Mapping[str, object]
    selection_files: tuple[TransitionFile, ...]
    native_runtimes: Mapping[str, object]
    deadline_epoch: float
    executable_digests: Mapping[str, str] | None = None
    selection_dependencies: tuple[TransitionFile, ...] = ()


def _pin_executable(
    path: Path,
    *,
    deadline: float,
    expected: Mapping[str, object] | None = None,
    expected_sha256: str | None = None,
) -> TransitionFile:
    """Pin the executable through the native runtime, which hashes and admits it."""

    return TransitionFile.artifact_dependency(
        pin_executable(path, deadline=deadline, expected=expected, expected_sha256=expected_sha256)
    )


def prepare_runtime_transition(
    request: RuntimeTransitionPreparation,
    *,
    context: HarnessContext,
    store: PreparationStore,
    deadline_monotonic: float,
) -> TransitionPlan:
    """Capture exact inverses under the permanent home owner; perform no writes."""
    deadline = cast(
        float,
        prepare_request(
            "deadline",
            deadline=deadline_monotonic,
            now=time.monotonic(),
            deadline_epoch=request.deadline_epoch,
            wall=time.time(),
        ).get("deadline"),
    )
    prepare_request("operation", operation_id=request.operation_id)
    require_codex_install_owner(context.guard_home)
    assert_transition_mutation_allowed(context.guard_home)
    selection = deepcopy(request.selection_files)
    if not selection or any(change.kind != "selection" for change in selection):
        raise TransitionError("selection_plan_invalid")
    artifacts = {"predecessor": deepcopy(dict(request.predecessor)), "candidate": deepcopy(dict(request.candidate))}
    native = deepcopy(dict(request.native_runtimes))
    executable_digests = deepcopy(dict(request.executable_digests or {}))
    prepare_request(
        "bindings",
        executable_digests=None if request.executable_digests is None else executable_digests,
        native=native,
    )
    rows = deepcopy(store.list_managed_installs())
    require_deadline(deadline)
    files: dict[Path, TransitionFile] = {}

    def add(change: TransitionFile) -> None:
        require_deadline(deadline)
        captured = deepcopy(change)
        payload = captured.payload()
        path = Path(cast(str, payload["path"]))
        previous = files.get(path)
        files[path] = captured if previous is None else merge_transition_dependency(previous, captured)

    installs = []
    updated_at = datetime.now(timezone.utc).isoformat()
    try:
        # These scopes carry timing only, never approval or publication rights.
        with hook_validation_deadline(deadline), inverse_recovery_budget(deadline):
            for change in selection:
                add(change)
            for change in request.selection_dependencies:
                if change.expected_digest is None:
                    raise TransitionError("selection_plan_invalid")
                add(change)
            for row in rows:
                harness = row.get("harness")
                if not isinstance(harness, str):
                    raise TransitionError("managed_install_snapshot_invalid")
                TransitionInstall(harness, row, None).payload()
                if row["active"] is not True:
                    continue
                workspace = row["workspace"]
                if workspace is not None and (not isinstance(workspace, str) or not Path(workspace).is_absolute()):
                    raise TransitionError("managed_install_snapshot_invalid")
                manifest = cast(dict[str, object], row["manifest"])
                adapter_context = replace(
                    context,
                    workspace_dir=Path(workspace) if isinstance(workspace, str) else None,
                    workspace_override_explicit=manifest.get("hook_workspace_explicit") is True,
                )
                require_deadline(deadline)
                prepared = prepare_install(harness, adapter_context)
                require_deadline(deadline)
                for change in prepared.files:
                    if change.kind != "binding":
                        raise TransitionError("adapter_preparation_generation_conflict")
                    add(change)
                after: dict[str, object] = {
                    "harness": harness,
                    "active": True,
                    "workspace": workspace,
                    "manifest": deepcopy(prepared.manifest),
                    "updated_at": updated_at,
                }
                installs.append(TransitionInstall(harness, row, after))
            if not installs:
                raise TransitionError("managed_install_bindings_missing")
            prepare_request("identity", artifacts=artifacts, native=native)
            for side in ("predecessor", "candidate"):
                path = cast(str, artifacts[side]["path"])
                identity = cast(dict[str, object], native[side])
                add(_pin_executable(Path(path), deadline=deadline, expected_sha256=executable_digests.get(side)))
                add(_pin_executable(Path(cast(str, identity["path"])), deadline=deadline, expected=identity))
            plan = TransitionPlan(
                request.operation_id,
                context.guard_home,
                artifacts["predecessor"],
                artifacts["candidate"],
                tuple(files.values()),
                request.deadline_epoch,
                managed_installs=tuple(installs),
                native_runtimes=native,
            )
            payload = plan.payload()
            RuntimeTransition._compare(payload, "before")
            if store.list_managed_installs() != rows:
                raise TransitionError("managed_install_generation_changed")
            require_deadline(deadline)
            return plan
    except CodexHookIntegrityError as error:
        if error.reason == "codex_hook_validation_deadline_expired":
            raise TransitionError("deadline_exceeded") from error
        raise
