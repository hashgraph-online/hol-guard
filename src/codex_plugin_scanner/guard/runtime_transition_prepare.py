"""Assemble all enrolled bindings before authorizing one exact transition.

The caller supplies reviewed artifact identities and prepared selection
files. This module does not accept arbitrary serialized file plans from a
CLI, verify release signatures, publish files, or obtain approval.
"""

from __future__ import annotations

import hashlib
import math
import os
import time
import uuid
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, cast

from .adapters import get_adapter
from .adapters.base import HarnessContext
from .codex_hook_file_integrity import CodexHookIntegrityError, hook_validation_deadline, validate_regular_file
from .codex_install_transaction import require_codex_install_owner
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


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TransitionError("deadline_exceeded")


def _pin_executable(
    path: Path,
    *,
    deadline: float,
    expected: Mapping[str, object] | None = None,
    expected_sha256: str | None = None,
) -> TransitionFile:
    _check_deadline(deadline)
    before = validate_regular_file(path, role="artifact", executable_required=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)

        def fingerprint(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_uid,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if fingerprint(before) != fingerprint(opened):
            raise TransitionError("generation_changed")
        digest = hashlib.sha256()
        count = 0
        while True:
            _check_deadline(deadline)
            chunk = os.read(descriptor, 64 * 1024)
            _check_deadline(deadline)
            if not chunk:
                break
            count += len(chunk)
            if count > opened.st_size:
                raise TransitionError("generation_changed")
            digest.update(chunk)
        if (
            count != opened.st_size
            or fingerprint(opened) != fingerprint(os.fstat(descriptor))
            or fingerprint(opened) != fingerprint(path.lstat())
        ):
            raise TransitionError("generation_changed")
        sha256 = digest.hexdigest()
        if expected_sha256 is not None and sha256 != expected_sha256:
            raise TransitionError("artifact_generation_changed")
        if expected is not None and (
            expected.get("sha256") != sha256
            or expected.get("size") != count
            or expected.get("mtime_ns") != opened.st_mtime_ns
        ):
            raise TransitionError("native_runtime_generation_changed")
        result = TransitionFile.artifact_dependency(
            {
                "path": str(path),
                "mode": opened.st_mode & 0o777,
                "owner_uid": opened.st_uid,
                "size": count,
                "sha256": sha256,
                "role": "artifact",
            }
        )
        _check_deadline(deadline)
        return result
    finally:
        os.close(descriptor)


def prepare_runtime_transition(
    request: RuntimeTransitionPreparation,
    *,
    context: HarnessContext,
    store: PreparationStore,
    deadline_monotonic: float,
) -> TransitionPlan:
    """Capture exact inverses under the permanent home owner; perform no writes."""
    deadline = deadline_monotonic
    if (
        isinstance(deadline, bool)
        or not math.isfinite(deadline)
        or not 0 < deadline - time.monotonic() <= 60
        or isinstance(request.deadline_epoch, bool)
        or not math.isfinite(request.deadline_epoch)
        or not 0 < request.deadline_epoch - time.time() <= 60
    ):
        raise TransitionError("deadline_invalid")
    deadline = min(deadline, time.monotonic() + request.deadline_epoch - time.time())
    try:
        if str(uuid.UUID(request.operation_id)) != request.operation_id:
            raise ValueError
    except (ValueError, AttributeError) as error:
        raise TransitionError("operation_id_invalid") from error
    require_codex_install_owner(context.guard_home)
    assert_transition_mutation_allowed(context.guard_home)
    selection = deepcopy(request.selection_files)
    if not selection or any(change.kind != "selection" for change in selection):
        raise TransitionError("selection_plan_invalid")
    artifacts = {"predecessor": deepcopy(dict(request.predecessor)), "candidate": deepcopy(dict(request.candidate))}
    native = deepcopy(dict(request.native_runtimes))
    executable_digests = deepcopy(dict(request.executable_digests or {}))
    if request.executable_digests is not None and (
        set(executable_digests) != {"candidate", "predecessor"}
        or any(
            not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
            for value in executable_digests.values()
        )
    ):
        raise TransitionError("artifact_digest_invalid")
    if set(native) != {"candidate", "predecessor"}:
        raise TransitionError("native_runtime_bindings_missing")
    rows = deepcopy(store.list_managed_installs())
    _check_deadline(deadline)
    files: dict[Path, TransitionFile] = {}

    def add(change: TransitionFile) -> None:
        _check_deadline(deadline)
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
                _check_deadline(deadline)
                adapter = get_adapter(harness)
                prepared = adapter.prepare_install(adapter_context)
                _check_deadline(deadline)
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
            for side in ("predecessor", "candidate"):
                path = artifacts[side].get("path")
                identity = native[side]
                if (
                    not isinstance(path, str)
                    or not Path(path).is_absolute()
                    or not isinstance(identity, dict)
                    or not isinstance(identity.get("path"), str)
                    or not Path(identity["path"]).is_absolute()
                ):
                    raise TransitionError("artifact_identity_invalid")
                add(_pin_executable(Path(path), deadline=deadline, expected_sha256=executable_digests.get(side)))
                add(_pin_executable(Path(identity["path"]), deadline=deadline, expected=identity))
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
            _check_deadline(deadline)
            return plan
    except CodexHookIntegrityError as error:
        if error.reason == "codex_hook_validation_deadline_expired":
            raise TransitionError("deadline_exceeded") from error
        raise
