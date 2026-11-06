"""Exact-authorized activation and private-journal Desktop crash recovery."""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO, cast

from ... import __version__
from ..adapters.base import HarnessContext
from ..approval_gate import ApprovalGateError, public_config, require_high_risk
from ..codex_hook_file_integrity import CodexHookIntegrityError
from ..codex_install_transaction import codex_install_transaction
from ..daemon.start_lock import guard_daemon_start_lock
from ..native_runtime import NativeRuntimeIdentity
from ..runtime_transition import (
    RuntimeTransition,
    TransitionError,
    TransitionPlan,
    TransitionStatus,
    inverse_recovery_budget,
)
from ..runtime_transition_admission import NativeProtectionAdmission
from ..runtime_transition_codex_observer import observe_configured_codex_hook
from ..runtime_transition_coordinator import RuntimeTransitionCoordinator
from ..runtime_transition_daemon import TransitionDaemonDriver, TransitionHookObserver
from ..runtime_transition_prepare import prepare_runtime_transition
from ..stable_guard_cli import exact_process_guard_cli_binding
from ..store import GuardStore
from .approval_gate_prompt import consume_desktop_lifecycle_env
from .commands_lifecycle_gate import LifecycleGateRequirement, lifecycle_authority_home
from .desktop_transition_request import load_desktop_transition_request
from .runtime_stage_timings import RuntimeStageTimings as _TransitionStageTimings


def _codex_observer(plan: TransitionPlan, context: HarnessContext, store: GuardStore) -> TransitionHookObserver:
    """Derive the observable binding from signed snapshots, never CLI proof input."""
    changes = {change.harness: change for change in plan.managed_installs}
    if set(changes) != {"codex"}:
        raise TransitionError("installed_hook_observer_unavailable")
    configurations: dict[str, tuple[Path, Path]] = {}
    for side, snapshot in (("predecessor", changes["codex"].before), ("candidate", changes["codex"].after)):
        if snapshot is None or snapshot.get("active") is not True:
            raise TransitionError("installed_hook_observer_unavailable")
        manifest = snapshot.get("manifest")
        if not isinstance(manifest, dict):
            raise TransitionError("managed_install_snapshot_invalid")
        config = manifest.get("managed_hook_config_path")
        if not isinstance(config, str) or not Path(config).is_absolute():
            raise TransitionError("installed_hook_binding_missing")
        config_path = Path(config)
        generation = "before" if side == "predecessor" else "after"
        if not any(change.path == config_path and getattr(change, generation) is not None for change in plan.files):
            raise TransitionError("installed_hook_binding_missing")
        workspace = snapshot.get("workspace")
        if workspace is not None and (not isinstance(workspace, str) or not Path(workspace).is_absolute()):
            raise TransitionError("managed_install_snapshot_invalid")
        configurations[side] = (config_path, Path(workspace) if isinstance(workspace, str) else context.home_dir)

    def observe(
        artifact: Mapping[str, object],
        daemon_identity: Mapping[str, object],
        operation_id: str,
        *,
        deadline_monotonic: float,
    ) -> NativeProtectionAdmission:
        del daemon_identity  # The lifecycle driver checks it before and after observation.
        if operation_id != plan.operation_id:
            raise TransitionError("plan_context_mismatch")
        sides = [
            side
            for side, expected in (("candidate", plan.candidate), ("predecessor", plan.predecessor))
            if artifact == expected
        ]
        if len(sides) != 1:
            raise TransitionError("daemon_artifact_binding_invalid")
        side = sides[0]
        from ..daemon.live_identity import DaemonArtifactBinding

        artifact_binding = DaemonArtifactBinding.from_transition_plan(plan, side)
        native = cast(Mapping[str, object], (plan.native_runtimes or {})[side])
        config_path, workspace = configurations[side]
        return observe_configured_codex_hook(
            operation_id=operation_id,
            artifact_generation=cast(str, artifact["generation"]),
            expected_runtime=NativeRuntimeIdentity(
                Path(cast(str, native["path"])),
                cast(int, native["size"]),
                cast(int, native["mtime_ns"]),
                cast(str, native["sha256"]),
            ),
            guard_home=plan.guard_home,
            config_path=config_path,
            workspace=workspace,
            deadline_monotonic=deadline_monotonic,
            artifact_binding=artifact_binding,
            receipt_store=store,
        )

    return observe


def _control_status(runtime: RuntimeTransition, operation_id: str) -> TransitionStatus:
    try:
        return runtime.status(operation_id)
    except TransitionError as error:
        if error.reason != "record_unavailable":
            raise
    try:
        return runtime.archived_status(operation_id)
    except TransitionError as error:
        if error.reason not in {"record_unavailable", "operation_superseded"}:
            raise
    return runtime.refusal_status(operation_id)


def run_desktop_runtime_transition(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    store: GuardStore,
    output_stream: TextIO,
) -> int:
    started = time.monotonic()
    timings = _TransitionStageTimings(started)
    epoch = time.time()
    operation_id = getattr(args, "operation_id", "")
    response: dict[str, object] = {"schema": "hol-guard.desktop-runtime-transition.v1", "operation_id": operation_id}
    try:
        timings.enter("authority")
        authority_home = lifecycle_authority_home(
            context.guard_home,
            requirement=LifecycleGateRequirement("runtime.transition", str(operation_id)),
        )
        gate = public_config(authority_home)
        timings.enter("factor_consumption")
        # Consume once before preparation can launch any diagnostic subprocess.
        # Status and inverse-only recovery never turn these factors into grants.
        factor = consume_desktop_lifecycle_env(
            totp_enabled=gate.totp_enabled, use_cooldown=False, cooldown_seconds=gate.cooldown_seconds
        )
        if not isinstance(operation_id, str) or str(uuid.UUID(operation_id)) != operation_id:
            raise TransitionError("operation_id_invalid")
        requested = getattr(args, "deadline_epoch", None)
        if (
            isinstance(requested, bool)
            or not isinstance(requested, (int, float))
            or not math.isfinite(requested)
            or not 0 < requested - epoch <= 60
        ):
            raise TransitionError("deadline_invalid")
        deadline = started + requested - epoch
        runtime = RuntimeTransition(context.guard_home, store, install_store=store)
        from ..sqlite_tuning import sqlite_operation_deadline

        timings.enter("owner_wait")
        with (
            sqlite_operation_deadline(deadline),
            codex_install_transaction(
                runtime.home,
                runtime.path,
                actor="desktop-transition",
                deadline=deadline,
            ),
        ):
            timings.enter("control")
            if time.monotonic() >= deadline:
                raise TransitionError("deadline_exceeded")
            if args.desktop_command == "transition-status":
                status = _control_status(runtime, operation_id)
                if time.monotonic() >= deadline:
                    raise TransitionError("deadline_exceeded")
            elif args.desktop_command == "transition-recover":
                status = _control_status(runtime, operation_id)
                if status.phase not in {"Committed", "FailedWithVerifiedRollback", "NotStarted"}:
                    plan = runtime.recovery_plan(operation_id)
                    if time.monotonic() >= deadline:
                        raise TransitionError("deadline_exceeded")
                    driver = TransitionDaemonDriver(
                        runtime, plan, home_dir=context.home_dir, observe_hook=_codex_observer(plan, context, store)
                    )
                    # Home owner precedes the start owner; inverse only.
                    with guard_daemon_start_lock(runtime.home, deadline=deadline):
                        status = RuntimeTransitionCoordinator(runtime, driver).recover(
                            operation_id,
                            deadline_monotonic=deadline,
                        )
            elif args.desktop_command == "transition-finalize":
                status = _control_status(runtime, operation_id)
                if getattr(args, "artifact_generation", None) != status.artifact_generation:
                    raise TransitionError("artifact_generation_mismatch")
                if status.phase not in {"Committed", "FailedWithVerifiedRollback"}:
                    raise TransitionError("nonterminal_transition")
                if runtime.path.exists() or runtime.path.is_symlink():
                    with inverse_recovery_budget(deadline):
                        runtime.retire(operation_id)
                status = runtime.archived_status(operation_id)
            elif args.desktop_command == "transition-activate":
                timings.enter("request_verification")
                refusal_path = runtime._refusal_path(operation_id)
                if refusal_path.exists() or refusal_path.is_symlink():
                    raise TransitionError("operation_previously_refused")
                if not bool(getattr(sys, "frozen", False)):
                    raise TransitionError("packaged_transition_runtime_required")
                request = load_desktop_transition_request(
                    Path(args.request),
                    context=context,
                    operation_id=operation_id,
                    deadline_epoch=requested,
                    deadline_monotonic=deadline,
                    request_sha256=args.request_sha256,
                )
                if Path(cast(str, request.candidate["path"])) != Path(sys.executable).resolve(strict=True):
                    raise TransitionError("candidate_process_identity_mismatch")
                if request.candidate["version"] != __version__:
                    raise TransitionError("candidate_package_version_mismatch")
                timings.enter("plan_preparation")
                with exact_process_guard_cli_binding():
                    plan = prepare_runtime_transition(
                        request,
                        context=context,
                        store=store,
                        deadline_monotonic=deadline,
                    )
                driver = TransitionDaemonDriver(
                    runtime, plan, home_dir=context.home_dir, observe_hook=_codex_observer(plan, context, store)
                )
                if time.monotonic() >= deadline:
                    raise TransitionError("deadline_exceeded")
                try:
                    timings.enter("approval")
                    grant = require_high_risk(
                        authority_home,
                        purpose="protection_lifecycle",
                        approval_gate_input=factor,
                        action="runtime.transition",
                        scope="local-protection",
                        subject=plan.subject(),
                    )
                except ApprovalGateError as error:
                    try:
                        runtime.record_approval_refusal(plan, error.code, deadline_monotonic=deadline)
                    except (OSError, ValueError, TransitionError, CodexHookIntegrityError):
                        # Keep the original approval failure. No unsigned or
                        # partial receipt can establish NotStarted later.
                        print("guard_runtime_refusal_record_unavailable", file=sys.stderr)
                    raise
                timings.enter("daemon_owner_wait")
                with guard_daemon_start_lock(runtime.home, deadline=deadline):
                    timings.enter("activation")
                    status = RuntimeTransitionCoordinator(runtime, driver).activate(
                        plan,
                        authority_home=authority_home,
                        grant=grant,
                        deadline_monotonic=deadline,
                    )
                response["artifact_generation"] = plan.candidate["generation"]
            else:
                raise TransitionError("transition_command_invalid")
            response.update(
                phase=status.phase,
                first_cause=status.first_cause,
                recovery_causes=list(status.recovery_causes),
                artifact_generation=status.artifact_generation,
            )
            if time.monotonic() >= deadline:
                raise TransitionError("deadline_exceeded")
            result = (
                1
                if (
                    status.phase == "RecoveryRequired"
                    or (args.desktop_command == "transition-activate" and status.phase != "Committed")
                )
                else 0
            )
    except ApprovalGateError as error:
        response = {
            "schema": "hol-guard.desktop-runtime-transition.v1",
            "operation_id": operation_id,
            "reason_code": error.code,
        }
        result = 1
    except (ValueError, TransitionError, CodexHookIntegrityError) as error:
        response = {
            "schema": "hol-guard.desktop-runtime-transition.v1",
            "operation_id": operation_id,
            "reason_code": (
                error.reason
                if isinstance(error, (TransitionError, CodexHookIntegrityError))
                else "operation_id_invalid"
            ),
        }
        result = 1
    except Exception as error:
        # Exception text can include paths, private bindings or process output.
        response = {
            "schema": "hol-guard.desktop-runtime-transition.v1",
            "operation_id": operation_id,
            "reason_code": type(error).__name__,
        }
        result = 1
    timings.finish()
    print(json.dumps(response, sort_keys=True), file=output_stream)
    return result
