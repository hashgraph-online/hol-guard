"""Explicit app repair with exact local authorization and native completion."""

from __future__ import annotations

import argparse
import math
import time
from pathlib import Path

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..adapters.codex import _hook_manifest_spec
from ..approval_gate import ApprovalGateError, public_config, require_high_risk
from ..codex_hook_file_integrity import CodexHookIntegrityError, hook_validation_deadline
from ..codex_hook_manifest import (
    CODEX_AUTHORITY_REPAIR_ACTION,
    PreparedCodexHookRepair,
    prepare_authenticated_hook_manifest_repair,
)
from ..codex_hook_recovery import hook_publication_pending
from ..codex_hook_repair import (
    CodexHookRepairError,
    authorize_codex_hook_repair,
    prepare_codex_hook_repair_verification,
    publish_codex_hook_repair,
    verify_and_commit_codex_hook_repair,
)
from ..codex_hook_repair_native import inspect_codex_repair_native_runtime
from ..codex_hook_repair_request import load_codex_hook_repair_request, write_codex_hook_repair_request
from ..codex_install_transaction import codex_install_transaction
from ..codex_publication_inverse import publish_codex_publication_inverse, verify_and_retire_codex_publication_inverse
from ..codex_publication_inverse_authorization import authorize_codex_publication_inverse
from ..codex_publication_inverse_plan import (
    PUBLICATION_INVERSE_ACTION,
    PreparedCodexPublicationInverse,
    bind_codex_publication_inverse_verification,
    prepare_authenticated_hook_publication_inverse,
)
from ..runtime_transition import TransitionError, assert_transition_mutation_allowed, inverse_recovery_budget
from ..sqlite_tuning import sqlite_operation_deadline
from ..store import GuardStore
from .approval_gate_prompt import consume_desktop_lifecycle_env, prompt_for_approval_gate
from .commands_lifecycle_gate import LifecycleGateRequirement, lifecycle_authority_home
from .runtime_stage_timings import RuntimeStageTimings


def _reason(error: Exception) -> str:
    if isinstance(error, ApprovalGateError):
        return error.code
    if isinstance(error, (CodexHookIntegrityError, TransitionError)):
        return error.reason
    return type(error).__name__


def run_codex_authority_repair(
    args: argparse.Namespace,
    context: HarnessContext,
    store: GuardStore,
    workspace: Path | None,
) -> tuple[int, dict[str, object]]:
    payload: dict[str, object] = {"action": "repair", "repair": "codex-authority", "harness": "codex"}
    started = time.monotonic()
    timings = RuntimeStageTimings(started)
    timings.enter("control")
    epoch = time.time()
    deadline = started + 60.0
    request_arg = getattr(args, "authority_request", None)
    request_digest = getattr(args, "authority_request_sha256", None)
    request_path = Path(str(request_arg)).expanduser() if request_arg else None
    dry_run = bool(getattr(args, "dry_run", False))
    inverse_requested = False

    def requested_workspace() -> Path | None:
        explicit = getattr(args, "authority_verification_workspace", None)
        if explicit is None:
            return workspace or context.workspace_dir
        try:
            selected = Path(str(explicit)).expanduser().resolve(strict=True)
            if not selected.is_dir():
                raise ValueError("Verification workspace is not a directory")
            return selected
        except (OSError, ValueError) as error:
            raise TransitionError("authority_repair_verification_workspace_invalid") from error

    def prepare() -> PreparedCodexHookRepair | PreparedCodexPublicationInverse:
        with sqlite_operation_deadline(deadline), inverse_recovery_budget(deadline), hook_validation_deadline(deadline):
            assert_transition_mutation_allowed(context.guard_home)
            if hook_publication_pending(context.guard_home) != inverse_requested:
                raise TransitionError("authority_repair_publication_pending")
            if request_path is not None and not dry_run:
                timings.enter("request_verification")
                loaded = load_codex_hook_repair_request(
                    request_path,
                    guard_home=context.guard_home,
                    config_path=_hook_manifest_spec(context).config_path,
                    expected_sha256=str(request_digest),
                    deadline_monotonic=deadline,
                    inverse_spec=_hook_manifest_spec(context) if inverse_requested else None,
                )
                selected_workspace = requested_workspace()
                if selected_workspace is not None and loaded.verification_workspace != selected_workspace.resolve():
                    raise TransitionError("authority_repair_request_context_invalid")
                return loaded
            timings.enter("plan_preparation")
            if inverse_requested:
                inverse_plan = prepare_authenticated_hook_publication_inverse(_hook_manifest_spec(context))
                identity = inspect_codex_repair_native_runtime(deadline_monotonic=deadline)
                return bind_codex_publication_inverse_verification(
                    inverse_plan,
                    expected_runtime=identity,
                    workspace=(requested_workspace() or context.home_dir).resolve(),
                    deadline_monotonic=deadline,
                )
            plan = prepare_authenticated_hook_manifest_repair(_hook_manifest_spec(context))
            identity = inspect_codex_repair_native_runtime(deadline_monotonic=deadline)
            return prepare_codex_hook_repair_verification(
                plan,
                expected_runtime=identity,
                workspace=(requested_workspace() or context.home_dir).resolve(),
                deadline_monotonic=deadline,
            )

    try:
        requested_deadline = getattr(args, "authority_deadline_epoch", None)
        if requested_deadline is not None:
            if (
                isinstance(requested_deadline, bool)
                or not isinstance(requested_deadline, (int, float))
                or not math.isfinite(requested_deadline)
                or not 0 < requested_deadline - epoch <= 60
            ):
                raise TransitionError("authority_repair_deadline_invalid")
            deadline = started + requested_deadline - epoch
        if not bool(getattr(args, "restore_authority", False)):
            raise TransitionError("authority_repair_restore_flag_required")
        if (request_digest and request_path is None) or (dry_run and request_digest):
            raise TransitionError("authority_repair_request_arguments_invalid")
        if request_path is not None and not dry_run and not request_digest:
            raise TransitionError("authority_repair_request_digest_invalid")
        if get_adapter(str(args.harness)).harness != "codex":
            raise TransitionError("authority_repair_codex_only")
        if getattr(args, "surface", None) not in (None, "auto", "hooks"):
            raise TransitionError("authority_repair_hooks_only")
        # Restoring config as well as authority requires a captured, reviewed
        # request. The bare missing-manifest repair never silently broadens.
        inverse_requested = request_path is not None and hook_publication_pending(context.guard_home)
        action = PUBLICATION_INVERSE_ACTION if inverse_requested else CODEX_AUTHORITY_REPAIR_ACTION
        if inverse_requested:
            payload["repair"] = "codex-publication-inverse"
        if dry_run:
            if inverse_requested:
                assert request_path is not None
                with (
                    sqlite_operation_deadline(deadline),
                    codex_install_transaction(
                        context.guard_home,
                        _hook_manifest_spec(context).config_path,
                        actor=action,
                        deadline=min(deadline, time.monotonic() + 5.0),
                    ),
                ):
                    plan = prepare()
                    payload["request_sha256"] = write_codex_hook_repair_request(
                        request_path,
                        plan,
                        deadline_monotonic=deadline,
                    )
            else:
                plan = prepare()
            payload.update(
                status="prepared", verified=False, dry_run=True, operation_id=plan.operation_id, subject=plan.subject()
            )
            if request_path is not None and not inverse_requested:
                timings.enter("request_capture")
                payload["request_sha256"] = write_codex_hook_repair_request(
                    request_path,
                    plan,
                    deadline_monotonic=deadline,
                )
            return 0, payload
        config_path = _hook_manifest_spec(context).config_path
        timings.enter("owner_wait")
        with (
            sqlite_operation_deadline(deadline),
            codex_install_transaction(
                context.guard_home,
                config_path,
                actor=action,
                deadline=min(deadline, time.monotonic() + 5.0),
            ) as owner,
        ):
            plan = prepare()
            payload["operation_id"] = plan.operation_id
            subject = plan.subject()
            timings.enter("authority")
            authority = lifecycle_authority_home(
                context.guard_home,
                requirement=LifecycleGateRequirement(action, subject),
            )
            gate = public_config(authority)
            if not gate.enabled:
                raise ApprovalGateError(
                    "approval_gate_required", "Configure local approval before repairing authority."
                )
            if time.monotonic() >= deadline:
                raise TransitionError("authority_repair_deadline_exceeded")
            timings.enter("factor_consumption")
            factor = consume_desktop_lifecycle_env(
                totp_enabled=gate.totp_enabled, use_cooldown=False, cooldown_seconds=gate.cooldown_seconds
            )
            if factor is None:
                assert plan.native_runtime is not None
                restoration = (
                    "Restore the reviewed Codex config, signed manifest and retained authority receipt.\n"
                    + "\n".join(str(change.path) for change in plan.changes)
                    if isinstance(plan, PreparedCodexPublicationInverse)
                    else f"Restore signed Codex authority at {plan.manifest_change.path}."
                )
                factor = prompt_for_approval_gate(
                    authority,
                    use_cooldown=False,
                    require_fresh_totp=gate.totp_enabled,
                    summary=(
                        f"{restoration}\n"
                        f"Verify protected hooks for {plan.verification_workspace}.\n"
                        f"Native runtime SHA256: {plan.native_runtime.sha256}\nApproved plan: {subject}"
                    ),
                )
            if time.monotonic() >= deadline:
                raise TransitionError("authority_repair_deadline_exceeded")
            timings.enter("approval")
            grant = require_high_risk(
                authority,
                purpose="protection_lifecycle",
                approval_gate_input=factor,
                action=action,
                scope="local-protection",
                subject=subject,
                session_nonce=owner.operation_id,
            )
            if isinstance(plan, PreparedCodexPublicationInverse):
                inverse_authorization = authorize_codex_publication_inverse(
                    plan,
                    authority_home=authority,
                    grant=grant,
                    deadline_monotonic=deadline,
                )
                timings.enter("publication")
                inverse_pending = publish_codex_publication_inverse(inverse_authorization)
                timings.enter("native_verification")
                proof = verify_and_retire_codex_publication_inverse(inverse_pending, receipt_store=store)
            else:
                authorization = authorize_codex_hook_repair(
                    plan,
                    authority_home=authority,
                    grant=grant,
                    deadline_monotonic=deadline,
                )
                timings.enter("publication")
                pending = publish_codex_hook_repair(authorization)
                timings.enter("native_verification")
                proof = verify_and_commit_codex_hook_repair(pending, receipt_store=store)
            payload.update(
                status="verified",
                verified=True,
                recovery_required=False,
                native_runtime_sha256=proof.runtime_identity.sha256,
            )
        return 0, payload
    except (ApprovalGateError, CodexHookIntegrityError, TransitionError, OSError, ValueError) as error:
        required = hook_publication_pending(context.guard_home)
        try:
            assert_transition_mutation_allowed(context.guard_home)
        except TransitionError:
            required = True
        payload.update(
            status="recovery-required" if required else "failed",
            verified=False,
            recovery_required=required,
            error=_reason(error),
        )
        if isinstance(error, CodexHookRepairError):
            payload["first_error"] = _reason(error.first_error)
            payload["rollback_error"] = _reason(error.rollback_error)
        return 2, payload
    finally:
        timings.finish()
