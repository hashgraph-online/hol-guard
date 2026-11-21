"""Typed executors for Guard Cloud command queue jobs."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from ..cli.install_commands import (
    apply_managed_install,
    build_harness_verification,
    list_harness_setup_items,
)
from ..cli.update_commands import (
    build_guard_update_status_payload,
    run_guard_update,
)
from ..config import load_guard_config
from ..continuation_runtime import continue_request_after_application
from ..harness_context import HarnessContext
from ..harness_resume import resume_harness_operation, safe_resume_metadata
from ..local_supply_chain import (
    managed_install_audit_workspace_dirs,
    sync_supply_chain_cloud_state,
)
from ..native_command_job_plan import CommandJobPlanError, plan_command_job
from ..package_shim_status import record_package_shim_audit_result
from ..shims import (
    activate_package_shims,
    package_shim_status,
    probe_package_shim_intercepts,
)
from ..store import GuardStore
from ..supply_chain_workspace_audit import build_workspace_audit_payload, resolve_supply_chain_audit_workspace_dir
from .audit_workspace import audit_workspace_is_bound_to_context, bind_relative_audit_workspace
from .command_payload import mapping as _mapping
from .command_payload import optional_text as _text
from .command_payload import result as _command_result
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from .exact_cloud_review_executor import execute_exact_cloud_review_operation
from .review_policy_memory_executor import (
    REVIEW_POLICY_MEMORY_OPERATION,
    execute_review_policy_memory,
)

PACKAGE_SHIM_OPERATIONS: tuple[str, ...] = (
    "guard.packageShims.status",
    "guard.packageShims.repair",
    "guard.packageShims.test",
    "guard.packageShims.sync",
    "guard.packageShims.install",
    "guard.packageShims.remove",
    "guard.packageShims.audit",
)
APP_OPERATIONS: tuple[str, ...] = (
    "guard.app.status",
    "guard.app.repair",
    "guard.app.connect",
    "guard.app.remove",
    "guard.app.update",
    "guard.app.updateCheck",
)
EXACT_CLOUD_REVIEW_OPERATIONS: tuple[str, ...] = (EXACT_CLOUD_REVIEW_OPERATION,)
POLICY_MEMORY_OPERATIONS: tuple[str, ...] = (REVIEW_POLICY_MEMORY_OPERATION,)
SUPPORTED_COMMAND_OPERATIONS: tuple[str, ...] = (
    *PACKAGE_SHIM_OPERATIONS,
    *APP_OPERATIONS,
    *EXACT_CLOUD_REVIEW_OPERATIONS,
    *POLICY_MEMORY_OPERATIONS,
)
COMMAND_OPERATION_SCHEMA_VERSIONS: dict[str, int] = {operation: 1 for operation in SUPPORTED_COMMAND_OPERATIONS}


def execute_guard_command_job(
    job: dict[str, object],
    *,
    context: HarnessContext,
    store: GuardStore,
    now: Callable[[], str] | None = None,
) -> dict[str, object]:
    """Run one leased job as the native runtime plans it.

    The runtime decides the job's family, checks its manager, harness and
    surface arguments, and builds the local confirmation for removals. This
    function only runs the planned operation's local side effects.
    """

    operation = command_job_operation(job)
    generated_at = now() if now is not None else _now()
    payload = _job_payload(job)
    try:
        plan = plan_command_job(job.get("operation"), payload, guard_home=store.guard_home)
    except CommandJobPlanError as error:
        return _failure(error.code, "HOL Guard could not plan this command on this machine.")
    try:
        if operation in PACKAGE_SHIM_OPERATIONS:
            return _execute_package_shim_operation(
                operation,
                plan=plan,
                payload=payload,
                context=context,
                store=store,
                generated_at=generated_at,
            )
        if plan["action"] != "run":
            return _apply_non_run_plan(plan, generated_at=generated_at)
        family = plan["family"]
        if family == "app":
            return _execute_app_operation(
                operation,
                plan=plan,
                context=context,
                store=store,
                generated_at=generated_at,
            )
        if family == "exact_cloud_review":
            return execute_exact_cloud_review_operation(
                payload=payload,
                store=store,
                generated_at=generated_at,
                resume_after_approval=_resume_after_remote_approval,
            )
        if family == "policy_memory":
            return _result(
                execute_review_policy_memory(payload, store=store, generated_at=generated_at),
                generated_at=generated_at,
            )
    except ValueError as error:
        failure_code = str(error) or "invalid_payload"
        return _failure(failure_code, failure_code.replace("_", " "))
    return _failure("unsupported_operation", f"Unsupported Guard command operation: {operation or 'unknown'}")


def _apply_non_run_plan(plan: dict[str, object], *, generated_at: str) -> dict[str, object]:
    if plan["action"] == "confirm":
        data = plan["data"]
        return _waiting_local_confirm(dict(data) if isinstance(data, dict) else {}, generated_at=generated_at)
    return _failure(str(plan["failure_code"]), str(plan["failure_message"]))


def _failure(code: str, message: str) -> dict[str, object]:
    return {"failureCode": code, "failureMessage": message}


def _planned_managers(plan: dict[str, object]) -> tuple[str, ...] | None:
    managers = plan.get("managers")
    return tuple(str(manager) for manager in managers) if isinstance(managers, list) else None


def _execute_package_shim_operation(
    operation: str,
    *,
    plan: dict[str, object],
    payload: dict[str, object],
    context: HarnessContext,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    if operation == "guard.packageShims.audit" and not audit_workspace_is_bound_to_context(payload, context):
        return _failure("workspace_scope_mismatch", "Cloud audit requests must target the active local workspace.")
    if operation == "guard.packageShims.audit":
        payload = bind_relative_audit_workspace(payload, context)
    # The workspace is resolved before the plan's own failure applies, so a
    # job with a bad workspace and bad managers reports the workspace.
    command_context = _package_shim_context(payload, base_context=context, store=store)
    if plan["action"] != "run":
        return _apply_non_run_plan(plan, generated_at=generated_at)
    managers = _planned_managers(plan)
    if operation == "guard.packageShims.status":
        return _result(package_shim_status(command_context), generated_at=generated_at)
    if operation == "guard.packageShims.install":
        return _result(activate_package_shims(command_context, managers=managers), generated_at=generated_at)
    if operation == "guard.packageShims.repair":
        return _result(
            activate_package_shims(command_context, managers=managers, repair=True),
            generated_at=generated_at,
        )
    if operation == "guard.packageShims.test":
        return _result(
            probe_package_shim_intercepts(
                command_context,
                managers=managers,
                workspace_dir=command_context.workspace_dir,
            ),
            generated_at=generated_at,
        )
    if operation == "guard.packageShims.sync":
        return _result(
            sync_supply_chain_cloud_state(
                store,
                workspace_dir=command_context.workspace_dir,
            ),
            generated_at=generated_at,
        )
    if operation == "guard.packageShims.audit":
        if command_context.workspace_dir is None:
            return _failure("workspace_required", "Package shim audit requires a workspace path.")
        audit_payload, exit_code = build_workspace_audit_payload(
            command_name="audit",
            config=load_guard_config(store.guard_home),
            now=generated_at,
            sbom_paths=(),
            store=store,
            workspace_dir=command_context.workspace_dir,
        )
        audit_payload["exit_code"] = exit_code
        if exit_code == 0:
            proof = record_package_shim_audit_result(command_context, audited_at=generated_at)
            if isinstance(proof, dict):
                audit_payload.update(proof)
        return _result(audit_payload, generated_at=generated_at)
    return _failure("unsupported_operation", f"Unsupported package shim operation: {operation}")


def _execute_app_operation(
    operation: str,
    *,
    plan: dict[str, object],
    context: HarnessContext,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    harness = plan.get("harness")
    surface = plan.get("surface")
    harness = harness if isinstance(harness, str) else None
    surface = surface if isinstance(surface, str) else None
    workspace = str(context.workspace_dir) if context.workspace_dir is not None else None
    if operation == "guard.app.status":
        if harness is None:
            return _result({"items": list_harness_setup_items(context, store)}, generated_at=generated_at)
        return _result(build_harness_verification(harness, context, store, surface=surface), generated_at=generated_at)
    if operation == "guard.app.update":
        return _result(
            _execute_app_update(context=context, store=store, generated_at=generated_at),
            generated_at=generated_at,
        )
    if operation == "guard.app.updateCheck":
        return _result(
            _execute_app_update_check(context=context, generated_at=generated_at),
            generated_at=generated_at,
        )
    if harness is None or operation not in {"guard.app.connect", "guard.app.repair"}:
        return _failure("unsupported_operation", f"Unsupported app operation: {operation}")
    result = apply_managed_install("install", harness, False, context, store, workspace, generated_at, surface=surface)
    if operation == "guard.app.repair":
        result["action"] = "repair"
    return _result(result, generated_at=generated_at)


def _execute_app_update(
    *,
    context: HarnessContext,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    status = build_guard_update_status_payload(guard_home=context.guard_home)
    update_payload, exit_code = run_guard_update(
        dry_run=False,
        context=context,
        store=store,
        workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
        now=generated_at,
        include_alpha=status.get("release_channel") == "alpha",
    )
    return {
        "update": update_payload,
        "exitCode": exit_code,
        "succeeded": exit_code == 0,
    }


def _execute_app_update_check(*, context: HarnessContext, generated_at: str) -> dict[str, object]:
    del generated_at
    return build_guard_update_status_payload(guard_home=context.guard_home)


def _resume_after_remote_approval(
    *,
    store: GuardStore,
    request_row: dict[str, object],
    request_id: str,
    action: str,
    now: str,
) -> dict[str, object]:
    harness = _optional_string(request_row.get("harness"))
    if harness == "codex" and action in {"allow", "block"}:
        continuation = _resume_codex_request(store=store, request_id=request_id, action=action, now=now)
        if continuation is None:
            return {}
        return _continuation_resume_metadata(continuation, detail_key="codexResume")
    harness_resume = resume_harness_operation(store, request_id=request_id, action=action, now=now)
    if harness_resume is None:
        return {}
    return _continuation_resume_metadata(harness_resume, detail_key="harnessResume")


def _resume_codex_request(
    *,
    store: GuardStore,
    request_id: str,
    action: str,
    now: str,
) -> dict[str, object] | None:
    request = store.get_approval_request(request_id)
    if not isinstance(request, dict):
        return None
    try:
        continuation = continue_request_after_application(
            store,
            request_row=request,
            action=action,
            now=now,
        )
        return continuation
    except ValueError as error:
        return {
            "codexResume": {
                "reason": str(error) or "resume_failed",
                "status": "failed",
                "message": "HOL Guard could not resume the Codex request after applying the remote decision.",
            },
            "continuationReason": str(error) or "resume_failed",
            "continuationStatus": "failed",
        }


def _continuation_resume_metadata(continuation: dict[str, object], *, detail_key: str) -> dict[str, object]:
    detail = continuation.get(detail_key)
    safe = safe_resume_metadata(detail) if isinstance(detail, dict) else {}
    status = _optional_string(continuation.get("continuationStatus"))
    if status is None:
        raise ValueError("continuation_status_missing")
    payload: dict[str, object] = {
        "continuationReason": _optional_string(continuation.get("continuationReason")),
        "continuationStatus": status,
    }
    if safe:
        payload[detail_key] = safe
    completed_at = _optional_string(continuation.get("continuationCompletedAt"))
    if completed_at is not None:
        payload["continuationCompletedAt"] = completed_at
    return payload


def _package_shim_context(
    payload: dict[str, object],
    *,
    base_context: HarnessContext,
    store: GuardStore,
) -> HarnessContext:
    if payload.get("workspace_dir") is None and payload.get("workspace") is None:
        return base_context
    allowed_roots = (
        base_context.home_dir.resolve(),
        Path.cwd().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    )
    workspace_dir = resolve_supply_chain_audit_workspace_dir(
        workspace_dir_value=payload.get("workspace_dir"),
        workspace_value=payload.get("workspace"),
        allowed_roots=allowed_roots,
        managed_workspace_dirs=managed_install_audit_workspace_dirs(store),
        guard_home=store.guard_home,
    )
    return HarnessContext(
        home_dir=base_context.home_dir,
        workspace_dir=workspace_dir or base_context.workspace_dir,
        guard_home=base_context.guard_home,
    )


def command_job_operation(job: dict[str, object]) -> str:
    operation = job.get("operation")
    return operation if isinstance(operation, str) else ""


def _job_payload(job: dict[str, object]) -> dict[str, object]:
    return _mapping(job.get("payload"))


def _optional_string(value: object) -> str | None:
    return _text(value)


def _result(data: dict[str, object], *, generated_at: str) -> dict[str, object]:
    return _command_result(data, generated_at=generated_at)


def _waiting_local_confirm(
    data: dict[str, object],
    *,
    generated_at: str,
) -> dict[str, object]:
    payload = _result(data, generated_at=generated_at)
    payload["waitingLocalConfirm"] = True
    return payload


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
