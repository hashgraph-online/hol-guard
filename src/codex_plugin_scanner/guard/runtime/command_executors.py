"""Typed executors for Guard Cloud command queue jobs."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..cli.install_commands import (
    apply_managed_install,
    build_harness_verification,
    list_harness_setup_items,
    uninstall_confirmation_token,
)
from ..cli.update_commands import (
    build_guard_update_status_payload,
    run_guard_update,
)
from ..config import load_guard_config
from ..continuation_runtime import continue_request_after_application
from ..harness_resume import resume_harness_operation, safe_resume_metadata
from ..local_supply_chain import (
    build_workspace_audit_payload,
    managed_install_audit_workspace_dirs,
    resolve_supply_chain_audit_workspace_dir,
    sync_supply_chain_cloud_state,
)
from ..package_shim_status import record_package_shim_audit_result
from ..shims import (
    activate_package_shims,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
)
from ..store import GuardStore
from . import local_request_snapshots
from .cloud_review_repair import execute_cloud_review_sync_repair
from .command_payload import mapping as _mapping
from .command_payload import optional_text as _text
from .command_payload import result as _command_result
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from .exact_cloud_review_executor import execute_exact_cloud_review_operation
from .legacy_approval_command_executor import execute_legacy_approval_operation
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
APPROVAL_OPERATIONS: tuple[str, ...] = (
    "guard.approval.resolve",
    "guard.localRequests.snapshot",
)
LIVE_REQUEST_OPERATIONS: tuple[str, ...] = ("guard.liveRequests.reassignQuarantined",)
EXACT_CLOUD_REVIEW_OPERATIONS: tuple[str, ...] = (EXACT_CLOUD_REVIEW_OPERATION,)
POLICY_MEMORY_OPERATIONS: tuple[str, ...] = (REVIEW_POLICY_MEMORY_OPERATION,)
SUPPORTED_COMMAND_OPERATIONS: tuple[str, ...] = (
    *PACKAGE_SHIM_OPERATIONS,
    *APP_OPERATIONS,
    *APPROVAL_OPERATIONS,
    *LIVE_REQUEST_OPERATIONS,
    *EXACT_CLOUD_REVIEW_OPERATIONS,
    *POLICY_MEMORY_OPERATIONS,
)
COMMAND_OPERATION_SCHEMA_VERSIONS: dict[str, int] = {operation: 1 for operation in SUPPORTED_COMMAND_OPERATIONS}
LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT = local_request_snapshots.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT
LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT = local_request_snapshots.LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT
LOCAL_REQUEST_SNAPSHOT_MAX_BYTES = local_request_snapshots.LOCAL_REQUEST_SNAPSHOT_MAX_BYTES


def execute_guard_command_job(
    job: dict[str, object],
    *,
    context: HarnessContext,
    store: GuardStore,
    now: Callable[[], str] | None = None,
) -> dict[str, object]:
    operation = command_job_operation(job)
    generated_at = now() if now is not None else _now()
    payload = _job_payload(job)
    try:
        if operation in PACKAGE_SHIM_OPERATIONS:
            return _execute_package_shim_operation(
                operation,
                payload=payload,
                context=context,
                store=store,
                generated_at=generated_at,
            )
        if operation in APPROVAL_OPERATIONS:
            return execute_legacy_approval_operation(
                operation,
                job=job,
                payload=payload,
                store=store,
                generated_at=generated_at,
                resume_after_approval=_resume_after_remote_approval,
            )
        if operation in LIVE_REQUEST_OPERATIONS:
            return execute_cloud_review_sync_repair(
                payload,
                store=store,
                generated_at=generated_at,
            )
        if operation in APP_OPERATIONS:
            return _execute_app_operation(
                operation,
                payload=payload,
                context=context,
                store=store,
                generated_at=generated_at,
            )
        if operation in EXACT_CLOUD_REVIEW_OPERATIONS:
            return execute_exact_cloud_review_operation(
                payload=payload,
                store=store,
                generated_at=generated_at,
                resume_after_approval=_resume_after_remote_approval,
            )
        if operation in POLICY_MEMORY_OPERATIONS:
            return _result(
                execute_review_policy_memory(payload, store=store, generated_at=generated_at),
                generated_at=generated_at,
            )
    except ValueError as error:
        failure_code = str(error) or "invalid_payload"
        return {
            "failureCode": failure_code,
            "failureMessage": failure_code.replace("_", " "),
        }
    return {
        "failureCode": "unsupported_operation",
        "failureMessage": f"Unsupported Guard command operation: {operation or 'unknown'}",
    }


def _execute_package_shim_operation(
    operation: str,
    *,
    payload: dict[str, object],
    context: HarnessContext,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    command_context = _package_shim_context(payload, base_context=context, store=store)
    if operation == "guard.packageShims.status":
        return _result(package_shim_status(command_context), generated_at=generated_at)
    if operation == "guard.packageShims.install":
        managers = _package_shim_managers(payload)
        return _result(activate_package_shims(command_context, managers=managers), generated_at=generated_at)
    if operation == "guard.packageShims.repair":
        managers = _package_shim_managers(payload)
        return _result(
            activate_package_shims(command_context, managers=managers, repair=True),
            generated_at=generated_at,
        )
    if operation == "guard.packageShims.remove":
        managers = _package_shim_managers(payload)
        return _waiting_local_confirm(
            _package_shim_remove_confirmation_payload(managers),
            generated_at=generated_at,
        )
    if operation == "guard.packageShims.test":
        managers = _package_shim_managers(payload)
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
            return {
                "failureCode": "workspace_required",
                "failureMessage": "Package shim audit requires a workspace path.",
            }
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
            record_package_shim_audit_result(command_context, audited_at=generated_at)
        return _result(audit_payload, generated_at=generated_at)
    return {
        "failureCode": "unsupported_operation",
        "failureMessage": f"Unsupported package shim operation: {operation}",
    }


def _execute_app_operation(
    operation: str,
    *,
    payload: dict[str, object],
    context: HarnessContext,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    harness = _optional_string(payload.get("harness"))
    surface = _optional_surface(payload.get("surface"))
    workspace = str(context.workspace_dir) if context.workspace_dir is not None else None
    if operation == "guard.app.status":
        if harness is None:
            return _result({"items": list_harness_setup_items(context, store)}, generated_at=generated_at)
        get_adapter(harness)
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
    if harness is None:
        return {"failureCode": "harness_required", "failureMessage": "App command requires a harness."}
    get_adapter(harness)
    if operation == "guard.app.connect":
        return _result(
            apply_managed_install("install", harness, False, context, store, workspace, generated_at, surface=surface),
            generated_at=generated_at,
        )
    if operation == "guard.app.repair":
        result = apply_managed_install(
            "install",
            harness,
            False,
            context,
            store,
            workspace,
            generated_at,
            surface=surface,
        )
        result["action"] = "repair"
        return _result(result, generated_at=generated_at)
    if operation == "guard.app.remove":
        return _waiting_local_confirm(
            _app_remove_confirmation_payload(harness=harness, surface=surface),
            generated_at=generated_at,
        )
    return {
        "failureCode": "unsupported_operation",
        "failureMessage": f"Unsupported app operation: {operation}",
    }


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
    )
    return HarnessContext(
        home_dir=base_context.home_dir,
        workspace_dir=workspace_dir or base_context.workspace_dir,
        guard_home=base_context.guard_home,
    )


def _package_shim_managers(payload: dict[str, object]) -> tuple[str, ...] | None:
    managers = payload.get("managers")
    if managers is None:
        return None
    if not isinstance(managers, list) or not managers:
        raise ValueError("invalid_managers")
    normalized = tuple(manager.strip().lower() for manager in managers if isinstance(manager, str) and manager.strip())
    if len(normalized) != len(managers):
        raise ValueError("invalid_managers")
    if len(normalized) != len(set(normalized)):
        raise ValueError("duplicate_manager")
    supported = set(package_shim_supported_managers())
    if not set(normalized).issubset(supported):
        raise ValueError("unsupported_manager")
    return normalized


def _package_shim_remove_confirmation_payload(
    managers: tuple[str, ...] | None,
) -> dict[str, object]:
    confirm_parts = ["hol-guard", "package-shims", "uninstall"]
    if managers:
        for manager in managers:
            confirm_parts.extend(["--manager", manager])
    summary = "Run the local package-shim uninstall command on this machine to confirm removal."
    if managers:
        summary = (
            "Run the local package-shim uninstall command on this machine to "
            f"confirm removal for {', '.join(managers)}."
        )
    return {
        "confirm_command": " ".join(confirm_parts),
        "managers": list(managers or ()),
        "summary": summary,
    }


def _app_remove_confirmation_payload(
    *,
    harness: str,
    surface: str | None,
) -> dict[str, object]:
    confirmation_phrase = uninstall_confirmation_token(harness)
    confirm_parts = ["hol-guard", "apps", "disconnect", harness]
    if surface is not None:
        confirm_parts.extend(["--surface", surface])
    confirm_parts.extend(["--confirm", confirmation_phrase])
    return {
        "confirm_command": " ".join(confirm_parts),
        "confirmation_phrase": confirmation_phrase,
        "harness": harness,
        "summary": (
            f"Run the local disconnect command on this machine to confirm removing Guard protection for {harness}."
        ),
        "surface": surface,
    }


def command_job_operation(job: dict[str, object]) -> str:
    operation = job.get("operation")
    return operation if isinstance(operation, str) else ""


def _job_payload(job: dict[str, object]) -> dict[str, object]:
    return _mapping(job.get("payload"))


def _optional_string(value: object) -> str | None:
    return _text(value)


def _optional_surface(value: object) -> str | None:
    surface = _optional_string(value)
    if surface is None:
        return None
    if surface not in {"editor", "cli"}:
        raise ValueError("unsupported_surface")
    return surface


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
