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
)
from ..config import load_guard_config
from ..local_supply_chain import (
    build_workspace_audit_payload,
    managed_install_audit_workspace_dirs,
    resolve_supply_chain_audit_workspace_dir,
)
from ..package_shim_status import record_package_shim_audit_result
from ..runtime.runner import sync_supply_chain_bundle
from ..shims import (
    activate_package_shims,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
    uninstall_package_shims,
)
from ..store import GuardStore

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
)
SUPPORTED_COMMAND_OPERATIONS: tuple[str, ...] = (*PACKAGE_SHIM_OPERATIONS, *APP_OPERATIONS)
COMMAND_OPERATION_SCHEMA_VERSIONS: dict[str, int] = {operation: 1 for operation in SUPPORTED_COMMAND_OPERATIONS}


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
        if operation in APP_OPERATIONS:
            return _execute_app_operation(
                operation,
                payload=payload,
                context=context,
                store=store,
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
        return _result(uninstall_package_shims(command_context, managers=managers), generated_at=generated_at)
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
        return _result(sync_supply_chain_bundle(store), generated_at=generated_at)
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
        return _result(
            apply_managed_install(
                "uninstall",
                harness,
                False,
                context,
                store,
                workspace,
                generated_at,
                surface=surface,
            ),
            generated_at=generated_at,
        )
    return {
        "failureCode": "unsupported_operation",
        "failureMessage": f"Unsupported app operation: {operation}",
    }


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


def command_job_operation(job: dict[str, object]) -> str:
    operation = job.get("operation")
    return operation if isinstance(operation, str) else ""


def _job_payload(job: dict[str, object]) -> dict[str, object]:
    payload = job.get("payload")
    return dict(payload) if isinstance(payload, dict) else {}


def _optional_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _optional_surface(value: object) -> str | None:
    surface = _optional_string(value)
    if surface is None:
        return None
    if surface not in {"editor", "cli"}:
        raise ValueError("unsupported_surface")
    return surface


def _result(data: dict[str, object], *, generated_at: str) -> dict[str, object]:
    return {
        "data": data,
        "generatedAt": generated_at,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
