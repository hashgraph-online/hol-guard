"""Guard library steps the native daemon's supply-chain routes run.

The native daemon owns the ``/v1/supply-chain/*`` routes: dispatch, the
per-workspace action rate limit, the one-at-a-time mutation lock, manager
validation, the approval gate and every reply. Each call here is one library
step it cannot take natively yet and reports its outcome as data.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any

from ..adapters.base import HarnessContext
from ..config import load_guard_config
from ..headless_receipts import record_headless_receipt
from ..local_supply_chain import managed_install_audit_workspace_dirs, resolve_package_firewall_entitlement_with_refresh
from ..native_daemon_handler import NativeDaemonHandlerError, native_supply_chain_error
from ..native_hook_artifact_compose import NativeHookComposeError
from ..native_runner_authority import NativeRunnerAuthorityError
from ..package_firewall_entitlement import package_firewall_access, package_firewall_entitlement_or_denied
from ..package_firewall_receipts import package_firewall_receipt_metadata
from ..package_shim_status import record_package_shim_audit_result
from ..project_folder_picker import (
    ProjectFolderPickerBusyError,
    ProjectFolderPickerUnavailableError,
    choose_project_folder,
)
from ..shims import (
    activate_package_shims,
    package_shim_dashboard_status,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
    uninstall_package_shims,
)
from ..store import GuardStore
from ..supply_chain_repair import coordinate_supply_chain_repair, repair_sync_intelligence
from ..supply_chain_workspace_audit import build_workspace_audit_payload, resolve_supply_chain_audit_workspace_dir
from .control_host import control_server


def _text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _payload(args: Mapping[str, Any]) -> dict[str, object]:
    payload = args.get("payload")
    return dict(payload) if isinstance(payload, dict) else {}


def _workspace_dir(store: GuardStore, payload: Mapping[str, object], *, reject_invalid_explicit: bool) -> Path | None:
    return resolve_supply_chain_audit_workspace_dir(
        workspace_dir_value=payload.get("workspace_dir"),
        workspace_value=payload.get("workspace"),
        allowed_roots=(Path.home().resolve(), Path.cwd().resolve(), Path(tempfile.gettempdir()).resolve()),
        managed_workspace_dirs=managed_install_audit_workspace_dirs(store),
        reject_invalid_explicit=reject_invalid_explicit,
        guard_home=store.guard_home,
    )


def supply_chain_context(
    store: GuardStore, payload: Mapping[str, object], *, reject_invalid_explicit: bool = False
) -> HarnessContext:
    """The harness context for the project folder a request names."""

    return HarnessContext(
        home_dir=Path.home().resolve(),
        workspace_dir=_workspace_dir(store, payload, reject_invalid_explicit=reject_invalid_explicit),
        guard_home=store.guard_home,
    )


def supply_chain_entitlement(server: Any) -> dict[str, object]:
    """The entitlement, read without a refresh while a connect is in flight."""

    from ..daemon.server_control_connect_state import (
        _copy_guard_cloud_connect_state,
        _copy_package_firewall_connect_state,
        _guard_cloud_connect_state_is_in_flight,
    )

    with server.guard_cloud_browser_session_lock:
        cloud_connect = _copy_guard_cloud_connect_state(server)
        package_connect = _copy_package_firewall_connect_state(server)
        if _guard_cloud_connect_state_is_in_flight(cloud_connect) or _guard_cloud_connect_state_is_in_flight(
            package_connect
        ):
            return package_firewall_entitlement_or_denied(server.store)
        return resolve_package_firewall_entitlement_with_refresh(server.store)


def _access(
    store: GuardStore, entitlement: dict[str, object], operation: str | None, has_installed_managers: bool
) -> dict[str, object] | None:
    try:
        access = package_firewall_access(
            entitlement,
            operation=operation,
            has_installed_managers=has_installed_managers,
            guard_home=store.guard_home,
        )
    except NativeHookComposeError:
        return None
    return {
        "operation_allowed": access.operation_allowed,
        "block": list(access.block),
        "available_actions": access.available_actions,
        "action_states": access.action_states,
    }


def entitlement(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The package-protection entitlement, refreshed unless a connect is running."""

    with control_server(store, args) as server:
        return supply_chain_entitlement(server)


def status(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """What the package-protection status view shows."""

    from ..daemon.server_control_connect_state import _resolve_package_firewall_connect_flow

    with control_server(store, args) as server:
        current = supply_chain_entitlement(server)
        shims = package_shim_dashboard_status(
            HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=store.guard_home)
        )
        access = _access(store, current, None, bool(shims.get("installed_managers")))
        answer: dict[str, object] = {"entitlement": current, "access": access}
        if access is None:
            return answer
        try:
            audit_dir = _workspace_dir(store, {}, reject_invalid_explicit=False)
        except NativeRunnerAuthorityError:
            return {**answer, "workspace": "unavailable"}
        return {
            **answer,
            "workspace": "ok",
            "audit_workspace_dir": str(audit_dir) if audit_dir is not None else None,
            "connect_flow": _resolve_package_firewall_connect_flow(server=server, entitlement=current),
            "supported_managers": list(package_shim_supported_managers()),
            "package_shims": shims,
        }


def prepare(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Entitlement, workspace and access for one package-protection action."""

    operation = args.get("operation")
    access_operation = args.get("access_operation", operation)
    if not isinstance(operation, str) or not isinstance(access_operation, str):
        return {"workspace": "invalid", "error": "unsupported_supply_chain_operation"}
    payload = _payload(args)
    with control_server(store, args) as server:
        current = supply_chain_entitlement(server)
    answer: dict[str, object] = {
        "entitlement": current,
        "supported_managers": list(package_shim_supported_managers()),
        "workspace_id": store.get_cloud_workspace_id(),
    }
    try:
        context = supply_chain_context(store, payload, reject_invalid_explicit=operation == "audit")
    except NativeRunnerAuthorityError:
        return {**answer, "workspace": "unavailable"}
    except ValueError as error:
        return {**answer, "workspace": "invalid", "error": str(error)}
    installed = bool(package_shim_status(context).get("installed_managers"))
    return {**answer, "workspace": "ok", "access": _access(store, current, access_operation, installed)}


def _managers(args: Mapping[str, Any]) -> tuple[str, ...] | None:
    managers = args.get("managers")
    if isinstance(managers, list) and all(isinstance(manager, str) for manager in managers):
        return tuple(managers)
    return None


def _run(store: GuardStore, operation: str, context: HarnessContext, managers: tuple[str, ...] | None) -> dict:
    from ..daemon.server_control_cloud_sync import _sync_supply_chain_cloud_state_with_optional_auth_context

    if operation == "install":
        return activate_package_shims(context, managers=managers)
    if operation == "repair":
        return activate_package_shims(context, managers=managers, repair=True)
    if operation == "remove":
        return uninstall_package_shims(context, managers=managers)
    if operation == "test":
        return probe_package_shim_intercepts(
            context, managers=managers, workspace_dir=context.workspace_dir, project_shell_profile=True
        )
    if operation == "audit":
        if context.workspace_dir is None:
            raise ValueError("workspace_dir_required")
        now = datetime.now(timezone.utc).isoformat()
        audit_payload, exit_code = build_workspace_audit_payload(
            command_name="audit",
            config=load_guard_config(store.guard_home),
            now=now,
            sbom_paths=(),
            store=store,
            workspace_dir=context.workspace_dir,
        )
        audit_payload["exit_code"] = exit_code
        if exit_code == 0:
            proof = record_package_shim_audit_result(context, audited_at=now)
            if isinstance(proof, dict):
                audit_payload.update(proof)
        return audit_payload
    if operation == "sync":
        return _sync_supply_chain_cloud_state_with_optional_auth_context(
            store, None, workspace_dir=context.workspace_dir
        )
    raise ValueError("unsupported_supply_chain_operation")


def run(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Runs one package-protection action and records its receipt."""

    from ..daemon.server_control_cloud_sync import (
        _managed_controls_publish_for,
        _queue_headless_cloud_sync_with_optional_publish,
    )
    from ..daemon.server_control_connect_state import _activate_package_firewall_runtime

    operation = args.get("operation")
    if not isinstance(operation, str):
        return {"value_error": "unsupported_supply_chain_operation"}
    payload = _payload(args)
    managers = _managers(args)
    try:
        context = supply_chain_context(store, payload, reject_invalid_explicit=operation == "audit")
        if operation == "activate":
            code, response = _activate_package_firewall_runtime(context)
            return {"reply": [code, response]}
        result = _run(store, operation, context, managers)
    except NativeRunnerAuthorityError:
        return {"workspace": "unavailable"}
    except ValueError as error:
        return {"value_error": str(error)}
    except Exception as error:
        try:
            code, body = native_supply_chain_error(operation, error, guard_home=store.guard_home)
        except NativeDaemonHandlerError:
            return {"reply": [503, {"error": "native_handler_policy_unavailable"}]}
        return {"reply": [code, body]}
    overrides = package_firewall_receipt_metadata(
        operation=operation, result=result, managers=managers, workspace_dir=context.workspace_dir, store=store
    )
    evidence = overrides.get("scanner_evidence")
    receipt = record_headless_receipt(
        store,
        harness="package-firewall",
        operation=operation,
        payload=payload,
        result=result,
        workspace_id=_text(payload.get("workspace_id")) or store.get_cloud_workspace_id(),
        policy_decision=_text(overrides.get("policy_decision")),
        capabilities_summary=_text(overrides.get("capabilities_summary")),
        artifact_name=_text(overrides.get("artifact_name")),
        scanner_evidence_extra=evidence if isinstance(evidence, dict) else None,
    )
    answer: dict[str, object] = {"result": result, "receipt": receipt}
    if operation == "audit":
        with control_server(store, args) as server:
            cloud_sync = _queue_headless_cloud_sync_with_optional_publish(
                store=store, managed_controls_publish=_managed_controls_publish_for(server)
            )
        receipt["cloud_sync"] = cloud_sync
        answer["cloud_sync"] = cloud_sync
    return answer


def repair_all(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Repairs package shims, the runtime and intelligence, then records the receipt."""

    from ..daemon.server_control_connect_state import (
        _activate_package_firewall_runtime,
        _repair_detected_package_shims,
    )

    payload = _payload(args)
    install_missing = args.get("install_missing") is True
    try:
        context = supply_chain_context(store, payload, reject_invalid_explicit=False)
    except NativeRunnerAuthorityError:
        return {"workspace": "unavailable"}
    result = coordinate_supply_chain_repair(
        repair_package_shims=partial(_repair_detected_package_shims, context, install_missing=install_missing),
        activate_runtime=partial(_activate_package_firewall_runtime, context),
        sync_intelligence=partial(repair_sync_intelligence, store, workspace_dir=context.workspace_dir),
    )
    receipt = record_headless_receipt(
        store,
        harness="package-firewall",
        operation="repair_all",
        payload=payload,
        result=result,
        workspace_id=_text(payload.get("workspace_id")) or store.get_cloud_workspace_id(),
    )
    return {"result": result, "receipt": receipt}


def choose_folder(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Opens the project folder picker and resolves what was chosen."""

    del args
    try:
        selected = choose_project_folder()
    except ProjectFolderPickerBusyError:
        return {"picker": "busy"}
    except ProjectFolderPickerUnavailableError:
        return {"picker": "unavailable"}
    if selected is None:
        return {"picker": "cancelled"}
    try:
        resolved = _workspace_dir(store, {"workspace_dir": selected}, reject_invalid_explicit=True)
    except NativeRunnerAuthorityError:
        return {"picker": "chosen", "workspace": "unavailable"}
    except ValueError as error:
        return {"picker": "chosen", "workspace": "invalid", "error": str(error)}
    if resolved is None:
        return {"picker": "chosen", "workspace": "invalid", "error": "workspace_dir_invalid"}
    return {"picker": "chosen", "workspace": "ok", "workspace_dir": str(resolved)}


def workspace_id(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The paired Cloud workspace, which keys the action rate limit."""

    del args
    return {"workspace_id": store.get_cloud_workspace_id()}


SUPPLY_CHAIN_CALLS = {
    "supply_chain.workspace_id": workspace_id,
    "supply_chain.entitlement": entitlement,
    "supply_chain.status": status,
    "supply_chain.prepare": prepare,
    "supply_chain.run": run,
    "supply_chain.repair_all": repair_all,
    "supply_chain.choose_folder": choose_folder,
}
