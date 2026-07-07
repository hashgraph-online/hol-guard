"""Typed executors for Guard Cloud command queue jobs."""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeGuard

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
from ..local_supply_chain import (
    build_workspace_audit_payload,
    managed_install_audit_workspace_dirs,
    resolve_supply_chain_audit_workspace_dir,
    sync_supply_chain_cloud_state,
)
from ..models import DECISION_SCOPE_VALUES, GUARD_ACTION_VALUES, DecisionScope, GuardAction, PolicyDecision
from ..package_shim_status import record_package_shim_audit_result
from ..review_contracts import (
    GuardReviewContractError,
    guard_review_oauth_metadata,
    validate_decision_memory_bundle_target,
    validate_remote_approval_request_binding,
    validated_decision_memory_bundle,
    validated_remote_approval_envelope,
)
from ..review_memory_ack import build_decision_memory_ack
from ..shims import (
    activate_package_shims,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
)
from ..store import GuardStore
from . import local_request_snapshots

_GUARD_REVIEW_MEMORY_REGISTRY_SYNC_KEY = "guard_review_memory_registry"
_GUARD_REVIEW_MEMORY_VERSION_SYNC_KEY = "guard_review_memory_policy_version"
_GUARD_REVIEW_MEMORY_ACK_SYNC_KEY = "guard_review_memory_last_ack"

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
SUPPORTED_COMMAND_OPERATIONS: tuple[str, ...] = (*PACKAGE_SHIM_OPERATIONS, *APP_OPERATIONS, *APPROVAL_OPERATIONS)
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
        if operation in APP_OPERATIONS:
            return _execute_app_operation(
                operation,
                payload=payload,
                context=context,
                store=store,
                generated_at=generated_at,
            )
        if operation in APPROVAL_OPERATIONS:
            return _execute_approval_operation(
                operation,
                payload=payload,
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
            _execute_app_update_check(generated_at=generated_at),
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
    update_payload, exit_code = run_guard_update(
        dry_run=False,
        context=context,
        store=store,
        workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
        now=generated_at,
    )
    return {
        "update": update_payload,
        "exitCode": exit_code,
        "succeeded": exit_code == 0,
    }


def _execute_app_update_check(generated_at: str) -> dict[str, object]:
    return build_guard_update_status_payload()


def _execute_approval_operation(
    operation: str,
    *,
    payload: dict[str, object],
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    if operation == "guard.localRequests.snapshot":
        return _result(_local_request_snapshot_payload(store), generated_at=generated_at)
    if operation != "guard.approval.resolve":
        return {
            "failureCode": "unsupported_operation",
            "failureMessage": f"Unsupported approval operation: {operation}",
        }
    action = _optional_string(payload.get("action"))
    local_request_id = _optional_string(payload.get("localRequestId")) or _optional_string(
        payload.get("local_request_id")
    )
    if action not in {"allow_once", "block", "policy_sync"}:
        raise ValueError("invalid_approval_payload")
    if action == "policy_sync":
        return _execute_policy_sync(payload, store=store, generated_at=generated_at)
    if local_request_id is None:
        raise ValueError("invalid_approval_payload")
    remote_approval = _payload_mapping(payload.get("remoteApproval") or payload.get("remote_approval"))
    if not remote_approval:
        raise ValueError("missing_remote_approval")
    request_row = store.get_approval_request(local_request_id)
    if not isinstance(request_row, dict):
        return _result(
            {
                "action": action,
                "localRequestId": local_request_id,
                "status": "not_resolved",
            },
            generated_at=generated_at,
        )
    oauth = guard_review_oauth_metadata(store)
    envelope = validated_remote_approval_envelope(remote_approval, store=store)
    validate_remote_approval_request_binding(
        envelope=envelope,
        request_row=request_row,
        oauth=oauth,
        store=store,
    )
    request_policy_action = _optional_string(request_row.get("policy_action"))
    resolution_scope = _optional_string(request_row.get("recommended_scope"))
    if (
        request_policy_action not in {"block", "pause", "review", "require-reapproval"}
        or resolution_scope not in DECISION_SCOPE_VALUES
    ):
        raise ValueError("remote_approval_not_permitted")
    receipt_id = _optional_string(envelope.get("receiptId"))
    if receipt_id is None:
        raise ValueError("invalid_remote_approval_receipt")
    if not store.claim_remote_once_receipt(
        receipt_id,
        request_id=local_request_id,
        claimed_at=generated_at,
    ):
        raise ValueError("remote_approval_replayed")
    envelope_decision = _optional_string(envelope.get("decision"))
    if envelope_decision not in {"allow_once", "block"}:
        store.release_remote_once_receipt(receipt_id)
        raise ValueError("invalid_remote_approval_decision")
    resolution_scope = resolution_scope or "artifact"
    resolution_action = "block" if envelope_decision == "block" else "allow"
    try:
        result = store.resolve_request_with_signed_remote_result(
            local_request_id,
            resolution_action=resolution_action,
            resolution_scope=resolution_scope,
            reason=_optional_string(payload.get("reason")) or "Guard Cloud signed remote approval",
            resolved_at=generated_at,
        )
    except Exception:
        store.release_remote_once_receipt(receipt_id)
        raise
    if result.get("resolved") is not True:
        store.release_remote_once_receipt(receipt_id)
    return _result(
        {
            "action": action,
            "localRequestId": local_request_id,
            "remoteApproval": envelope,
            "resolution": result,
            "status": "completed" if result.get("resolved") is True else "not_resolved",
        },
        generated_at=generated_at,
    )


def _execute_policy_sync(
    payload: dict[str, object],
    *,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    bundle_payload = _payload_mapping(payload.get("decisionMemoryBundle") or payload.get("decision_memory_bundle"))
    if not bundle_payload:
        raise ValueError("missing_decision_memory_bundle")
    oauth = guard_review_oauth_metadata(store)
    bundle = validated_decision_memory_bundle(bundle_payload, store=store)
    validate_decision_memory_bundle_target(
        bundle=bundle,
        oauth=oauth,
        last_policy_version=_stored_review_memory_policy_version(store),
    )
    registry = _stored_review_memory_registry(store)
    revocations = bundle.get("revocations")
    for revoked_rule_id in revocations if isinstance(revocations, list) else []:
        revoked_key = _optional_string(revoked_rule_id)
        if revoked_key is not None:
            registry.pop(revoked_key, None)
    rejected_rule_ids: list[str] = []
    applied_rule_count = 0
    rules = bundle.get("memoryRules")
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            raise ValueError("invalid_decision_memory_rule")
        rule_id = _optional_string(rule.get("ruleId"))
        if rule_id is None:
            raise ValueError("invalid_decision_memory_rule")
        try:
            decision = _decision_from_memory_rule(bundle=bundle, rule=rule)
        except GuardReviewContractError:
            rejected_rule_ids.append(rule_id)
            continue
        registry[rule_id] = {
            "decision": decision.to_dict(),
            "ruleId": rule_id,
        }
        applied_rule_count += 1
    store.replace_remote_policies(
        [
            *_existing_non_review_remote_policies(store),
            *[_decision_from_registry_entry(entry) for entry in registry.values()],
        ],
        generated_at,
        remote_write_authorized=True,
    )
    store.set_sync_payload(
        _GUARD_REVIEW_MEMORY_REGISTRY_SYNC_KEY,
        list(registry.values()),
        generated_at,
    )
    ack_status = "accepted" if not rejected_rule_ids else "rejected"
    if ack_status == "accepted":
        store.set_sync_payload(
            _GUARD_REVIEW_MEMORY_VERSION_SYNC_KEY,
            {"policyVersion": _optional_string(bundle.get("policyVersion"))},
            generated_at,
        )
    ack = build_decision_memory_ack(
        bundle=bundle,
        oauth=oauth,
        status=ack_status,
        applied_rule_count=applied_rule_count,
        reason=None if not rejected_rule_ids else "decision_memory_rule_rejected",
        rejected_rule_ids=rejected_rule_ids,
    )
    store.set_sync_payload(_GUARD_REVIEW_MEMORY_ACK_SYNC_KEY, ack, generated_at)
    return _result(
        {
            "action": "policy_sync",
            "bundleHash": _optional_string(bundle.get("bundleHash")),
            "bundleVersion": _optional_string(bundle.get("bundleVersion")),
            "decisionMemoryAck": ack,
            "localRequestId": _optional_string(payload.get("localRequestId")),
            "status": str(ack["status"]),
        },
        generated_at=generated_at,
    )


def _local_policy_scope(scope: str | None) -> DecisionScope:
    """Map Cloud policy scopes onto the narrower local policy model."""
    if scope in {"workspace", "team", "policy", "machine", "project"}:
        return "workspace"
    if scope == "item":
        return "artifact"
    return "artifact"


def _is_decision_scope(value: object) -> TypeGuard[DecisionScope]:
    return isinstance(value, str) and value in DECISION_SCOPE_VALUES


def _is_guard_action(value: object) -> TypeGuard[GuardAction]:
    return isinstance(value, str) and value in GUARD_ACTION_VALUES


def _local_request_snapshot_items(store: GuardStore) -> list[dict[str, object]]:
    return local_request_snapshots.local_request_snapshot_items(store)


def _local_request_snapshot_payload(store: GuardStore) -> dict[str, object]:
    local_request_snapshots.LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT = LOCAL_REQUEST_PENDING_SNAPSHOT_LIMIT
    local_request_snapshots.LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT = LOCAL_REQUEST_RESOLVED_SNAPSHOT_LIMIT
    local_request_snapshots.LOCAL_REQUEST_SNAPSHOT_MAX_BYTES = LOCAL_REQUEST_SNAPSHOT_MAX_BYTES
    return local_request_snapshots.local_request_snapshot_payload(store)


def _local_request_snapshot_items_for_status(
    store: GuardStore,
    *,
    status: str,
    limit: int,
) -> tuple[list[dict[str, object]], bool]:
    return local_request_snapshots._local_request_snapshot_items_for_status(
        store,
        status=status,
        limit=limit,
    )


def _local_request_snapshot_byte_capped_items(
    items: list[dict[str, object]],
    *,
    max_bytes: int,
    existing_items: list[dict[str, object]] | None = None,
) -> tuple[list[dict[str, object]], bool]:
    return local_request_snapshots._local_request_snapshot_byte_capped_items(
        items,
        max_bytes=max_bytes,
        existing_items=existing_items,
    )


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


def _payload_mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _stored_review_memory_policy_version(store: GuardStore) -> str | None:
    payload = store.get_sync_payload(_GUARD_REVIEW_MEMORY_VERSION_SYNC_KEY)
    if not isinstance(payload, dict):
        return None
    return _optional_string(payload.get("policyVersion"))


def _stored_review_memory_registry(store: GuardStore) -> dict[str, dict[str, object]]:
    payload = store.get_sync_payload(_GUARD_REVIEW_MEMORY_REGISTRY_SYNC_KEY)
    if not isinstance(payload, list):
        return {}
    registry: dict[str, dict[str, object]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        rule_id = _optional_string(item.get("ruleId"))
        decision = item.get("decision")
        if rule_id is None or not isinstance(decision, dict):
            continue
        registry[rule_id] = {"decision": dict(decision), "ruleId": rule_id}
    return registry


def _existing_non_review_remote_policies(store: GuardStore) -> list[PolicyDecision]:
    decisions: list[PolicyDecision] = []
    for item in store.list_policy_decisions():
        if item.get("source") in {"cloud-signed-memory"}:
            continue
        if item.get("source") not in {"cloud-sync", "team-policy", "policy-bundle"}:
            continue
        scope = _optional_string(item.get("scope"))
        action = _optional_string(item.get("action"))
        harness = _optional_string(item.get("harness"))
        if scope is None or action is None or harness is None:
            continue
        if not _is_decision_scope(scope) or not _is_guard_action(action):
            continue
        decisions.append(
            PolicyDecision(
                harness=harness,
                scope=scope,
                action=action,
                artifact_id=_optional_string(item.get("artifact_id")),
                artifact_hash=_optional_string(item.get("artifact_hash")),
                workspace=_optional_string(item.get("workspace")),
                publisher=_optional_string(item.get("publisher")),
                reason=_optional_string(item.get("reason")),
                owner=_optional_string(item.get("owner")),
                source=str(item.get("source") or "cloud-sync"),
                expires_at=_optional_string(item.get("expires_at")),
            )
        )
    return decisions


def _decision_from_registry_entry(entry: dict[str, object]) -> PolicyDecision:
    decision = entry.get("decision")
    if not isinstance(decision, dict):
        raise ValueError("invalid_decision_memory_registry")
    harness = _optional_string(decision.get("harness"))
    scope = _optional_string(decision.get("scope"))
    action = _optional_string(decision.get("action"))
    if harness is None or scope is None or action is None:
        raise ValueError("invalid_decision_memory_registry")
    if not _is_decision_scope(scope) or not _is_guard_action(action):
        raise ValueError("invalid_decision_memory_registry")
    return PolicyDecision(
        harness=harness,
        scope=scope,
        action=action,
        artifact_id=_optional_string(decision.get("artifact_id")),
        artifact_hash=_optional_string(decision.get("artifact_hash")),
        workspace=_optional_string(decision.get("workspace")),
        publisher=_optional_string(decision.get("publisher")),
        reason=_optional_string(decision.get("reason")),
        owner=_optional_string(decision.get("owner")),
        source=str(decision.get("source") or "cloud-signed-memory"),
        expires_at=_optional_string(decision.get("expires_at")),
    )


def _decision_from_memory_rule(
    *,
    bundle: dict[str, object],
    rule: dict[str, object],
) -> PolicyDecision:
    harness = _optional_string(rule.get("harnessId"))
    artifact_id = _optional_string(rule.get("artifactId"))
    action = _optional_string(rule.get("action"))
    scope_value = _optional_string(rule.get("scope"))
    if harness is None or artifact_id is None or action is None or scope_value is None:
        raise GuardReviewContractError("invalid_decision_memory_rule")
    if not _is_guard_action(action):
        raise GuardReviewContractError("invalid_decision_memory_rule")
    if action == "allow" and scope_value not in {"artifact", "workspace"}:
        raise GuardReviewContractError("decision_memory_allow_scope_unsupported")
    scope = _local_policy_scope(scope_value)
    target = rule.get("target")
    target_payload = target if isinstance(target, dict) else {}
    workspace_ids = target_payload.get("workspaceIds")
    workspace = _optional_string(bundle.get("workspaceId"))
    if scope == "workspace" and isinstance(workspace_ids, list):
        workspace = next(
            (candidate for candidate in (_optional_string(item) for item in workspace_ids) if candidate is not None),
            workspace,
        )
    return PolicyDecision(
        harness=harness,
        scope=scope,
        action=action,
        artifact_id=artifact_id,
        artifact_hash=_optional_string(rule.get("artifactHash")),
        workspace=workspace if scope == "workspace" else None,
        publisher=None,
        reason=_optional_string(rule.get("reason")) or "Guard Cloud signed decision memory sync",
        owner=None,
        source="cloud-signed-memory",
        expires_at=_optional_string(rule.get("expiresAt")),
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
    payload = job.get("operationPayload")
    if not isinstance(payload, dict):
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
