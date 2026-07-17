"""Protect approval helpers for package-install flows."""

from __future__ import annotations

import argparse
import os
import shlex
from collections.abc import Callable
from pathlib import Path

from ..adapters.base import HarnessContext
from ..approvals import approval_center_hint, attach_primary_approval_link, queue_blocked_approvals
from ..config import load_guard_config
from ..models import GuardArtifact, HarnessDetection
from ..package_execution_context import (
    changed_package_execution_context_components,
    package_execution_context_from_evidence,
    package_execution_context_from_scanner_evidence,
)
from ..shim_probe import SHIM_PROBE_ENV_VALUE, SHIM_PROBE_ENV_VAR
from ..store import GuardStore


def _queue_local_protect_approvals(
    response_payload: dict[str, object],
    *,
    store: GuardStore,
    guard_home: Path,
    workspace: Path,
    ensure_approval_daemon: Callable[[Path], str],
    approval_delivery_payload: Callable[[str], dict[str, object]],
    localize_pending_approval_copy: Callable[[dict[str, object], str], None],
) -> None:
    if not _should_queue_local_protect_approval(response_payload):
        return
    artifact = _protect_request_artifact(response_payload, workspace=workspace)
    if artifact is None:
        return
    approval_item = _protect_approval_item(response_payload, workspace=workspace, artifact=artifact)
    if approval_item is None:
        return
    _annotate_package_execution_context_change(approval_item, store=store, artifact_id=artifact.artifact_id)
    try:
        approval_center_url = ensure_approval_daemon(guard_home)
    except RuntimeError:
        return
    detection = HarnessDetection(
        harness=artifact.harness,
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    _protect_config = load_guard_config(guard_home)
    queued = queue_blocked_approvals(
        detection=detection,
        evaluation={"artifacts": [approval_item]},
        store=store,
        approval_center_url=approval_center_url,
        redaction_level=_protect_config.receipt_redaction_level,
    )
    if not queued:
        return
    response_payload["approval_requests"] = queued
    response_payload["artifact_id"] = artifact.artifact_id
    response_payload["approval_request_ids"] = [
        str(item["request_id"]) for item in queued if isinstance(item, dict) and "request_id" in item
    ]
    response_payload["approval_center_url"] = approval_center_url
    harness = artifact.harness
    display_harness = _protect_display_harness(response_payload)
    attach_primary_approval_link(
        response_payload,
        harness=harness,
        approval_center_url=approval_center_url,
    )
    response_payload["review_hint"] = approval_center_hint(
        context=HarnessContext(home_dir=guard_home, workspace_dir=workspace, guard_home=guard_home),
        harness=display_harness,
        approval_center_url=approval_center_url,
        queued=queued,
        request_id=_optional_string(response_payload.get("primary_approval_request_id")),
        artifact_id=artifact.artifact_id,
    )
    response_payload["approval_delivery"] = approval_delivery_payload(display_harness)
    localize_pending_approval_copy(response_payload, display_harness)
    _bind_protect_receipt_approval(response_payload, store=store)


def _should_queue_local_protect_approval(response_payload: dict[str, object]) -> bool:
    if os.environ.get(SHIM_PROBE_ENV_VAR) == SHIM_PROBE_ENV_VALUE:
        return False
    if _protect_has_reason_code(response_payload, "saved_package_block"):
        return False
    return not (
        os.environ.get("PYTEST_CURRENT_TEST") and os.environ.get("HOL_GUARD_TEST_SKIP_LOCAL_APPROVAL_QUEUE") == "1"
    )


def _protect_request_artifact(response_payload: dict[str, object], *, workspace: Path) -> GuardArtifact | None:
    receipt = response_payload.get("receipt")
    request = response_payload.get("request")
    if not isinstance(receipt, dict) or not isinstance(request, dict):
        return None
    artifact_id = _optional_string(receipt.get("artifact_id"))
    if artifact_id is None:
        return None
    artifact_name = _optional_string(receipt.get("artifact_name")) or artifact_id
    redacted_command = _optional_string(request.get("redacted_command"))
    command_tokens = request.get("command")
    if redacted_command is None and isinstance(command_tokens, list):
        command_parts = [str(item) for item in command_tokens if isinstance(item, str)]
        redacted_command = shlex.join(command_parts) if command_parts else None
    source_scope = _optional_string(receipt.get("source_scope")) or "project"
    package_manager = (
        _optional_string(request.get("package_manager")) or _optional_string(request.get("executor")) or "package"
    )
    intent_kind = _optional_string(request.get("install_kind")) or "install"
    config_path = str(workspace / "hol-guard.toml")
    return GuardArtifact(
        artifact_id=artifact_id,
        name=artifact_name,
        harness=_protect_payload_harness(response_payload),
        artifact_type="package_request",
        source_scope=source_scope,
        config_path=config_path,
        command=redacted_command,
        metadata={
            "package_manager": package_manager,
            "intent_kind": intent_kind,
            "targets": request.get("targets") if isinstance(request.get("targets"), list) else [],
            "manifest_paths": request.get("manifest_paths") if isinstance(request.get("manifest_paths"), list) else [],
            "lockfile_paths": request.get("lockfile_paths") if isinstance(request.get("lockfile_paths"), list) else [],
            "redacted_command": redacted_command,
        },
    )


def _protect_approval_item(
    response_payload: dict[str, object],
    *,
    workspace: Path,
    artifact: GuardArtifact,
) -> dict[str, object] | None:
    del workspace
    supply_chain_evaluation = response_payload.get("supply_chain_evaluation")
    receipt = response_payload.get("receipt")
    verdict = response_payload.get("verdict")
    if not isinstance(supply_chain_evaluation, dict) or not isinstance(receipt, dict) or not isinstance(verdict, dict):
        return None
    policy_action = _protect_policy_action(response_payload)
    if policy_action not in {"block", "require-reapproval"}:
        return None
    user_copy = supply_chain_evaluation.get("user_copy")
    user_copy_map = user_copy if isinstance(user_copy, dict) else {}
    request = response_payload.get("request")
    package_context = request.get("package_execution_context") if isinstance(request, dict) else None
    scanner_evidence = [dict(package_context)] if isinstance(package_context, dict) else []
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_name": artifact.name,
        "artifact_hash": _optional_string(receipt.get("artifact_hash")) or artifact.artifact_id,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "policy_action": policy_action,
        "changed_fields": _protect_target_labels(response_payload),
        "risk_summary": _optional_string(verdict.get("reason"))
        or _optional_string(supply_chain_evaluation.get("risk_summary"))
        or _optional_string(user_copy_map.get("summary")),
        "risk_signals": _string_list(verdict.get("risk_signals")),
        "action_envelope_json": (
            receipt.get("action_envelope_json") if isinstance(receipt.get("action_envelope_json"), dict) else None
        ),
        "decision_v2_json": {
            "action": policy_action,
            "user_title": _optional_string(user_copy_map.get("title")) or "Review required",
            "summary": _optional_string(user_copy_map.get("summary")) or _optional_string(verdict.get("reason")) or "",
            "harness_message": _optional_string(user_copy_map.get("harness_message")) or "",
        },
        "scanner_evidence": scanner_evidence,
    }


def _annotate_package_execution_context_change(
    approval_item: dict[str, object],
    *,
    store: GuardStore,
    artifact_id: str,
) -> None:
    scanner_evidence = approval_item.get("scanner_evidence")
    current = package_execution_context_from_scanner_evidence(scanner_evidence)
    if current is None:
        return
    previous = None
    for request in store.list_approval_requests(status="resolved", limit=200):
        if request.get("artifact_id") != artifact_id:
            continue
        previous = package_execution_context_from_scanner_evidence(request.get("scanner_evidence"))
        if previous is not None:
            break
    if previous is None or previous.digest == current.digest:
        return
    changed_components = changed_package_execution_context_components(previous, current)
    if not changed_components:
        return
    changed_fields = _string_list(approval_item.get("changed_fields"))
    changed_fields.extend(f"package_context_{component}" for component in changed_components)
    approval_item["changed_fields"] = list(dict.fromkeys(changed_fields))
    if not isinstance(scanner_evidence, list):
        return
    for index, evidence in enumerate(scanner_evidence):
        parsed = package_execution_context_from_evidence(evidence)
        if parsed is not None and parsed.digest == current.digest and isinstance(evidence, dict):
            scanner_evidence[index] = {**evidence, "changed_components": list(changed_components)}
            break


def _protect_target_labels(response_payload: dict[str, object]) -> list[str]:
    request = response_payload.get("request")
    if not isinstance(request, dict):
        return []
    targets = request.get("targets")
    if not isinstance(targets, list):
        return []
    labels: list[str] = []
    for item in targets:
        if not isinstance(item, dict):
            continue
        candidate = _optional_string(item.get("package_name")) or _optional_string(item.get("raw_spec"))
        if candidate is not None and candidate not in labels:
            labels.append(candidate)
    return labels


def _protect_payload_harness(response_payload: dict[str, object]) -> str:
    request = response_payload.get("request")
    if isinstance(request, dict):
        for key in ("harness", "package_manager", "executor"):
            value = _optional_string(request.get(key))
            if value is not None:
                return value
    receipt = response_payload.get("receipt")
    if isinstance(receipt, dict):
        value = _optional_string(receipt.get("harness"))
        if value is not None:
            return value
    return "guard-cli"


def _protect_display_harness(response_payload: dict[str, object]) -> str:
    request = response_payload.get("request")
    if isinstance(request, dict):
        for key in ("package_manager", "harness", "executor"):
            value = _optional_string(request.get(key))
            if value is not None:
                return value
    return _protect_payload_harness(response_payload)


def _protect_policy_action(response_payload: dict[str, object]) -> str | None:
    verdict = response_payload.get("verdict")
    if isinstance(verdict, dict):
        action = _optional_string(verdict.get("action"))
        if action == "block":
            return "block"
        if action == "review":
            return "require-reapproval"
    supply_chain_evaluation = response_payload.get("supply_chain_evaluation")
    if not isinstance(supply_chain_evaluation, dict):
        return None
    return _optional_string(supply_chain_evaluation.get("policy_action"))


def _protect_has_reason_code(response_payload: dict[str, object], reason_code: str) -> bool:
    supply_chain_evaluation = response_payload.get("supply_chain_evaluation")
    if not isinstance(supply_chain_evaluation, dict):
        return False
    reasons = supply_chain_evaluation.get("reasons")
    if not isinstance(reasons, list):
        return False
    return any(_optional_string(item.get("code")) == reason_code for item in reasons if isinstance(item, dict))


def _bind_protect_receipt_approval(response_payload: dict[str, object], *, store: GuardStore) -> None:
    receipt = response_payload.get("receipt")
    if not isinstance(receipt, dict):
        return
    receipt_id = _optional_string(receipt.get("receipt_id"))
    approval_request_id = _optional_string(response_payload.get("primary_approval_request_id"))
    if receipt_id is None or approval_request_id is None:
        return
    receipt["approval_source"] = "approval-center"
    receipt["approval_request_id"] = approval_request_id
    store.update_receipt_approval_context(
        receipt_id,
        approval_source="approval-center",
        approval_request_id=approval_request_id,
    )


def _suppress_package_shim_allow_output(args: argparse.Namespace, response_payload: dict[str, object]) -> bool:
    if not bool(getattr(args, "package_shim_ui", False)) or bool(getattr(args, "json", False)):
        return False
    verdict = response_payload.get("verdict")
    action = _optional_string(verdict.get("action")) if isinstance(verdict, dict) else None
    return action == "allow"


def _optional_string(value: object | None) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _string_list(value: object | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]
