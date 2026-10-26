"""Native approval projections and display-only row mapping."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .approval_scope_support import apply_scope_surfaces, request_scope_contract_payloads
from .decision_boundaries import (
    CanonicalApprovalSurfaces,
    canonical_approval_surfaces_batch,
)
from .native_signal_projection import NativeSignalProjectionError, NativeSignalProjectionUnavailableError
from .runtime.browser_mcp_intent import classify_browser_operation

APPROVAL_QUEUE_PREVIEW_MAX_LENGTH = 512


_LEGACY_BROWSER_MULTI_ELEMENT_OPERATIONS = frozenset({"drag", "drag_drop_file", "fill_form"})


_LEGACY_BROWSER_ELEMENT_OPERATIONS = frozenset(
    {
        "click",
        "fill",
        "fill_input",
        "focus_element",
        "hover",
        "select_dropdown",
        "upload_file",
    }
)


def _browser_launch_target_for_display(value: object) -> tuple[object, str | None]:
    """Repair legacy browser labels without changing persisted approval identity."""
    if not isinstance(value, str):
        return value, None
    parts = value.split()
    if len(parts) != 3 or parts[2] != "unknown":
        return value, None
    server_name, operation, _unknown = parts
    try:
        intent = classify_browser_operation(operation, server_name)
    except ValueError:
        # Display-only label repair; a native outage must not break rendering
        # stored approvals. The decision path stays fail-closed.
        return value, None
    if intent is None:
        return value, None

    operation_lower = operation.lower()
    element_operation = operation_lower.removeprefix("browser_")
    if "network" in operation_lower:
        target = "network request" if operation_lower.startswith(("get_", "read_")) else "network activity"
    elif "console" in operation_lower:
        target = "console message" if operation_lower.startswith(("get_", "read_")) else "console messages"
    elif element_operation in _LEGACY_BROWSER_MULTI_ELEMENT_OPERATIONS:
        target = "page elements"
    elif element_operation in _LEGACY_BROWSER_ELEMENT_OPERATIONS:
        target = "page element"
    elif operation_lower in {"list_pages", "browser_list_pages"}:
        target = "open pages"
    elif operation_lower in {"select_page", "close_page", "browser_select_page", "browser_close_page"}:
        target = "browser page"
    else:
        target = "current page"
    return f"{server_name} {operation} {target}", target


def _browser_risk_signals_for_display(signals: list[object], target: str | None) -> list[object]:
    if target is None:
        return signals
    return [signal.replace("unknown target", target) if isinstance(signal, str) else signal for signal in signals]


def _approval_queue_preview(
    action_envelope: dict[str, object] | None,
    launch_target: object,
) -> str | None:
    command = action_envelope.get("command") if action_envelope is not None else None
    candidate = command if isinstance(command, str) and command.strip() else launch_target
    if not isinstance(candidate, str) or not candidate.strip():
        return None
    normalized = candidate.strip()
    if len(normalized) <= APPROVAL_QUEUE_PREVIEW_MAX_LENGTH:
        return normalized
    return f"{normalized[: APPROVAL_QUEUE_PREVIEW_MAX_LENGTH - 1]}…"


def _approval_queue_command_category(action_envelope: dict[str, object] | None) -> str | None:
    value = action_envelope.get("command_category") if action_envelope is not None else None
    return value if isinstance(value, str) and value.startswith("command.") else None


def _row_to_payload(row: sqlite3.Row, *, guard_home: Path | None = None) -> dict[str, object]:
    return _rows_to_payloads([row], guard_home=guard_home)[0]


def _rows_to_payloads(rows: list[sqlite3.Row], *, guard_home: Path | None = None) -> list[dict[str, object]]:
    """Build payloads, asking the resident for every row's scope contract in one call."""

    projections = _project_listing_rows(rows, guard_home=guard_home)
    drafts = [_row_to_draft(row, projection) for row, projection in zip(rows, projections, strict=True)]
    if not drafts:
        return []
    contracts = request_scope_contract_payloads([draft for draft, _error in drafts], guard_home=guard_home)
    payloads: list[dict[str, object]] = []
    for (payload, contract_error), contract in zip(drafts, contracts, strict=True):
        payload.update(contract)
        if contract_error is not None:
            payload["decision_contract_error"] = contract_error
        apply_scope_surfaces(payload)
        payloads.append(payload)
    return payloads


def _project_listing_rows(
    rows: list[sqlite3.Row], *, guard_home: Path | None = None
) -> list[CanonicalApprovalSurfaces]:
    """Project stored rows for listings; a resident failure reads as scope unavailable."""

    from .native_approval_scope import ApprovalScopeUnavailableError

    try:
        return canonical_approval_surfaces_batch([_row_decision_inputs(row) for row in rows], guard_home=guard_home)
    except (NativeSignalProjectionError, NativeSignalProjectionUnavailableError) as error:
        raise ApprovalScopeUnavailableError from error


def _row_decision_inputs(row: sqlite3.Row) -> tuple[object, object, object]:
    parsed_decision_v2 = _optional_json_object(row["decision_v2_json"])
    parsed_action_envelope = _optional_json_object(row["action_envelope_json"])
    return (
        row["policy_action"],
        parsed_decision_v2 if parsed_decision_v2 is not None else row["decision_v2_json"],
        parsed_action_envelope if parsed_action_envelope is not None else row["action_envelope_json"],
    )


def _row_to_draft(
    row: sqlite3.Row, canonical_decision: CanonicalApprovalSurfaces
) -> tuple[dict[str, object], str | None]:
    launch_target, browser_target = _browser_launch_target_for_display(row["launch_target"])
    risk_signals = _browser_risk_signals_for_display(_safe_json_list(row["risk_signals_json"]), browser_target)
    payload: dict[str, object] = {
        "request_id": str(row["request_id"]),
        "harness": str(row["harness"]),
        "artifact_id": str(row["artifact_id"]),
        "artifact_name": str(row["artifact_name"]),
        "artifact_type": str(row["artifact_type"]),
        "artifact_hash": str(row["artifact_hash"]),
        "publisher": row["publisher"],
        "policy_action": canonical_decision.policy_action,
        "recommended_scope": str(row["recommended_scope"]),
        "changed_fields": _safe_json_list(row["changed_fields_json"]),
        "source_scope": str(row["source_scope"]),
        "oauth_source": row["oauth_source"],
        "config_path": str(row["config_path"]),
        "workspace": row["workspace"],
        "launch_target": launch_target,
        "normalized_identity_key": row["normalized_identity_key"],
        "action_identity": row["action_identity"],
        "queue_group_id": row["queue_group_id"],
        "dedupe_count": int(row["dedupe_count"] or 1),
        "last_seen_at": row["last_seen_at"],
        "display_status": str(row["status"]),
        "resolution_intent": row["resolution_action"],
        "transport": row["transport"],
        "risk_summary": row["risk_summary"],
        "risk_signals": risk_signals,
        "artifact_label": row["artifact_label"],
        "source_label": row["source_label"],
        "trigger_summary": row["trigger_summary"],
        "why_now": row["why_now"],
        "launch_summary": row["launch_summary"],
        "risk_headline": row["risk_headline"],
        "action_envelope_json": canonical_decision.action_envelope_json,
        "decision_v2_json": canonical_decision.decision_v2_json,
        "fallback_cli_command": row["fallback_cli_command"],
        "raw_command_text": row["raw_command_text"],
        "guard_version": row["guard_version"],
        "first_seen_guard_version": row["first_seen_guard_version"],
        "last_seen_guard_version": row["last_seen_guard_version"],
        "watch_only_observation": bool(row["watch_only_observation"]),
        "scanner_evidence": _json_object_list(row["scanner_evidence_json"]),
        "browser_intent": _json_object(row["browser_intent_json"]),
        "continuation_snapshot": _json_object(row["continuation_snapshot_json"]),
        "review_command": str(row["review_command"]),
        "approval_url": str(row["approval_url"]),
        "status": str(row["status"]),
        "resolution_action": row["resolution_action"],
        "resolution_scope": row["resolution_scope"],
        "reason": row["reason"],
        "created_at": str(row["created_at"]),
        "resolved_at": row["resolved_at"],
    }
    return payload, canonical_decision.contract_error


def _safe_json_list(value: object) -> list[object]:
    if value is None:
        return []
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    return list(parsed) if isinstance(parsed, list) else []


def _json_object(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return dict(parsed) if isinstance(parsed, dict) else None


def _json_object_list(value: object) -> list[dict[str, object]]:
    if value is None:
        return []
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [dict(item) for item in parsed if isinstance(item, dict)]


def _row_to_approval_summary(row: sqlite3.Row, canonical_decision: CanonicalApprovalSurfaces) -> dict[str, object]:
    launch_target, _browser_target = _browser_launch_target_for_display(row["launch_target"])
    action_envelope = canonical_decision.action_envelope_json
    payload: dict[str, object] = {
        "request_id": str(row["request_id"]),
        "harness": str(row["harness"]),
        "artifact_id": str(row["artifact_id"]),
        "artifact_name": str(row["artifact_name"]),
        "artifact_type": str(row["artifact_type"]),
        "policy_action": canonical_decision.policy_action,
        "changed_fields": _safe_json_list(row["changed_fields_json"]),
        "source_scope": str(row["source_scope"]),
        "config_path": str(row["config_path"]),
        "workspace": row["workspace"],
        "launch_target": launch_target,
        "queue_preview": _approval_queue_preview(action_envelope, launch_target),
        "queue_command_category": _approval_queue_command_category(action_envelope),
        "risk_summary": row["risk_summary"],
        "risk_headline": row["risk_headline"],
        "raw_command_text": row["raw_command_text"],
        "fallback_cli_command": row["fallback_cli_command"],
        "review_command": str(row["review_command"]),
        "action_identity": row["action_identity"],
        "queue_group_id": row["queue_group_id"],
        "dedupe_count": int(row["dedupe_count"] or 1),
        "watch_only_observation": bool(row["watch_only_observation"]),
        "created_at": str(row["created_at"]),
        "last_seen_at": row["last_seen_at"],
        "display_status": str(row["status"]),
    }
    if canonical_decision.contract_error is not None:
        payload["decision_contract_error"] = canonical_decision.contract_error
    return payload


def _optional_json_object(value: object) -> dict[str, object] | None:
    # JSON object keys are always strings, so the general parser is exact here.
    return _json_object(value)
