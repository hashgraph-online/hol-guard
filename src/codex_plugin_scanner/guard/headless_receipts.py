"""Receipts for actions the dashboard runs through the local daemon.

Supply-chain package protection and headless app actions record one receipt
per completed action. The material the artifact hash covers, the receipt
fields and the summary the reply carries are fixed here so every route that
records one writes the same shape.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .receipts.manager import build_receipt
from .stable_digest import stable_digest_hex
from .store import GuardStore


def _text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def cursor_receipt_context(
    *,
    harness: str,
    operation: str,
    payload: Mapping[str, object],
    result: Mapping[str, object],
    cloud_sync: Mapping[str, object] | None,
) -> dict[str, Any] | None:
    """What a Cursor action's receipt names in place of the generic fields."""

    if harness != "cursor":
        return None
    action_payload = result.get("cursor_action")
    action_dict = action_payload if isinstance(action_payload, dict) else {}
    surface = (
        _text(action_dict.get("surface")) or _text(payload.get("surface")) or _text(payload.get("editor_or_cli"))
    ) or "editor"
    action = _text(action_dict.get("action")) or operation
    evidence = action_dict.get("evidence")
    evidence_dict = evidence if isinstance(evidence, dict) else {}
    action_scope = _text(evidence_dict.get("actionScope")) or f"cursor:{surface}:{action}"
    cloud_sync_status = "pending"
    if isinstance(cloud_sync, Mapping):
        cloud_sync_status = _text(cloud_sync.get("status")) or cloud_sync_status
    surface_label = "CLI" if surface == "cli" else "editor"
    return {
        "action_scope": action_scope,
        "artifact_name": f"Cursor {surface_label} {action}",
        "capabilities_summary": f"Guard local daemon completed Cursor {surface_label} {action}.",
        "changed_capability": f"{surface}:{action}",
        "scanner_evidence": {
            "action_scope": action_scope,
            "cloud_sync_status": cloud_sync_status,
            "cursor_status": _text(action_dict.get("status")) or "unknown",
            "editor_or_cli": surface,
            "error_reason": _text(payload.get("error_reason")),
        },
        "source_scope": f"cursor:{surface}",
        "summary": {
            "action_scope": action_scope,
            "cloud_sync": dict(cloud_sync) if isinstance(cloud_sync, Mapping) else {"status": cloud_sync_status},
            "editor_or_cli": surface,
        },
    }


def record_headless_receipt(
    store: GuardStore,
    *,
    harness: str,
    operation: str,
    payload: Mapping[str, object],
    result: Mapping[str, object],
    workspace_id: str | None,
    location_id: str | None = None,
    cloud_sync: Mapping[str, object] | None = None,
    policy_decision: str | None = None,
    capabilities_summary: str | None = None,
    artifact_name: str | None = None,
    scanner_evidence_extra: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Stores the action's receipt and returns the summary the reply carries."""

    cursor = cursor_receipt_context(
        harness=harness, operation=operation, payload=payload, result=result, cloud_sync=cloud_sync
    )
    material = json.dumps(
        {
            "harness": harness,
            "location_id": location_id,
            "operation": operation,
            "result_keys": sorted(result.keys()),
            "cursor": cursor,
            "workspace_id": workspace_id,
        },
        sort_keys=True,
    )
    artifact_id = f"headless:{harness}:{operation}"
    resolved_artifact_name = artifact_name or f"Headless {operation}"
    resolved_capabilities_summary = capabilities_summary or f"Guard local daemon completed headless {operation}."
    source_scope = "local-daemon"
    changed_capabilities = [] if operation in {"status", "scan"} else [operation]
    scanner_evidence: dict[str, object] = {
        "operation": operation,
        "location_id": location_id,
        "workspace_id": workspace_id,
        "status": "completed",
    }
    if scanner_evidence_extra is not None:
        scanner_evidence.update(scanner_evidence_extra)
    if cursor is not None:
        artifact_id = str(cursor["action_scope"])
        resolved_artifact_name = str(cursor["artifact_name"])
        resolved_capabilities_summary = str(cursor["capabilities_summary"])
        source_scope = str(cursor["source_scope"])
        changed_capabilities = [str(cursor["changed_capability"])]
        scanner_evidence.update(cursor["scanner_evidence"])
    receipt = build_receipt(
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=stable_digest_hex(material.encode("utf-8")),
        policy_decision=policy_decision or "allow",
        capabilities_summary=resolved_capabilities_summary,
        changed_capabilities=changed_capabilities,
        provenance_summary="Guard Cloud local daemon API",
        artifact_name=resolved_artifact_name,
        source_scope=source_scope,
        scanner_evidence=(scanner_evidence,),
        approval_source="guard-cloud-headless",
    )
    store.add_receipt(receipt)
    summary: dict[str, object] = {
        "id": receipt.receipt_id,
        "operation": operation,
        "status": "completed",
        "timestamp": receipt.timestamp,
    }
    if cursor is not None:
        summary.update(cursor["summary"])
    return summary
