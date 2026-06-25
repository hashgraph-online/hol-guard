"""Guard receipt helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import TypeGuard
from uuid import uuid4

from ..models import GUARD_ACTION_VALUES, GuardAction, GuardReceipt
from ..runtime.actions import GuardActionEnvelope


def _redacted_envelope_dict(
    envelope: GuardActionEnvelope,
    *,
    redaction_level: str = "full",
) -> dict[str, object]:
    """Return a cloud-safe redacted view of the action envelope.

    ``redaction_level`` controls how much command detail is included:
    - ``full`` (default): command text never leaves the daemon (counts/booleans only)
    - ``partial``: command text included (already secret-scrubbed via redact_text at source)
    - ``none``: command text, target paths, network hosts, package name included
    """
    base: dict[str, object] = {
        "schema_version": envelope.schema_version,
        "action_id": envelope.action_id,
        "harness": envelope.harness,
        "event_name": envelope.event_name,
        "action_type": envelope.action_type,
        "workspace_hash": envelope.workspace_hash,
        "tool_name": envelope.tool_name,
        "command_length": len(envelope.command) if envelope.command is not None else 0,
        "target_paths_count": len(envelope.target_paths),
        "network_hosts_count": len(envelope.network_hosts),
        "mcp_server": envelope.mcp_server,
        "mcp_tool": envelope.mcp_tool,
        "package_manager": envelope.package_manager,
        "has_package_name": envelope.package_name is not None and len(envelope.package_name) > 0,
        "package_intent_kind": envelope.package_intent_kind,
        "package_targets_count": len(envelope.package_targets),
        "pre_execution_result": envelope.pre_execution_result,
        "script_name": envelope.script_name,
    }

    if redaction_level == "none":
        if envelope.command is not None:
            base["command"] = envelope.command
        if envelope.target_paths:
            base["target_paths"] = list(envelope.target_paths)
        if envelope.network_hosts:
            base["network_hosts"] = list(envelope.network_hosts)
        if envelope.package_name is not None and len(envelope.package_name) > 0:
            base["package_name"] = envelope.package_name
    elif redaction_level == "partial":
        if envelope.command is not None:
            base["command"] = envelope.command

    return base


def _auto_diff_summary(changed_capabilities: list[str]) -> str:
    """Generate a prose diff summary from the changed capabilities list."""
    count = len(changed_capabilities)
    sample = ", ".join(changed_capabilities[:3])
    suffix = " ..." if count > 3 else ""
    return f"{count} change(s): {sample}{suffix}"


def _is_guard_action(value: str) -> TypeGuard[GuardAction]:
    return value in GUARD_ACTION_VALUES


def _resolve_policy_decision(value: str) -> GuardAction:
    return value if _is_guard_action(value) else "require-reapproval"


def build_receipt(
    harness: str,
    artifact_id: str,
    artifact_hash: str,
    policy_decision: str,
    capabilities_summary: str,
    changed_capabilities: list[str],
    provenance_summary: str,
    artifact_name: str | None,
    source_scope: str | None,
    user_override: str | None = None,
    scanner_evidence: Sequence[Mapping[str, object]] = (),
    diff_summary: str | None = None,
    approval_source: str | None = None,
    approval_request_id: str | None = None,
) -> GuardReceipt:
    """Create a runtime receipt."""

    resolved_diff_summary = diff_summary
    if resolved_diff_summary is None and changed_capabilities:
        resolved_diff_summary = _auto_diff_summary(changed_capabilities)
    resolved_policy_decision = _resolve_policy_decision(policy_decision)

    return GuardReceipt(
        receipt_id=f"guard-receipt-{uuid4()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=resolved_policy_decision,
        capabilities_summary=capabilities_summary,
        changed_capabilities=tuple(changed_capabilities),
        provenance_summary=provenance_summary,
        user_override=user_override,
        artifact_name=artifact_name,
        source_scope=source_scope,
        diff_summary=resolved_diff_summary,
        approval_source=approval_source,
        approval_request_id=approval_request_id,
        scanner_evidence=tuple(dict(item) for item in scanner_evidence),
    )
