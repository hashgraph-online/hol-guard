"""Guard receipt helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from uuid import uuid4

from ..models import GuardReceipt


def _auto_diff_summary(changed_capabilities: list[str]) -> str:
    """Generate a prose diff summary from the changed capabilities list."""
    count = len(changed_capabilities)
    sample = ", ".join(changed_capabilities[:3])
    suffix = " ..." if count > 3 else ""
    return f"{count} change(s): {sample}{suffix}"


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
) -> GuardReceipt:
    """Create a runtime receipt."""

    resolved_diff_summary = diff_summary
    if resolved_diff_summary is None and changed_capabilities:
        resolved_diff_summary = _auto_diff_summary(changed_capabilities)

    return GuardReceipt(
        receipt_id=f"guard-receipt-{uuid4()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_decision,  # type: ignore[arg-type]
        capabilities_summary=capabilities_summary,
        changed_capabilities=tuple(changed_capabilities),
        provenance_summary=provenance_summary,
        user_override=user_override,
        artifact_name=artifact_name,
        source_scope=source_scope,
        diff_summary=resolved_diff_summary,
        approval_source=approval_source,
        scanner_evidence=tuple(dict(item) for item in scanner_evidence),
    )
