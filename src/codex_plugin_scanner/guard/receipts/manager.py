"""Guard receipt helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from ..models import GuardReceipt


def build_receipt(
    harness: str,
    artifact_id: str,
    artifact_hash: str,
    policy_decision: str,
    changed_capabilities: list[str],
    provenance_summary: str,
    artifact_name: str | None,
    source_scope: str | None,
    user_override: str | None = None,
) -> GuardReceipt:
    """Create a runtime receipt."""

    return GuardReceipt(
        receipt_id=f"guard-receipt-{uuid4()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_decision,  # type: ignore[arg-type]
        changed_capabilities=tuple(changed_capabilities),
        provenance_summary=provenance_summary,
        user_override=user_override,
        artifact_name=artifact_name,
        source_scope=source_scope,
    )
