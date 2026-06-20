from __future__ import annotations

from datetime import datetime, timezone

from .review_contracts import GuardReviewOAuthMetadata

_DECISION_MEMORY_ACK_CONTRACT_VERSION = "guard.decision-memory-ack.v1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_decision_memory_ack(
    *,
    bundle: dict[str, object],
    oauth: GuardReviewOAuthMetadata,
    status: str,
    applied_rule_count: int,
    reason: str | None = None,
    rejected_rule_ids: list[str] | None = None,
) -> dict[str, object]:
    return {
        "acknowledgedAt": _now().isoformat(),
        "appliedRuleCount": max(0, applied_rule_count),
        "bundleHash": bundle.get("bundleHash"),
        "bundleVersion": bundle.get("bundleVersion"),
        "contractVersion": _DECISION_MEMORY_ACK_CONTRACT_VERSION,
        "deviceId": oauth.device_id,
        "machineId": oauth.machine_id,
        "machineInstallationId": oauth.installation_id,
        "policyVersion": bundle.get("policyVersion"),
        "reason": reason,
        "rejectedRuleIds": rejected_rule_ids or [],
        "status": status,
        "workspaceId": oauth.workspace_id,
    }
