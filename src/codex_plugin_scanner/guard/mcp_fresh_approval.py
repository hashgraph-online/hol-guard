"""Exact fresh MCP approval proof shared by evaluation and launch gates."""

from __future__ import annotations

from collections.abc import Mapping

from .models import GuardArtifact
from .runtime.approval_reuse import APPROVAL_REUSE_NO_SAVED_DECISION, APPROVAL_REUSE_REAPPROVAL_REQUIRED


def fresh_local_tool_approval_matches(
    decision: Mapping[str, object] | None,
    *,
    artifact: GuardArtifact,
    artifact_hash: str,
) -> bool:
    """Shape-check exact proof only after validated lookup or atomic claim.

    This is not integrity validation or launch authority by itself. Retained
    policy rules cannot satisfy a fresh-approval requirement.
    """
    return (
        decision is not None
        and (
            (
                decision.get("source") == "approval-gate-once"
                and isinstance(decision.get("approval_id"), str)
                and bool(decision.get("approval_id"))
            )
            or (
                decision.get("source") == "approval-gate"
                and isinstance(decision.get("decision_id"), int)
                and not isinstance(decision.get("decision_id"), bool)
            )
        )
        and decision.get("action") == "allow"
        and decision.get("scope") == "artifact"
        and decision.get("harness") == artifact.harness
        and decision.get("artifact_id") == artifact.artifact_id
        and decision.get("artifact_hash") == artifact_hash
        and isinstance(decision.get("expires_at"), str)
    )


def fresh_lookup_preserves_claim(reason_code: str | None) -> bool:
    """Consumption may expose no grant or an older allow requiring reapproval.

    Neither grants new authority. The caller must independently validate the
    consumed exact proof, unchanged context, and current deny/launch gates.
    Integrity and changed-context lookup failures are never tolerated.
    """
    return reason_code in {None, APPROVAL_REUSE_NO_SAVED_DECISION, APPROVAL_REUSE_REAPPROVAL_REQUIRED}


def fresh_claim_allows_reapproval(
    *,
    claim_disposition: str | None,
    reason_code: str | None,
    decision: Mapping[str, object] | None,
    artifact: GuardArtifact,
    artifact_hash: str,
) -> bool:
    return (
        claim_disposition == "consumed"
        and fresh_lookup_preserves_claim(reason_code)
        and fresh_local_tool_approval_matches(decision, artifact=artifact, artifact_hash=artifact_hash)
    )
