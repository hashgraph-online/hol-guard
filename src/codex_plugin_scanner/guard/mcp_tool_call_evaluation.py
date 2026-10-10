"""Operation-scoped MCP evaluation; the native resident owns the decision.

Rust composes current floors, provider/account review, temporary choices,
saved reuse, claim disposition, and fresh post-claim authority. This adapter
only runs the effects Rust names (see ``native_mcp_tool_policy``) and presents
the answer as a ``ToolCallDecision``. It never recomputes or overrides it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .native_mcp_tool_policy import FreshAuthorityProvider, native_evaluate_tool_call

if TYPE_CHECKING:
    from .config import GuardConfig
    from .mcp_tool_calls import ToolCallDecision
    from .models import GuardArtifact
    from .store import GuardStore


def evaluate_tool_call(
    *,
    store: GuardStore,
    config: GuardConfig,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
    claim_saved_approval: bool = True,
    fresh_authority_provider: FreshAuthorityProvider | None = None,
) -> ToolCallDecision:
    from .mcp_tool_calls import ToolCallAuthority, ToolCallDecision

    result = native_evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        claim_saved_approval=claim_saved_approval,
        fresh_authority_provider=fresh_authority_provider,
    )
    payload = result.payload
    authority = None
    if result.authority is not None and payload["post_claim_authority"] == "fresh":
        fresh_config, fresh_artifact, fresh_hash, fresh_arguments = result.authority
        authority = ToolCallAuthority(
            config=fresh_config,
            artifact=fresh_artifact,
            artifact_hash=fresh_hash,
            arguments=fresh_arguments,
        )
    return ToolCallDecision(
        action=payload["action"],
        source=payload["source"],
        signals=tuple(payload["signals"]),
        summary=payload["summary"],
        risk_categories=tuple(payload["risk_categories"]),
        normalization_reason_code=payload["normalization_reason_code"],
        original_action=payload["original_action"],
        approval_reuse_status=payload["approval_reuse_status"],
        approval_reuse_reason_code=payload["approval_reuse_reason_code"],
        current_action=payload["current_action"],
        saved_action=payload["saved_action"],
        pending_approval_reuse_decision=payload["pending_approval_reuse_decision"],
        approval_reuse_claim_disposition=payload["approval_reuse_claim_disposition"],
        post_claim_revalidated=payload["post_claim_revalidated"],
        post_claim_authority=authority,
    )
