"""Operation-scoped MCP evaluation with the existing approval authority."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, cast

from .runtime.approval_reuse import ApprovalReuseValidationFailure

if TYPE_CHECKING:
    from .config import GuardConfig
    from .mcp_tool_calls import ApprovalReuseClaimDisposition, ToolCallDecision
    from .models import GuardArtifact
    from .store import GuardStore


@dataclass(frozen=True)
class _ClaimedToolApproval:
    decision: Mapping[str, object]
    disposition: ApprovalReuseClaimDisposition | None


def evaluate_tool_call(
    *,
    store: GuardStore,
    config: GuardConfig,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
    claim_saved_approval: bool = True,
    fresh_authority_provider: (Callable[[], tuple[GuardConfig, GuardArtifact, str, object] | None] | None) = None,
) -> ToolCallDecision:
    with store.connection_scope():
        result = _evaluate_tool_call(
            store=store,
            config=config,
            artifact=artifact,
            artifact_hash=artifact_hash,
            arguments=arguments,
            claim_saved_approval=claim_saved_approval,
        )
    if not isinstance(result, _ClaimedToolApproval):
        return result
    from . import mcp_tool_calls as calls

    # The claim is already committed. Refresh authority without a storage lease,
    # then re-read policy in a new scope before deciding whether it still allows.
    return calls._revalidate_claimed_tool_call_approval(
        store=store,
        initial_artifact=artifact,
        initial_artifact_hash=artifact_hash,
        initial_arguments=arguments,
        initial_config=config,
        claimed_decision=result.decision,
        claim_disposition=result.disposition,
        fresh_authority_provider=fresh_authority_provider,
    )


def _evaluate_tool_call(
    *,
    store: GuardStore,
    config: GuardConfig,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
    claim_saved_approval: bool = True,
) -> ToolCallDecision | _ClaimedToolApproval:
    from . import mcp_tool_calls as calls

    current = calls._evaluate_current_tool_call(
        config=config,
        artifact=artifact,
        arguments=arguments,
    )
    current = calls._apply_temporary_mcp_grant(
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        current=current,
    )
    if (
        calls.composio_requires_action_review(artifact.command or "")
        and current.action != "block"
        and store.read_mcp_provider_authority_hash() != artifact.metadata.get("mcp_provider_catalog_hash")
    ):
        return replace(
            current,
            action=calls.most_restrictive_guard_action(current.action, "require-reapproval"),
            source="composio-schema-reapproval",
            summary="The app action inventory changed. Rebuild this call and review it again.",
        )
    runtime_exact_match_context = calls._browser_runtime_exact_match_context(artifact, arguments)
    policy_lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        artifact.harness,
        artifact.artifact_id,
        artifact_hash=artifact_hash,
        workspace=str(config.workspace) if config.workspace is not None else None,
        publisher=artifact.publisher,
        runtime_exact_match_context=runtime_exact_match_context,
        memory_command=artifact.command,
        memory_artifact_type=artifact.artifact_type,
        memory_artifact_name=artifact.name,
        consume_one_shot=False,
    )
    saved_decision = policy_lookup["decision"]
    ignored_integrity = policy_lookup["ignored_local_integrity"]
    if saved_decision is None and ignored_integrity is None:
        diagnosed_reason = store.approval_reuse_validation_reason(
            artifact.harness,
            artifact.artifact_id,
            artifact_hash,
            str(config.workspace) if config.workspace is not None else None,
            artifact.publisher,
        )
        if diagnosed_reason is None:
            return current
        saved_action: object | None = "allow"
        validation_reason: ApprovalReuseValidationFailure | None = cast(
            ApprovalReuseValidationFailure,
            diagnosed_reason,
        )
    else:
        saved_action = (
            saved_decision.get("action")
            if saved_decision is not None
            else ("require-reapproval" if ignored_integrity is not None else None)
        )
        validation_reason = (
            "approval_reuse_integrity_failure"
            if ignored_integrity is not None
            else (
                cast(
                    ApprovalReuseValidationFailure,
                    calls._tool_call_saved_allow_validation_reason(
                        saved_decision,
                        artifact_hash=artifact_hash,
                    ),
                )
                if saved_decision is not None
                else None
            )
        )

    if (
        validation_reason is None
        and saved_decision is not None
        and saved_action == "allow"
        and calls.composio_requires_action_review(artifact.command or "")
        and store.approval_reuse_claim_disposition(saved_decision) != "consumed"
    ):
        # No supported account resolver exists for this profile. A retained
        # wrapper approval could silently follow a changed default account.
        # Fresh single-use review remains available; durable reuse does not.
        validation_reason = "approval_reuse_provider_account_unverified"
    reuse = calls.evaluate_approval_reuse(
        current.action,
        saved_action,
        saved_decision_present=True,
        validation_reason=validation_reason,
        fresh_local_approval=(
            validation_reason is None
            and saved_decision is not None
            and store.approval_reuse_claim_disposition(saved_decision) == "consumed"
            and calls.fresh_local_tool_approval_matches(saved_decision, artifact=artifact, artifact_hash=artifact_hash)
        ),
    )
    pending_decision: Mapping[str, object] | None = None
    claim_disposition: ApprovalReuseClaimDisposition | None = None
    if reuse.should_claim and saved_decision is not None:
        raw_claim_disposition = store.approval_reuse_claim_disposition(saved_decision)
        if raw_claim_disposition in {"consumed", "retained"}:
            claim_disposition = raw_claim_disposition
        if claim_saved_approval:
            if not store.claim_approval_reuse_decision(saved_decision):
                reuse = calls.evaluate_approval_reuse(
                    current.action,
                    saved_action,
                    saved_decision_present=True,
                    validation_reason=calls.APPROVAL_REUSE_CLAIM_FAILED,
                )
            else:
                return _ClaimedToolApproval(saved_decision, claim_disposition)
        else:
            pending_decision = saved_decision
    return calls._tool_call_decision_with_reuse(
        current,
        reuse,
        pending_decision=pending_decision,
        claim_disposition=claim_disposition,
    )
