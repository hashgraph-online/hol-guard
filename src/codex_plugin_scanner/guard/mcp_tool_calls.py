"""Runtime Guard evaluation for MCP tool calls."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, cast

from .action_lattice import most_restrictive_guard_action, normalize_guard_action
from .approval_gate import ApprovalGateGrant
from .collections_support import dedupe_preserving_order
from .config import GuardConfig
from .local_cli_trust import apply_local_mcp_extension_decision
from .mcp_fresh_approval import fresh_local_tool_approval_matches, fresh_lookup_preserves_claim
from .models import GuardAction, GuardArtifact, GuardReceipt, PolicyDecision
from .native_context import (
    context_mcp_tool_approval_hash,
    context_mcp_tool_policy,
    context_mcp_tool_risk,
    context_opaque_digest,
)
from .receipts import build_receipt
from .runtime.approval_context import (
    approval_context_tokens_validation_reason,
    current_extension_control_binding_digest,
)
from .runtime.approval_context import (
    saved_allow_context_validation_reason as _tool_call_saved_allow_validation_reason,  # noqa: F401 - evaluation compatibility
)
from .runtime.approval_reuse import (
    APPROVAL_REUSE_ACCEPTED,
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
    APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN,
    APPROVAL_REUSE_NO_SAVED_DECISION,
    APPROVAL_REUSE_SAVED_ACTION_UNKNOWN,
    ApprovalReuseDecision,
    ApprovalReuseStatus,
    ApprovalReuseValidationFailure,
    evaluate_approval_reuse,
)
from .runtime.browser_mcp_intent import browser_intent_display_target, normalize_browser_mcp_intent
from .runtime.composio_contract import composio_requires_action_review
from .runtime.mcp_protection import (
    McpServerIdentity,
    build_mcp_tool_identity,
    mcp_server_identity_metadata,
    mcp_tool_identity_metadata,
)
from .runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall, scanner_evidence_for_mcp_skill_firewall
from .store import GuardStore, browser_mcp_exact_match_context
from .temporary_mcp_approvals import runtime_grant_selectors

_NON_EXECUTED_TOOL_CALL_TAXONOMY: Mapping[GuardAction, tuple[str, str]] = {
    "review": ("runtime_tool_call_review_required", "runtime tool call awaiting review"),
    "require-reapproval": ("runtime_tool_call_reapproval_required", "runtime tool call awaiting fresh approval"),
    "sandbox-required": ("runtime_tool_call_sandbox_required", "runtime tool call requires an enforceable sandbox"),
    "block": ("runtime_tool_call_blocked", "runtime tool call blocked"),
}

ApprovalReuseClaimDisposition = Literal["consumed", "retained"]

_APPROVAL_REUSE_DECISION_IDENTITY_KEYS = (
    "action",
    "approval_id",
    "artifact_hash",
    "artifact_id",
    "decision_id",
    "expires_at",
    "harness",
    "integrity_enforcement",
    "integrity_generation",
    "integrity_key_id",
    "integrity_mode",
    "integrity_status",
    "integrity_version",
    "owner",
    "publisher",
    "reason",
    "request_id",
    "scope",
    "signed_at",
    "source",
    "updated_at",
    "workspace",
)


def approval_reuse_decisions_match(
    expected: Mapping[str, object] | None,
    current: Mapping[str, object] | None,
) -> bool:
    """Return whether two lookups selected the same saved authority row."""

    if expected is None or current is None:
        return False
    expected_approval_id = expected.get("approval_id")
    current_approval_id = current.get("approval_id")
    expected_decision_id = expected.get("decision_id")
    current_decision_id = current.get("decision_id")
    same_identifier = (
        isinstance(expected_approval_id, str)
        and bool(expected_approval_id)
        and current_approval_id == expected_approval_id
    ) or (
        isinstance(expected_decision_id, int)
        and not isinstance(expected_decision_id, bool)
        and current_decision_id == expected_decision_id
    )
    return same_identifier and all(
        expected.get(key) == current.get(key) for key in _APPROVAL_REUSE_DECISION_IDENTITY_KEYS
    )


def claimed_approval_authorizes_postclaim_review(
    *,
    claim_disposition: ApprovalReuseClaimDisposition | None,
    claimed_decision: Mapping[str, object] | None,
    current_decision: Mapping[str, object] | None,
) -> bool:
    """Validate the saved proof used to lower a fresh review after claiming."""

    if claim_disposition == "consumed":
        return True
    return claim_disposition == "retained" and approval_reuse_decisions_match(
        claimed_decision,
        current_decision,
    )


@dataclass(frozen=True, slots=True)
class ToolCallAuthority:
    """Fresh execution identity selected at the post-claim boundary."""

    config: GuardConfig
    artifact: GuardArtifact
    artifact_hash: str
    arguments: object


@dataclass(frozen=True, slots=True)
class ToolCallDecision:
    """Decision for one MCP tool call."""

    action: GuardAction
    source: str
    signals: tuple[str, ...]
    summary: str
    risk_categories: tuple[str, ...] = ()
    normalization_reason_code: str | None = None
    original_action: str | None = None
    approval_reuse_status: ApprovalReuseStatus | None = None
    approval_reuse_reason_code: str | None = None
    current_action: GuardAction | None = None
    saved_action: GuardAction | None = None
    pending_approval_reuse_decision: Mapping[str, object] | None = None
    approval_reuse_claim_disposition: ApprovalReuseClaimDisposition | None = None
    post_claim_revalidated: bool = False
    post_claim_authority: ToolCallAuthority | None = None


def resolve_tool_call_policy_action(
    decision: ToolCallDecision,
    *,
    action: object | None = None,
) -> GuardAction:
    """Resolve the exact action enforced for a tool-call decision.

    A first-time review remains ``review``.  A rejected attempt to reuse prior
    authority is a genuine fresh-approval boundary and is therefore surfaced as
    ``require-reapproval`` instead of silently making every review look stale.
    """

    normalized = normalize_guard_action(decision.action if action is None else action)
    stale_prior_authority = (
        decision.approval_reuse_status == "rejected"
        and decision.approval_reuse_reason_code not in {None, APPROVAL_REUSE_NO_SAVED_DECISION}
    )
    if normalized == "review" and stale_prior_authority:
        return "require-reapproval"
    return normalized


_MCP_COMMAND_ARGUMENT_KEYS: tuple[str, ...] = (
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "script",
    "expression",
    "code",
    "query",
)

_MCP_PATH_ARGUMENT_KEYS: tuple[str, ...] = (
    "path",
    "file_path",
    "filePath",
    "filepath",
    "directory",
    "dir",
    "cwd",
    "working_dir",
    "workingDir",
    "url",
    "uri",
)


def extract_mcp_command_text(
    artifact: GuardArtifact,
    arguments: object,
) -> str | None:
    """Extract a human-readable command string from MCP tool call arguments.

    For tools like ctx_shell/bash the primary argument is a ``command`` string.
    For file/path tools we surface the path. For other tools we return None so
    the UI falls back to the artifact name.
    """
    if not isinstance(arguments, Mapping):
        return None

    tool_name = artifact.name
    for key in _MCP_COMMAND_ARGUMENT_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for key in _MCP_PATH_ARGUMENT_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return f"{tool_name} {value.strip()}"

    return None


def build_tool_call_artifact(
    *,
    harness: str,
    server_name: str,
    tool_name: str,
    source_scope: str,
    config_path: str,
    transport: str,
    server_id: str | None = None,
    server_fingerprint: object | None = None,
    server_identity: McpServerIdentity | None = None,
    tool_schema: object | None = None,
    tool_description: str | None = None,
    tool_definition: Mapping[str, object] | None = None,
    provider_catalog_hash: str | None = None,
) -> GuardArtifact:
    metadata: dict[str, object] = {"server_name": server_name}
    if provider_catalog_hash is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", provider_catalog_hash):
            raise ValueError("invalid provider catalog authority hash")
        metadata["mcp_provider_catalog_hash"] = provider_catalog_hash
    if server_id is not None:
        metadata["server_id"] = server_id
    if server_fingerprint is not None:
        metadata["server_fingerprint"] = server_fingerprint
    if server_identity is not None:
        metadata["mcp_server_identity"] = mcp_server_identity_metadata(server_identity)
    if server_id is not None:
        server_hash = server_id
    elif server_identity is not None:
        server_hash = server_identity.identity_hash
    else:
        server_hash = server_id or context_opaque_digest(
            f"{harness}:{source_scope}:{server_name}",
            unbound_label="mcp-server",
            strict=False,  # identity hash; stored rows share this producer
        )
    tool_identity = build_mcp_tool_identity(
        server_hash=server_hash,
        tool_name=tool_name,
        schema=tool_schema,
        description=tool_description,
    )
    metadata["mcp_tool_identity"] = mcp_tool_identity_metadata(tool_identity)
    if tool_schema is not None:
        metadata["tool_schema"] = tool_schema
    if tool_definition is not None:
        from .store_mcp_catalog import tool_definition_authority_hash

        metadata["mcp_tool_authority_hash"] = (
            tool_definition_authority_hash(dict(tool_definition)) if tool_definition.get("name") == tool_name else None
        )
    if isinstance(tool_description, str) and tool_description.strip():
        metadata["tool_description"] = tool_description.strip()
    return enrich_artifact_with_mcp_skill_firewall(
        GuardArtifact(
            artifact_id=f"{harness}:runtime:{source_scope}:{server_name}:{tool_name}",
            name=f"{server_name}:{tool_name}",
            harness=harness,
            artifact_type="tool_call",
            source_scope=source_scope,
            config_path=config_path,
            command=tool_name,
            transport=transport,
            metadata=metadata,
        )
    )


def build_tool_call_hash(
    artifact: GuardArtifact,
    arguments: object,
    *,
    workspace: Path | str | None = None,
    config: GuardConfig | None = None,
) -> str:
    request: dict[str, object] = {
        "artifact": {
            "name": artifact.name,
            "command": artifact.command,
            "metadata": dict(artifact.metadata),
        },
        "artifact_id": artifact.artifact_id,
        "config_path": artifact.config_path,
        "harness": artifact.harness,
        "publisher": artifact.publisher,
        "source_scope": artifact.source_scope,
        "transport": artifact.transport,
        "arguments": arguments,
        "config": None
        if config is None
        else {
            **_tool_call_configuration(config),
            "managed_policy_hash": config.managed_policy_hash,
            "managed_policy_status": config.managed_policy_status,
            "sandbox_analysis": config.sandbox_analysis,
        },
        "workspace": _normalized_tool_call_workspace(workspace) if workspace is not None else None,
    }
    if config is not None:
        request["extension_control_digest"] = current_extension_control_binding_digest()
    token_or_digest, _risk_categories = context_mcp_tool_approval_hash(request, expect_token=config is not None)
    return token_or_digest


def _tool_call_configuration(config: GuardConfig) -> dict[str, object]:
    """Raw configuration DTO; policy resolution and versioning are native."""
    return {
        field: getattr(config, field)
        for field in (
            "mode",
            "default_action",
            "artifact_actions",
            "publisher_actions",
            "harness_actions",
            "risk_actions",
            "harness_risk_actions",
            "security_level",
            "protection_posture",
            "protection_posture_explicit",
            "managed_locked_settings",
        )
    }


def _normalized_tool_call_workspace(workspace: Path | str) -> str:
    candidate = Path(workspace).expanduser()
    try:
        return str(candidate.resolve(strict=False))
    except (OSError, RuntimeError):
        return str(candidate.absolute())


def _browser_runtime_exact_match_context(artifact: GuardArtifact, arguments: object) -> str | None:
    browser_intent = normalize_browser_mcp_intent(artifact, arguments)
    if browser_intent is None:
        return None
    return browser_mcp_exact_match_context(
        intent=browser_intent.intent,
        operation=browser_intent.operation,
        target_origin=browser_intent.target_origin,
        target_path_prefix=browser_intent.target_path_prefix,
        profile_mode=browser_intent.profile_mode,
        mcp_server_identity_hash=browser_intent.mcp_server_identity_hash,
        mcp_tool_identity_hash=browser_intent.mcp_tool_identity_hash,
        mcp_schema_hash=browser_intent.mcp_schema_hash,
        sensitive_surface_flags=browser_intent.sensitive_surface_flags,
    )


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
    from .mcp_tool_call_evaluation import evaluate_tool_call as evaluate

    return evaluate(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        claim_saved_approval=claim_saved_approval,
        fresh_authority_provider=fresh_authority_provider,
    )


def _apply_temporary_mcp_grant(
    *,
    store: GuardStore,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
    current: ToolCallDecision,
) -> ToolCallDecision:
    original_action = current.action
    from .runtime.mcp_provider_permissions import composio_provider_action_floor

    provider_floor = (
        composio_provider_action_floor(
            store.read_mcp_provider_choices(),
            harness=artifact.harness,
            tool_name=artifact.command or "",
            arguments=arguments,
        )
        if composio_requires_action_review(artifact.command or "")
        else None
    )
    if provider_floor is not None and provider_floor.action == "block":
        return replace(
            current,
            action="block",
            source="composio-action-deny",
            summary="A denied app action blocks this execution. No batch member may run.",
        )
    # A decisive extension choice fixes the action. Temporary grants only add
    # Allow, so probing them cannot change that choice.
    granted = apply_local_mcp_extension_decision(store, artifact, original_action)
    if granted is not None and (granted[0] in {"block", "review"} or current.action != "allow"):
        return replace(current, action=granted[0], source=granted[1], summary=granted[2])
    if original_action == "review":
        selectors = runtime_grant_selectors(
            normalize_browser_mcp_intent(artifact, arguments),
            current.risk_categories,
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash,
        )
        for selector in selectors:
            lookup = store.resolve_policy_decision_lookup(
                artifact.harness,
                selector,
                consume_one_shot=False,
            )
            decision = lookup["decision"]
            if decision is not None and decision.get("action") == "allow" and decision.get("source") == "approval-gate":
                current = replace(
                    current,
                    action="allow",
                    source="temporary-mcp-grant",
                    summary="A time-bounded approval covers this routine MCP capability.",
                )
                break
    if composio_requires_action_review(artifact.command or ""):
        return replace(
            current,
            action=most_restrictive_guard_action(current.action, "review"),
            source="composio-action-review",
            summary="Review the underlying actions and account. A wrapper grant does not authorize execution.",
        )
    return current


def _revalidate_claimed_tool_call_approval(
    *,
    store: GuardStore,
    initial_artifact: GuardArtifact,
    initial_artifact_hash: str,
    initial_arguments: object,
    initial_config: GuardConfig,
    claimed_decision: Mapping[str, object],
    claim_disposition: ApprovalReuseClaimDisposition | None,
    fresh_authority_provider: (Callable[[], tuple[GuardConfig, GuardArtifact, str, object] | None] | None),
) -> ToolCallDecision:
    """Rebuild MCP authority after claiming an exact saved allow.

    The claim closes the one-shot race, but it does not freeze configuration,
    tool identity, arguments, or a concurrently inserted saved block.  Re-read
    all of those inputs before returning an executable allow.
    """

    from .native_context import bind_context_digest_home

    bind_context_digest_home(getattr(store, "guard_home", None))
    refresh_failed = False
    if fresh_authority_provider is None:
        fresh_config = initial_config
        fresh_artifact = initial_artifact
        fresh_arguments = initial_arguments
        fresh_artifact_hash = build_tool_call_hash(
            fresh_artifact,
            fresh_arguments,
            workspace=fresh_config.workspace or Path.cwd(),
            config=fresh_config,
        )
    else:
        try:
            provided = fresh_authority_provider()
        except Exception:
            provided = None
        if provided is None:
            refresh_failed = True
            fresh_config = initial_config
            fresh_artifact = initial_artifact
            fresh_arguments = initial_arguments
            fresh_artifact_hash = initial_artifact_hash
        else:
            fresh_config, fresh_artifact, fresh_artifact_hash, fresh_arguments = provided

    fresh_current = _evaluate_current_tool_call(
        config=fresh_config,
        artifact=fresh_artifact,
        arguments=fresh_arguments,
    )
    fresh_decision = evaluate_tool_call(
        store=store,
        config=fresh_config,
        artifact=fresh_artifact,
        artifact_hash=fresh_artifact_hash,
        arguments=fresh_arguments,
        claim_saved_approval=False,
    )
    validation_reason: ApprovalReuseValidationFailure | None
    if refresh_failed or fresh_artifact.artifact_id != initial_artifact.artifact_id:
        validation_reason = APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM
    else:
        context_changed = approval_context_tokens_validation_reason(
            initial_artifact_hash,
            fresh_artifact_hash,
        )
        validation_reason = APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM if context_changed is not None else None
    if fresh_decision.approval_reuse_reason_code == "approval_reuse_integrity_failure":
        validation_reason = "approval_reuse_integrity_failure"
    elif fresh_decision.approval_reuse_status == "rejected" and not fresh_lookup_preserves_claim(
        fresh_decision.approval_reuse_reason_code
    ):
        validation_reason = APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM

    # A fresh unclaimed allow is not launch authority. Reuse the freshly
    # computed current action, while preserving a newly observed saved block or
    # another terminal result from the second lookup.
    post_claim_current_action = fresh_decision.action
    if fresh_decision.saved_action == "allow" and fresh_decision.approval_reuse_reason_code == APPROVAL_REUSE_ACCEPTED:
        post_claim_current_action = fresh_current.action
    if post_claim_current_action == "review" and not claimed_approval_authorizes_postclaim_review(
        claim_disposition=claim_disposition,
        claimed_decision=claimed_decision,
        current_decision=fresh_decision.pending_approval_reuse_decision,
    ):
        validation_reason = APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM
    if validation_reason is not None:
        post_claim_current_action = most_restrictive_guard_action(
            post_claim_current_action,
            "require-reapproval",
        )
    post_claim_current = replace(
        fresh_current,
        action=post_claim_current_action,
        summary=(
            "Current tool-call authority changed after the saved approval was claimed."
            if validation_reason is not None
            else fresh_current.summary
        ),
    )
    reuse = evaluate_approval_reuse(
        post_claim_current.action,
        "allow",
        saved_decision_present=True,
        validation_reason=validation_reason,
        fresh_local_approval=(
            claim_disposition == "consumed"
            and fresh_local_tool_approval_matches(
                claimed_decision, artifact=fresh_artifact, artifact_hash=fresh_artifact_hash
            )
        ),
    )
    return replace(
        _tool_call_decision_with_reuse(post_claim_current, reuse),
        approval_reuse_claim_disposition=claim_disposition,
        post_claim_revalidated=True,
        post_claim_authority=ToolCallAuthority(
            config=fresh_config,
            artifact=fresh_artifact,
            artifact_hash=fresh_artifact_hash,
            arguments=fresh_arguments,
        ),
    )


def claim_deferred_tool_call_approval(
    *,
    store: GuardStore,
    decision: ToolCallDecision,
) -> ToolCallDecision:
    """Atomically claim a provisionally accepted approval at the launch gate."""

    pending = decision.pending_approval_reuse_decision
    if pending is None:
        return decision
    if store.claim_approval_reuse_decision(pending):
        # This helper has no fresh artifact/config provider. A successful claim
        # is atomic evidence, but it is not sufficient launch authority until
        # retained-row presence and every current input are revalidated.
        failed_action = most_restrictive_guard_action(
            decision.current_action or "block",
            "require-reapproval",
        )
        current = ToolCallDecision(
            action=failed_action,
            source="risk-policy",
            signals=decision.signals,
            summary="Current tool call requires reapproval because post-claim authority was unavailable.",
            risk_categories=decision.risk_categories,
        )
        reuse = evaluate_approval_reuse(
            current.action,
            decision.saved_action,
            saved_decision_present=True,
            validation_reason=APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
        )
        return replace(
            _tool_call_decision_with_reuse(current, reuse),
            approval_reuse_claim_disposition=decision.approval_reuse_claim_disposition,
            post_claim_revalidated=True,
        )
    current = ToolCallDecision(
        action=decision.current_action or "block",
        source="risk-policy",
        signals=decision.signals,
        summary="Current tool call still requires review because its saved approval could not be claimed.",
        risk_categories=decision.risk_categories,
    )
    reuse = evaluate_approval_reuse(
        current.action,
        decision.saved_action,
        saved_decision_present=True,
        validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
    )
    return _tool_call_decision_with_reuse(current, reuse)


def _evaluate_current_tool_call(
    *,
    config: GuardConfig,
    artifact: GuardArtifact,
    arguments: object,
) -> ToolCallDecision:
    """Present the native recommendation; saved approval authority is separate."""
    policy = context_mcp_tool_policy(
        {
            "artifact": {"name": artifact.name, "command": artifact.command, "metadata": dict(artifact.metadata)},
            "arguments": arguments,
            "harness": artifact.harness,
            "artifact_id": artifact.artifact_id,
            "publisher": artifact.publisher,
            "config": _tool_call_configuration(config),
        }
    )
    categories = tuple(policy["risk_categories"])
    signals = _risk_signals_from_categories(artifact, arguments, categories)
    summary = {
        "no_risk": "Guard did not detect a high-risk signal in this tool call.",
        "configuration_stricter": (
            "Local Guard's current configuration is stricter than the tool-call-specific recommendation."
        ),
        "risk": _risk_summary_from_signals(signals),
    }[policy["summary_code"]]
    return ToolCallDecision(
        action=cast(GuardAction, policy["action"]),
        source=policy["source"],
        signals=signals,
        summary=summary,
        risk_categories=categories,
    )


def _tool_call_decision_with_reuse(
    current: ToolCallDecision,
    reuse: ApprovalReuseDecision,
    *,
    pending_decision: Mapping[str, object] | None = None,
    claim_disposition: ApprovalReuseClaimDisposition | None = None,
) -> ToolCallDecision:
    normalization_reason_code = reuse.saved_normalization_reason_code or reuse.current_normalization_reason_code
    original_action = reuse.original_saved_action or reuse.original_current_action
    if reuse.reason_code == APPROVAL_REUSE_SAVED_ACTION_UNKNOWN:
        source = "policy-invalid"
        summary = "Local Guard found an unknown policy action in saved state and requires reapproval."
    elif reuse.reason_code == APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN:
        source = "policy-invalid"
        summary = "Local Guard found an unknown current policy action and blocked the tool call."
    elif reuse.reason_code == APPROVAL_REUSE_ACCEPTED:
        source = "policy"
        summary = "Local Guard reused an exact saved approval for the current reviewable tool call."
    elif reuse.reason_code == APPROVAL_REUSE_NO_SAVED_DECISION:
        source = current.source
        summary = current.summary
    elif reuse.saved_action == "block":
        source = "policy"
        summary = "Local Guard kept this tool call blocked by saved policy."
    else:
        source = current.source
        summary = f"{current.summary} Saved approval was not reused ({reuse.reason_code})."
    return ToolCallDecision(
        action=reuse.action,
        source=source,
        signals=current.signals,
        summary=summary,
        risk_categories=current.risk_categories,
        normalization_reason_code=normalization_reason_code,
        original_action=original_action,
        approval_reuse_status=reuse.status,
        approval_reuse_reason_code=reuse.reason_code,
        current_action=reuse.current_action,
        saved_action=reuse.saved_action,
        pending_approval_reuse_decision=pending_decision,
        approval_reuse_claim_disposition=claim_disposition,
    )


def tool_call_risk_signals(artifact: GuardArtifact, arguments: object) -> tuple[str, ...]:
    return _risk_signals_from_categories(artifact, arguments, tool_call_risk_categories(artifact, arguments))


def _risk_signals_from_categories(
    artifact: GuardArtifact,
    arguments: object,
    categories: tuple[str, ...],
) -> tuple[str, ...]:
    browser_intent = normalize_browser_mcp_intent(artifact, arguments)
    signals_by_category: dict[str, str] = {
        "filesystem_access": "call shape implies filesystem path access",
        "destructive_mutation": "tool name implies destructive file or system changes",
        "command_execution": "tool name implies shell or command execution",
        "outbound_network": "call arguments imply outbound network activity",
        "secret_access": "call arguments mention sensitive local files or secrets",
        "privileged_system_mutation": "call arguments imply privileged system mutation",
        "tool_schema_mismatch": "tool name understates dangerous schema capabilities",
    }
    if browser_intent is not None:
        target = browser_intent_display_target(browser_intent, arguments)
        signals_by_category.update(
            {
                "browser_navigation": f"browser navigation to {target}",
                "browser_inspection": f"browser inspection of {target}",
                "browser_interaction": f"browser interaction on {target}",
                "browser_transfer": f"browser file transfer involving {target}",
                "browser_privileged": f"privileged browser access to {target}",
                "browser_external_domain": f"first navigation to external domain {target}",
                "browser_shared_profile": "browser MCP uses a shared or remote-debugging profile",
                "browser_sensitive_surface": (
                    "browser action touches sensitive surfaces: " + ", ".join(browser_intent.sensitive_surface_flags)
                ),
            }
        )
    return tuple(signals_by_category[category] for category in categories)


def tool_call_risk_categories(artifact: GuardArtifact, arguments: object) -> tuple[str, ...]:
    """Return Rust-owned Cloud risk categories for one MCP tool call."""
    return context_mcp_tool_risk(
        {"name": artifact.name, "command": artifact.command, "metadata": dict(artifact.metadata)},
        arguments,
    )


def tool_call_risk_summary(artifact: GuardArtifact, arguments: object) -> str:
    return _risk_summary_from_signals(tool_call_risk_signals(artifact, arguments))


def _risk_summary_from_signals(signals: tuple[str, ...]) -> str:
    if len(signals) == 0:
        return "No high-risk signal was detected in this tool call."
    if len(signals) == 1:
        return signals[0].capitalize() + "."
    return f"{signals[0].capitalize()}, and it also {', and it also '.join(signals[1:])}."


_INLINE_SOURCES = frozenset({"inline-approved", "inline-denied", "native-approved", "claude-native-approved"})
_POLICY_SOURCES = frozenset(
    {
        "heuristic",
        "policy",
        "auto",
        "pre-tool-hook",
        "permission-request-hook",
        "policy-allow",
        "policy-block",
        "policy_allow",
        "policy_block",
        "heuristic-allow",
        "heuristic-block",
        "heuristic_allow",
        "heuristic_block",
        "auto-allow",
        "auto-block",
    }
)


def _map_approval_source(decision_source: str) -> str:
    if decision_source in _INLINE_SOURCES:
        return "inline"
    if decision_source in _POLICY_SOURCES or decision_source.startswith("policy"):
        return "policy"
    return "approval_center"


def allow_tool_call(
    *,
    store: GuardStore,
    artifact: GuardArtifact,
    artifact_hash: str,
    decision_source: str,
    now: str,
    signals: tuple[str, ...],
    remember: bool,
    risk_categories: tuple[str, ...] = (),
    approval_gate_grant: ApprovalGateGrant | None = None,
    arguments: object = None,
    policy_workspace: str | None = None,
    additional_scanner_evidence: tuple[dict[str, object], ...] = (),
    policy_action: GuardAction = "allow",
    emit_runtime_evidence: bool = True,
) -> GuardReceipt:
    if remember:
        if composio_requires_action_review(artifact.command or ""):
            raise ValueError("verified_account_required_for_remembered_provider_action")
        store.upsert_policy(
            PolicyDecision(
                harness=artifact.harness,
                scope="artifact",
                action="allow",
                artifact_id=artifact.artifact_id,
                artifact_hash=artifact_hash,
                workspace=policy_workspace,
                reason=f"Approved via Guard runtime ({decision_source})",
                source="runtime-inline",
            ),
            now,
            approval_gate_grant=approval_gate_grant,
        )
    if emit_runtime_evidence:
        store.record_inventory_artifact(
            artifact=artifact,
            artifact_hash=artifact_hash,
            policy_action=policy_action,
            changed=False,
            now=now,
            approved=policy_action in {"allow", "warn"},
        )
    raw_command_text = extract_mcp_command_text(artifact, arguments)
    receipt = build_receipt(
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_action,
        capabilities_summary=f"mcp tool call • {artifact.name}",
        changed_capabilities=["runtime_tool_call", decision_source, *signals],
        provenance_summary=f"runtime tool call allowed from {artifact.config_path}",
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
        user_override="inline-approve" if decision_source == "inline-approved" else None,
        approval_source=_map_approval_source(decision_source),
        scanner_evidence=(
            scanner_evidence_for_mcp_skill_firewall(
                artifact,
                risk_categories=risk_categories,
            ),
            *additional_scanner_evidence,
        ),
        raw_command_text=raw_command_text,
    )
    if emit_runtime_evidence:
        store.add_receipt(receipt)
        store.add_event(
            "runtime_tool_call_allowed",
            {
                "artifact_id": artifact.artifact_id,
                "artifact_hash": artifact_hash,
                "decision_source": decision_source,
                "policy_action": policy_action,
                "risk_categories": list(risk_categories),
                "signals": list(signals),
            },
            now,
        )
    return receipt


def block_tool_call(
    *,
    store: GuardStore,
    artifact: GuardArtifact,
    artifact_hash: str,
    decision_source: str,
    now: str,
    signals: tuple[str, ...],
    risk_categories: tuple[str, ...] = (),
    arguments: object = None,
    additional_scanner_evidence: tuple[dict[str, object], ...] = (),
    policy_action: GuardAction = "block",
) -> GuardReceipt:
    try:
        event_name, provenance_action = _NON_EXECUTED_TOOL_CALL_TAXONOMY[policy_action]
    except KeyError as exc:
        raise ValueError(f"block_tool_call cannot record executing action {policy_action!r}.") from exc
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash=artifact_hash,
        policy_action=policy_action,
        changed=False,
        now=now,
        approved=False,
    )
    raw_command_text = extract_mcp_command_text(artifact, arguments)
    receipt = build_receipt(
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_action,
        capabilities_summary=f"mcp tool call • {artifact.name}",
        changed_capabilities=["runtime_tool_call", decision_source, *signals],
        provenance_summary=f"{provenance_action} from {artifact.config_path}",
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
        user_override="inline-deny" if decision_source == "inline-denied" else None,
        approval_source=_map_approval_source(decision_source),
        scanner_evidence=(
            scanner_evidence_for_mcp_skill_firewall(
                artifact,
                risk_categories=risk_categories,
            ),
            *additional_scanner_evidence,
        ),
        raw_command_text=raw_command_text,
    )
    store.add_receipt(receipt)
    store.add_event(
        event_name,
        {
            "artifact_id": artifact.artifact_id,
            "artifact_hash": artifact_hash,
            "decision_source": decision_source,
            "policy_action": policy_action,
            "execution_outcome": "not-executed",
            "risk_categories": list(risk_categories),
            "signals": list(signals),
        },
        now,
    )
    return receipt


_dedupe = dedupe_preserving_order
