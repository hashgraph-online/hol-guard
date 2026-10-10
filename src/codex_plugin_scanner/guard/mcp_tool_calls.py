"""Runtime Guard evaluation for MCP tool calls."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .action_lattice import normalize_guard_action
from .approval_gate import ApprovalGateGrant
from .collections_support import dedupe_preserving_order
from .config import GuardConfig
from .mcp_tool_call_evidence import receipt_evidence_for_mcp_tool_call
from .models import GuardAction, GuardArtifact, GuardReceipt, PolicyDecision
from .native_approval_proof import (
    ApprovalReuseClaimDisposition,
)
from .native_context import (
    context_mcp_tool_approval_hash,
    context_opaque_digest,
)
from .native_mcp_runtime_evidence import argument_entries, native_command_text
from .native_mcp_tool_evidence import native_tool_risk_evidence
from .receipts import build_receipt
from .runtime.approval_context import (
    current_extension_control_binding_digest,
)
from .runtime.approval_reuse import (
    APPROVAL_REUSE_NO_SAVED_DECISION,
    ApprovalReuseStatus,
)
from .runtime.composio_contract import composio_requires_action_review
from .runtime.mcp_protection import (
    McpServerIdentity,
    build_mcp_tool_identity,
    mcp_server_identity_metadata,
    mcp_tool_identity_metadata,
)
from .runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall
from .store import GuardStore

_NON_EXECUTED_TOOL_CALL_TAXONOMY: Mapping[GuardAction, tuple[str, str]] = {
    "review": ("runtime_tool_call_review_required", "runtime tool call awaiting review"),
    "require-reapproval": ("runtime_tool_call_reapproval_required", "runtime tool call awaiting fresh approval"),
    "sandbox-required": ("runtime_tool_call_sandbox_required", "runtime tool call requires an enforceable sandbox"),
    "block": ("runtime_tool_call_blocked", "runtime tool call blocked"),
}


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


def extract_mcp_command_text(
    artifact: GuardArtifact,
    arguments: object,
    *,
    guard_home: Path | None = None,
) -> str | None:
    """Return the native-owned display text for an MCP tool call (command or path)."""
    return native_command_text(artifact.name, argument_entries(arguments, mapping_type=Mapping), guard_home=guard_home)


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


def tool_call_risk_signals(artifact: GuardArtifact, arguments: object) -> tuple[str, ...]:
    """Return Rust-owned human-readable risk signals for one MCP tool call."""
    return native_tool_risk_evidence(artifact, arguments)[1]


def tool_call_risk_categories(artifact: GuardArtifact, arguments: object) -> tuple[str, ...]:
    """Return Rust-owned Cloud risk categories for one MCP tool call."""
    return native_tool_risk_evidence(artifact, arguments)[0]


def tool_call_risk_summary(artifact: GuardArtifact, arguments: object) -> str:
    """Return the Rust-owned risk summary for one MCP tool call."""
    return native_tool_risk_evidence(artifact, arguments)[2]


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
    # Display-only evidence; failure degrades it, never the receipt or event.
    raw_command_text, firewall_evidence = receipt_evidence_for_mcp_tool_call(
        artifact, arguments=arguments, risk_categories=risk_categories, guard_home=store.guard_home
    )
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
        scanner_evidence=(firewall_evidence, *additional_scanner_evidence),
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
    raw_command_text, firewall_evidence = receipt_evidence_for_mcp_tool_call(
        artifact, arguments=arguments, risk_categories=risk_categories, guard_home=store.guard_home
    )
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
        scanner_evidence=(firewall_evidence, *additional_scanner_evidence),
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
