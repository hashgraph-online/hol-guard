"""Runtime Guard evaluation for MCP tool calls."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approval_gate import ApprovalGateGrant
from .collections_support import dedupe_preserving_order
from .config import GuardConfig
from .mcp_tool_call_evidence import receipt_evidence_for_mcp_tool_call
from .models import GuardAction, GuardArtifact, GuardReceipt, PolicyDecision
from .native_approval_proof import (
    ApprovalReuseClaimDisposition,
)
from .native_mcp_tool_call_identity import NativeToolCallIdentity, native_tool_call_identity, server_identity_dto
from .receipts import build_receipt
from .runtime.approval_context import (
    current_extension_control_binding_digest,
)
from .runtime.approval_reuse import ApprovalReuseStatus
from .runtime.composio_contract import composio_requires_action_review
from .runtime.mcp_protection import (
    McpServerIdentity,
)
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
    # The action the native runtime enforces for this call. It differs from
    # ``action`` only where a rejected reuse of prior authority opens a fresh
    # approval boundary; Rust owns that derivation.
    policy_action: GuardAction | None = None


def resolve_tool_call_policy_action(decision: ToolCallDecision) -> GuardAction:
    """The action the native runtime enforces for a tool-call decision.

    Rust composes it from the decision and its approval-reuse state; a decision
    that reached Python without one carries no authority and cannot be read.
    """

    if decision.policy_action is None:
        raise ValueError("tool_call_policy_action_missing")
    return decision.policy_action


def _build_dto(
    *,
    harness: str,
    server_name: str,
    tool_name: str,
    source_scope: str,
    config_path: str,
    transport: str,
    server_id: str | None,
    server_fingerprint: object | None,
    server_identity: McpServerIdentity | None,
    tool_schema: object | None,
    tool_description: str | None,
    tool_definition: Mapping[str, object] | None,
    provider_catalog_hash: str | None,
) -> dict[str, object]:
    if tool_definition is None:
        tool: dict[str, object] = {"kind": "explicit", "schema": tool_schema, "description": tool_description}
    else:
        entry = dict(tool_definition)
        if tool_schema is not None:
            entry.pop("input_schema", None)
            entry["inputSchema"] = tool_schema
        if tool_description is not None:
            entry["description"] = tool_description
        tool = {"kind": "catalog", "entry": entry or None}
    return {
        "harness": harness,
        "server_name": server_name,
        "tool_name": tool_name,
        "source_scope": source_scope,
        "config_path": config_path,
        "transport": transport,
        "server_id": server_id,
        "server_fingerprint": server_fingerprint,
        "server_identity": server_identity_dto(server_identity),
        "provider_catalog_hash": provider_catalog_hash,
        "tool": tool,
    }


def _hash_input(
    arguments: object,
    *,
    workspace: Path | str | None,
    config: GuardConfig | None,
) -> dict[str, object]:
    return {
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
        "extension_control_digest": None if config is None else current_extension_control_binding_digest(),
    }


def build_tool_call_identity(
    *,
    arguments: object,
    workspace: Path | str | None,
    config: GuardConfig | None,
    guard_home: Path | None = None,
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
) -> NativeToolCallIdentity:
    """The artifact, its private bindings and approval hash in one resident call."""
    return native_tool_call_identity(
        build=_build_dto(
            harness=harness,
            server_name=server_name,
            tool_name=tool_name,
            source_scope=source_scope,
            config_path=config_path,
            transport=transport,
            server_id=server_id,
            server_fingerprint=server_fingerprint,
            server_identity=server_identity,
            tool_schema=tool_schema,
            tool_description=tool_description,
            tool_definition=tool_definition,
            provider_catalog_hash=provider_catalog_hash,
        ),
        hash_input=_hash_input(arguments, workspace=workspace, config=config),
        guard_home=guard_home,
    )


def build_tool_call_artifact(**facts: Any) -> GuardArtifact:
    """Build the artifact only (native); see :func:`build_tool_call_identity`."""
    unset: dict[str, Any] = dict.fromkeys(
        (
            "server_id",
            "server_fingerprint",
            "server_identity",
            "tool_schema",
            "tool_description",
            "tool_definition",
            "provider_catalog_hash",
        )
    )
    return native_tool_call_identity(build=_build_dto(**{**unset, **facts})).artifact


def build_tool_call_hash(
    artifact: GuardArtifact,
    arguments: object,
    *,
    workspace: Path | str | None = None,
    config: GuardConfig | None = None,
) -> str:
    identity = native_tool_call_identity(
        artifact=artifact, hash_input=_hash_input(arguments, workspace=workspace, config=config)
    )
    if identity.artifact_hash is None:
        raise ValueError("native_mcp_tool_approval_hash_unavailable")
    return identity.artifact_hash


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
    proxy_input: Mapping[str, object] | None = None,
    proxy_out: MutableMapping[str, Any] | None = None,
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
        proxy_input=proxy_input,
        proxy_out=proxy_out,
    )


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
        store.record_tool_call_evidence(
            artifact=artifact,
            artifact_hash=artifact_hash,
            policy_action=policy_action,
            approved=policy_action in {"allow", "warn"},
            receipt=receipt,
            event_name="runtime_tool_call_allowed",
            event_payload={
                "artifact_id": artifact.artifact_id,
                "artifact_hash": artifact_hash,
                "decision_source": decision_source,
                "policy_action": policy_action,
                "risk_categories": list(risk_categories),
                "signals": list(signals),
            },
            now=now,
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
    store.record_tool_call_evidence(
        artifact=artifact,
        artifact_hash=artifact_hash,
        policy_action=policy_action,
        approved=False,
        receipt=receipt,
        event_name=event_name,
        event_payload={
            "artifact_id": artifact.artifact_id,
            "artifact_hash": artifact_hash,
            "decision_source": decision_source,
            "policy_action": policy_action,
            "execution_outcome": "not-executed",
            "risk_categories": list(risk_categories),
            "signals": list(signals),
        },
        now=now,
    )
    return receipt


_dedupe = dedupe_preserving_order
