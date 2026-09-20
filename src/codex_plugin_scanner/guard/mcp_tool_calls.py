"""Runtime Guard evaluation for MCP tool calls."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field, fields, replace
from functools import lru_cache
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path, PurePath
from typing import Literal, cast

from .action_lattice import most_restrictive_guard_action, normalize_guard_action
from .approval_gate import ApprovalGateGrant
from .collections_support import dedupe_preserving_order
from .config import DEFAULT_SECURITY_LEVEL, GuardConfig, resolve_risk_action
from .local_cli_trust import apply_local_mcp_extension_decision
from .mcp_authority_binding import (
    AuthorityCheck,
    check_current_mcp_authority,
    current_mcp_authority_check,
    use_mcp_authority_check,
)
from .mcp_request_risk import (
    InvocationRiskFacts,
    ReviewedRiskHelpers,
    invocation_categories,
    invocation_risk_facts,
)
from .models import GuardAction, GuardArtifact, GuardReceipt, PolicyDecision
from .receipts import build_receipt
from .runtime.approval_context import (
    approval_context_tokens_validation_reason,
    build_approval_context_token,
)
from .runtime.approval_context import (
    saved_allow_context_validation_reason as _tool_call_saved_allow_validation_reason,
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
from .runtime.mcp_protection import (
    McpServerIdentity,
    build_mcp_tool_identity,
    mcp_server_identity_metadata,
    mcp_tool_identity_metadata,
)
from .runtime.mcp_skill_firewall import enrich_artifact_with_mcp_skill_firewall, scanner_evidence_for_mcp_skill_firewall
from .store import GuardStore, browser_mcp_exact_match_context
from .temporary_mcp_approvals import runtime_grant_selectors

_MCP_TOOL_CALL_EVALUATOR_POLICY_VERSION = "mcp-tool-call-evaluation-v3"  # bump with risk/action semantics

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
) -> GuardArtifact:
    metadata: dict[str, object] = {"server_name": server_name}
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
        server_hash = server_id or sha256(f"{harness}:{source_scope}:{server_name}".encode()).hexdigest()
    tool_identity = build_mcp_tool_identity(
        server_hash=server_hash,
        tool_name=tool_name,
        schema=tool_schema,
        description=tool_description,
    )
    metadata["mcp_tool_identity"] = mcp_tool_identity_metadata(tool_identity)
    if tool_schema is not None:
        metadata["tool_schema"] = tool_schema
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


@dataclass(frozen=True, slots=True)
class ToolCallRiskFacts:
    """Ordered pure facts bound to one exact, private request snapshot.

    This value carries no policy or approval authority. Consumers must match
    the complete inputs again and consume their owned matching copy. The
    private binding may contain request secrets, so it must never be exported.
    """

    categories: tuple[str, ...]
    _input_binding: tuple[bytes, tuple[str | int, ...]] = field(repr=False)


def _copy_strict_json(value: object, shape: bytearray, leaves: list[str | int]) -> object:
    """Own containers and bind their exact structure without encoding text.

    The private preorder shape has distinct scalar, key, and container tags.
    Container closing tags preserve nesting and key tags preserve dict order.
    Immutable string/integer leaves can be shared; floats use their exact hex
    spelling so that signed zero cannot compare equal. Neither the eventual
    bytes shape nor its leaf tuple retains a mutable caller-owned container.
    """

    kind = type(value)
    if value is None:
        shape.append(ord("n"))
        return value
    if kind is bool:
        shape.append(ord("t") if value else ord("f"))
        return value
    if kind is str or kind is int:
        shape.append(ord("s") if kind is str else ord("i"))
        leaves.append(cast(str | int, value))
        return value
    if kind is float and math.isfinite(cast(float, value)):
        shape.append(ord("d"))
        leaves.append(cast(float, value).hex())
        return value
    if kind is list:
        shape.append(ord("["))
        owned = [_copy_strict_json(item, shape, leaves) for item in cast(list[object], value)]
        shape.append(ord("]"))
        return owned
    if kind is dict:
        shape.append(ord("{"))
        result: dict[str, object] = {}
        for key, item in cast(dict[object, object], value).items():
            if type(key) is not str:
                raise ValueError("tool_call_facts_require_string_keys")
            shape.append(ord("k"))
            leaves.append(cast(str, key))
            result[cast(str, key)] = _copy_strict_json(item, shape, leaves)
        shape.append(ord("}"))
        return result
    raise ValueError("tool_call_facts_require_plain_finite_json")


def _tool_call_risk_snapshot(
    artifact: GuardArtifact, arguments: object
) -> tuple[tuple[bytes, tuple[str | int, ...]], GuardArtifact, object] | None:
    """Keep unsupported inputs on the existing, uncached analysis path."""

    if type(artifact) is not GuardArtifact or type(artifact.args) is not tuple:
        return None
    if any(type(item) is not str for item in artifact.args):
        return None
    try:
        shape = bytearray()
        leaves: list[str | int] = []
        owned_fields = {
            item.name: _copy_strict_json(getattr(artifact, item.name), shape, leaves)
            for item in fields(artifact)
            if item.name != "args"
        }
        # The exact GuardArtifact field order is fixed above. Its args tuple is
        # already immutable and validated, but still enters the value binding.
        _copy_strict_json(list(artifact.args), shape, leaves)
        owned_arguments = _copy_strict_json(arguments, shape, leaves)
        binding = bytes(shape), tuple(leaves)
        owned_artifact = replace(artifact, **owned_fields)
    except (ValueError, TypeError, RecursionError, RuntimeError):
        return None
    return binding, owned_artifact, owned_arguments


def prepare_tool_call_risk_facts(artifact: GuardArtifact, arguments: object) -> ToolCallRiskFacts | None:
    """Analyze once for a single authority preparation, never across waits."""

    snapshot = _tool_call_risk_snapshot(artifact, arguments)
    if snapshot is None:
        return None
    binding, owned_artifact, owned_arguments = snapshot
    return ToolCallRiskFacts(tool_call_risk_categories(owned_artifact, owned_arguments), binding)


def _matching_tool_call_risk_snapshot(
    artifact: GuardArtifact, arguments: object, facts: ToolCallRiskFacts | None
) -> tuple[GuardArtifact, object] | None:
    if facts is None:
        return None
    snapshot = _tool_call_risk_snapshot(artifact, arguments)
    if snapshot is None or snapshot[0] != facts._input_binding:
        return None
    return snapshot[1], snapshot[2]


def build_tool_call_hash(
    artifact: GuardArtifact,
    arguments: object,
    *,
    workspace: Path | str | None = None,
    config: GuardConfig | None = None,
    risk_facts: ToolCallRiskFacts | InvocationRiskFacts | None = None,
) -> str:
    invocation = cast(InvocationRiskFacts, risk_facts) if type(risk_facts) is InvocationRiskFacts else None
    legacy_facts = None if invocation is not None else cast(ToolCallRiskFacts | None, risk_facts)
    matching_snapshot = _matching_tool_call_risk_snapshot(artifact, arguments, legacy_facts)
    if matching_snapshot is not None:
        artifact, arguments = matching_snapshot
    risk_categories = legacy_facts.categories if matching_snapshot is not None and legacy_facts is not None else None
    if invocation is not None and invocation.supported():
        return _build_tool_call_hash_for_categories(
            artifact,
            arguments,
            workspace=workspace,
            config=config,
            risk_categories=risk_categories,
            invocation_facts=invocation,
        )
    return _build_tool_call_hash_for_categories(
        artifact,
        arguments,
        workspace=workspace,
        config=config,
        risk_categories=risk_categories,
    )


def _build_tool_call_hash_for_categories(
    artifact: GuardArtifact,
    arguments: object,
    *,
    workspace: Path | str | None,
    config: GuardConfig | None,
    risk_categories: tuple[str, ...] | None,
    invocation_facts: InvocationRiskFacts | None = None,
) -> str:
    """Private kernel; the caller owns any supplied facts and their inputs."""

    browser_intent = normalize_browser_mcp_intent(artifact, arguments)
    content_arguments: object = arguments
    if browser_intent is not None:
        content_arguments = {
            "intent": browser_intent.intent,
            "operation": browser_intent.operation,
            "target_origin": browser_intent.target_origin,
            "target_path_prefix": browser_intent.target_path_prefix,
            "method": browser_intent.method,
            "profile_mode": browser_intent.profile_mode,
            "mcp_server_identity_hash": browser_intent.mcp_server_identity_hash,
            "mcp_tool_identity_hash": browser_intent.mcp_tool_identity_hash,
            "mcp_schema_hash": browser_intent.mcp_schema_hash,
            "sensitive_surface_flags": list(browser_intent.sensitive_surface_flags),
        }
        exact_arguments = arguments
        if isinstance(arguments, Mapping):
            exact_arguments = {
                key: value for key, value in arguments.items() if key not in browser_intent.volatile_fields_dropped
            }
        content_arguments["exact_arguments_hash"] = sha256(
            json.dumps(exact_arguments, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if browser_intent.sensitive_surface_flags:
            sensitive_arguments = arguments
            if isinstance(arguments, Mapping):
                sensitive_arguments = {
                    key: value for key, value in arguments.items() if key not in browser_intent.volatile_fields_dropped
                }
            content_arguments["sensitive_arguments_hash"] = sha256(
                json.dumps(sensitive_arguments, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
    legacy_material: dict[str, object] = {
        "artifact_id": artifact.artifact_id,
        "config_path": artifact.config_path,
        "transport": artifact.transport,
        "server_fingerprint": artifact.metadata.get("server_fingerprint"),
        "server_identity": artifact.metadata.get("mcp_server_identity"),
        "tool_identity": artifact.metadata.get("mcp_tool_identity"),
        "arguments": content_arguments,
    }
    # Keep the legacy digest for callers that genuinely have no workspace,
    # while binding every workspace-aware runtime call to its effective cwd.
    # Artifact-scope policy rows intentionally discard their workspace column,
    # so the digest itself must carry this part of the security identity.
    if workspace is not None:
        legacy_material["workspace"] = _normalized_tool_call_workspace(workspace)
    legacy_payload = json.dumps(legacy_material, sort_keys=True)
    legacy_hash = sha256(legacy_payload.encode()).hexdigest()
    if config is None:
        return legacy_hash
    normalized_workspace = _normalized_tool_call_workspace(workspace) if workspace is not None else None
    server_fingerprint = artifact.metadata.get("server_fingerprint")
    resolved_executable = (
        server_fingerprint.get("resolved_executable") if isinstance(server_fingerprint, Mapping) else None
    )
    tool_catalog_fingerprint = (
        server_fingerprint.get("tool_catalog_fingerprint") if isinstance(server_fingerprint, Mapping) else None
    )
    content_hash = sha256(
        json.dumps(
            {
                "arguments": content_arguments,
                "artifact_id": artifact.artifact_id,
                "config_path": artifact.config_path,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return build_approval_context_token(
        identity={
            "artifact_id": artifact.artifact_id,
            "config_path": artifact.config_path,
            "harness": artifact.harness,
            "publisher": artifact.publisher,
            "source_scope": artifact.source_scope,
            "workspace": normalized_workspace,
            "resolved_executable": resolved_executable,
        },
        content=content_hash,
        capabilities={
            "risk_categories": list(
                risk_categories
                if risk_categories is not None
                else _invocation_tool_call_risk_categories(invocation_facts, artifact, arguments, consumer="hash")
            ),
            "server_identity": artifact.metadata.get("mcp_server_identity"),
            "tool_catalog_fingerprint": tool_catalog_fingerprint,
            "tool_identity": artifact.metadata.get("mcp_tool_identity"),
            "transport": artifact.transport,
        },
        policy=_tool_call_policy_context(config, artifact),
        sandbox={"analysis": config.sandbox_analysis},
    )


def _tool_call_policy_context(config: GuardConfig, artifact: GuardArtifact) -> dict[str, object]:
    explicit_risk_action = _configured_risk_action(config, "mcp_dangerous_tool", harness=artifact.harness)
    artifact_override = config.resolve_action_override(
        artifact.harness,
        artifact.artifact_id,
        artifact.publisher,
    )
    check_current_mcp_authority()
    return {
        "artifact_override": artifact_override,
        "default_action": config.default_action,
        "effective_risk_action": explicit_risk_action
        or resolve_risk_action(config, "mcp_dangerous_tool", harness=artifact.harness),
        "evaluator_policy_version": _MCP_TOOL_CALL_EVALUATOR_POLICY_VERSION,
        "managed_locked_settings": list(config.managed_locked_settings),
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "mode": config.mode,
        **(
            {
                "protection_posture": config.protection_posture,
                "protection_posture_explicit": True,
            }
            if config.protection_posture_explicit
            else {}
        ),
        "security_level": config.security_level,
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
    risk_facts: ToolCallRiskFacts | InvocationRiskFacts | None = None,
) -> ToolCallDecision:
    check_current_mcp_authority()
    current = _evaluate_current_tool_call(
        config=config,
        artifact=artifact,
        arguments=arguments,
        risk_facts=risk_facts,
    )
    check_current_mcp_authority()
    return _evaluate_tool_call_with_current(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        current=current,
        claim_saved_approval=claim_saved_approval,
        fresh_authority_provider=fresh_authority_provider,
    )


def _evaluate_tool_call_with_current(
    *,
    store: GuardStore,
    config: GuardConfig,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
    current: ToolCallDecision,
    claim_saved_approval: bool,
    fresh_authority_provider: Callable[[], tuple[GuardConfig, GuardArtifact, str, object] | None] | None = None,
    authority_check: AuthorityCheck | None = None,
) -> ToolCallDecision:
    """Compose a freshly evaluated current result with current saved state."""

    if authority_check is not None:
        with use_mcp_authority_check(authority_check, retain_current=True):
            return _evaluate_tool_call_with_current(
                store=store,
                config=config,
                artifact=artifact,
                artifact_hash=artifact_hash,
                arguments=arguments,
                current=current,
                claim_saved_approval=claim_saved_approval,
                fresh_authority_provider=fresh_authority_provider,
            )

    check_current_mcp_authority()
    current = _apply_temporary_mcp_grant(
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        current=current,
    )
    check_current_mcp_authority()
    runtime_exact_match_context = _browser_runtime_exact_match_context(artifact, arguments)
    check_current_mcp_authority()
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
    check_current_mcp_authority()
    saved_decision = policy_lookup["decision"]
    ignored_integrity = policy_lookup["ignored_local_integrity"]
    check_current_mcp_authority()
    if saved_decision is None and ignored_integrity is None:
        diagnosed_reason = store.approval_reuse_validation_reason(
            artifact.harness,
            artifact.artifact_id,
            artifact_hash,
            str(config.workspace) if config.workspace is not None else None,
            artifact.publisher,
        )
        check_current_mcp_authority()
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
                    _tool_call_saved_allow_validation_reason(
                        saved_decision,
                        artifact_hash=artifact_hash,
                    ),
                )
                if saved_decision is not None
                else None
            )
        )

    check_current_mcp_authority()
    reuse = evaluate_approval_reuse(
        current.action,
        saved_action,
        saved_decision_present=True,
        validation_reason=validation_reason,
    )
    pending_decision: Mapping[str, object] | None = None
    claim_disposition: ApprovalReuseClaimDisposition | None = None
    if reuse.should_claim and saved_decision is not None:
        check_current_mcp_authority()
        raw_claim_disposition = store.approval_reuse_claim_disposition(saved_decision)
        check_current_mcp_authority()
        if raw_claim_disposition in {"consumed", "retained"}:
            claim_disposition = raw_claim_disposition
        if claim_saved_approval:
            check_current_mcp_authority()
            claimed = store.claim_approval_reuse_decision(saved_decision)
            check_current_mcp_authority()
            if not claimed:
                reuse = evaluate_approval_reuse(
                    current.action,
                    saved_action,
                    saved_decision_present=True,
                    validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
                )
            else:
                return _revalidate_claimed_tool_call_approval(
                    store=store,
                    initial_artifact=artifact,
                    initial_artifact_hash=artifact_hash,
                    initial_arguments=arguments,
                    initial_config=config,
                    claimed_decision=saved_decision,
                    claim_disposition=claim_disposition,
                    fresh_authority_provider=fresh_authority_provider,
                )
        else:
            pending_decision = saved_decision
    check_current_mcp_authority()
    return _tool_call_decision_with_reuse(
        current,
        reuse,
        pending_decision=pending_decision,
        claim_disposition=claim_disposition,
    )


def _apply_temporary_mcp_grant(
    *,
    store: GuardStore,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
    current: ToolCallDecision,
) -> ToolCallDecision:
    check_current_mcp_authority()
    original_action = current.action
    if original_action == "review":
        browser_intent = normalize_browser_mcp_intent(artifact, arguments)
        check_current_mcp_authority()
        selectors = runtime_grant_selectors(
            browser_intent,
            current.risk_categories,
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash,
        )
        check_current_mcp_authority()
        for selector in selectors:
            check_current_mcp_authority()
            lookup = store.resolve_policy_decision_lookup(
                artifact.harness,
                selector,
                consume_one_shot=False,
            )
            check_current_mcp_authority()
            decision = lookup["decision"]
            allowed = (
                decision is not None and decision.get("action") == "allow" and decision.get("source") == "approval-gate"
            )
            check_current_mcp_authority()
            if allowed:
                current = replace(
                    current,
                    action="allow",
                    source="temporary-mcp-grant",
                    summary="A time-bounded approval covers this routine MCP capability.",
                )
                break
    granted = apply_local_mcp_extension_decision(store, artifact, original_action)
    check_current_mcp_authority()
    if granted is not None and (granted[0] == "block" or current.action != "allow"):
        return replace(current, action=granted[0], source=granted[1], summary=granted[2])
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
    risk_facts: ToolCallRiskFacts | InvocationRiskFacts | None = None,
) -> ToolCallDecision:
    """Evaluate current configuration and call shape without saved state."""

    configured_override = config.resolve_action_override(
        artifact.harness,
        artifact.artifact_id,
        artifact.publisher,
    )
    check_current_mcp_authority()
    current_config_action = configured_override if configured_override is not None else config.default_action

    # Resolve current policy before the public matching/owned-copy boundary.
    invocation = cast(InvocationRiskFacts, risk_facts) if type(risk_facts) is InvocationRiskFacts else None
    legacy_facts = None if invocation is not None else cast(ToolCallRiskFacts | None, risk_facts)
    matching_snapshot = _matching_tool_call_risk_snapshot(artifact, arguments, legacy_facts)
    if matching_snapshot is not None and legacy_facts is not None:
        artifact, arguments = matching_snapshot
        risk_categories = legacy_facts.categories
    else:
        risk_categories = _invocation_tool_call_risk_categories(invocation, artifact, arguments, consumer="current")
    if invocation is not None and invocation.supported():
        return _evaluate_current_tool_call_for_categories(
            config=config,
            artifact=artifact,
            arguments=arguments,
            current_config_action=current_config_action,
            risk_categories=risk_categories,
            invocation_facts=invocation,
        )
    return _evaluate_current_tool_call_for_categories(
        config=config,
        artifact=artifact,
        arguments=arguments,
        current_config_action=current_config_action,
        risk_categories=risk_categories,
    )


def _evaluate_current_tool_call_for_categories(
    *,
    config: GuardConfig,
    artifact: GuardArtifact,
    arguments: object,
    current_config_action: GuardAction,
    risk_categories: tuple[str, ...],
    invocation_facts: InvocationRiskFacts | None = None,
) -> ToolCallDecision:
    """Private kernel, called only after resolving current policy and inputs."""

    def with_current_config(decision: ToolCallDecision) -> ToolCallDecision:
        effective_action = most_restrictive_guard_action(decision.action, current_config_action)
        if effective_action == decision.action:
            return decision
        return replace(
            decision,
            action=effective_action,
            source="policy",
            summary=("Local Guard's current configuration is stricter than the tool-call-specific recommendation."),
        )

    signals = _tool_call_risk_signals_for_categories(artifact, arguments, risk_categories)
    if type(invocation_facts) is InvocationRiskFacts:
        invocation_facts.record_signals(artifact, arguments, risk_categories, signals)
    explicit_risk_action = _configured_risk_action(config, "mcp_dangerous_tool", harness=artifact.harness)

    if len(signals) == 0:
        return with_current_config(
            ToolCallDecision(
                action="allow",
                source="heuristic",
                signals=(),
                summary="Guard did not detect a high-risk signal in this tool call.",
                risk_categories=(),
            )
        )
    if explicit_risk_action is None and _routine_browser_call_is_safe_by_default(risk_categories):
        return with_current_config(
            ToolCallDecision(
                action="allow",
                source="browser-routine",
                signals=signals,
                summary=_tool_call_summary_for_signals(signals),
                risk_categories=risk_categories,
            )
        )
    configured_risk_action = explicit_risk_action or resolve_risk_action(
        config,
        "mcp_dangerous_tool",
        harness=artifact.harness,
    )
    if configured_risk_action is not None:
        source = "policy"
        if (
            explicit_risk_action is None
            and not config.protection_posture_explicit
            and config.mode == "prompt"
            and config.security_level == DEFAULT_SECURITY_LEVEL
        ):
            configured_risk_action = "review"
            source = "risk-policy"
        return with_current_config(
            ToolCallDecision(
                action=configured_risk_action,
                source=source,
                signals=signals,
                summary=_tool_call_summary_for_signals(signals),
                risk_categories=risk_categories,
            )
        )
    return with_current_config(
        ToolCallDecision(
            action="review" if config.mode == "prompt" else "block",
            source="heuristic",
            signals=signals,
            summary=_tool_call_summary_for_signals(signals),
            risk_categories=risk_categories,
        )
    )


def _routine_browser_call_is_safe_by_default(risk_categories: tuple[str, ...]) -> bool:
    categories = set(risk_categories)
    routine_categories = {"browser_navigation", "browser_inspection"}
    informational_categories = {"browser_external_domain"}
    return bool(categories.intersection(routine_categories)) and categories.issubset(
        routine_categories | informational_categories
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


def _configured_risk_action(config: GuardConfig, risk_class: str, *, harness: str) -> GuardAction | None:
    if config.harness_risk_actions is not None:
        harness_actions = config.harness_risk_actions.get(harness)
        if harness_actions is not None and risk_class in harness_actions:
            return harness_actions[risk_class]
    if config.risk_actions is not None and risk_class in config.risk_actions:
        return config.risk_actions[risk_class]
    return None


def tool_call_risk_signals(artifact: GuardArtifact, arguments: object) -> tuple[str, ...]:
    return _tool_call_risk_signals_for_categories(artifact, arguments, tool_call_risk_categories(artifact, arguments))


def _tool_call_risk_signals_for_categories(
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
    """Return normalized Cloud risk categories for one MCP tool call."""

    categories = _tool_call_risk_category_set(artifact, arguments)
    order = (
        "filesystem_access",
        "command_execution",
        "destructive_mutation",
        "outbound_network",
        "privileged_system_mutation",
        "secret_access",
        "tool_schema_mismatch",
        "browser_navigation",
        "browser_inspection",
        "browser_interaction",
        "browser_transfer",
        "browser_privileged",
        "browser_external_domain",
        "browser_shared_profile",
        "browser_sensitive_surface",
    )
    return tuple(category for category in order if category in categories)


def _tool_call_risk_category_set(artifact: GuardArtifact, arguments: object) -> set[str]:
    tool_name = PurePath(artifact.command or artifact.name).name
    serialized_arguments = _serialized_tool_arguments(arguments)
    combined = _risk_match_text(f"{artifact.name} {serialized_arguments}")
    tool_name_tokens = set(_tool_name_tokens(tool_name))
    categories: set[str] = set()
    argument_categories = _argument_key_risk_categories(arguments)
    schema_categories = _schema_risk_categories(artifact.metadata.get("tool_schema"))
    description_categories = _description_risk_categories(artifact.metadata.get("tool_description"))

    # Extract browser intent early so we can suppress outbound_network for
    # browser navigation targets.
    browser_intent = normalize_browser_mcp_intent(artifact, arguments)
    is_browser_navigation = browser_intent is not None and browser_intent.intent == "browser.navigation"

    if len(tool_name_tokens.intersection({"delete", "remove", "rm", "destroy", "erase"})) > 0:
        categories.add("destructive_mutation")
    if len(
        tool_name_tokens.intersection({"shell", "bash", "exec", "execute", "command", "powershell"})
    ) > 0 or _matches_any(
        combined,
        (
            _literal_pattern(
                "subprocess",
                "child_process",
                "childprocess",
                "popen",
                "os.system",
                "runtime.exec",
                prefix=r"(?<![a-z0-9_])",
                suffix=r"(?![a-z0-9_])",
            ),
            _literal_pattern("spawn", "execfile", "system", prefix=r"(?<![a-z0-9_])", suffix=r"(?:_sync)?\s*\("),
        ),
    ):
        categories.add("command_execution")
    network_patterns = (
        _literal_pattern("http://", "https://"),  # NOSONAR(S5332) Detector literals, without network I/O.
        _token_pattern("curl", "wget", "fetch", "axios", "requests"),
        _literal_pattern("socket", "net", "dns", prefix=r"(?<![a-z0-9_])", suffix=r"\s*[.(]"),
        _literal_pattern(
            "create_connection",
            "getaddrinfo",
            "gethostbyname",
            "sendto",
            "recvfrom",
            prefix=r"(?<![a-z0-9_])",
            suffix=r"\s*\(",
        ),
        _literal_pattern(
            "urllib.request", "urllib", "http.client", "http", "https", prefix=r"(?<![a-z0-9_])", suffix=r"\s*\."
        ),
        _literal_pattern(
            "udp",
            "tcp",
            "socks",
            "proxy",
            "tunnel",
            "port_forward",
            "port-forward",
            prefix=r"(?<![a-z0-9_])",
            suffix=r"(?![a-z0-9_])",
        ),
    )
    if (_matches_any(combined, network_patterns) or _contains_ip_address(combined)) and not is_browser_navigation:
        # Browser navigation intent suppresses generic outbound_network;
        # browser-specific categories below capture the actual risk surface.
        categories.add("outbound_network")
    if _matches_any(
        combined,
        (
            _literal_pattern(".env", prefix=r"(?<![a-z0-9_-])", suffix=r"(?![a-z0-9_-])"),
            _literal_pattern(".ssh", prefix=r"(?<![a-z0-9_-])", suffix=r"(?![a-z0-9_-])"),
            _token_pattern("idrsa", "id_rsa", "id-rsa", "credentials", "token", "secret", "passwd"),
            _literal_pattern(".npmrc", ".pypirc", prefix=r"(?<![a-z0-9_-])", suffix=r"(?![a-z0-9_-])"),
        ),
    ):
        categories.add("secret_access")
    if _matches_any(
        combined,
        (_token_pattern("sudo", "chmod", "chown", "launchctl", "systemctl"),),
    ):
        categories.add("privileged_system_mutation")
    categories.update(argument_categories)
    categories.update(schema_categories)
    categories.update(description_categories)
    if (
        browser_intent is not None
        and "filesystem_access" not in argument_categories
        and "filesystem_access" not in description_categories
    ):
        categories.discard("filesystem_access")
    mismatch_schema_categories = set(schema_categories)
    if browser_intent is not None and browser_intent.intent == "browser.navigation":
        mismatch_schema_categories.discard("outbound_network")
    if _tool_schema_understates_name(tool_name_tokens, mismatch_schema_categories):
        categories.add("tool_schema_mismatch")

    # Browser intent categories (HGBM034-HGBM043)
    if browser_intent is not None:
        if browser_intent.intent == "browser.navigation":
            categories.add("browser_navigation")
            # Suppress outbound_network for browser navigation — argument
            # keys like 'url' would otherwise re-add it.
            categories.discard("outbound_network")
            # External domain = public and not localhost/loopback
            if browser_intent.target_domain and browser_intent.target_domain not in (
                "localhost",
                "127.0.0.1",
                "::1",
            ):
                categories.add("browser_external_domain")
        elif browser_intent.intent == "browser.inspect":
            categories.add("browser_inspection")
        elif browser_intent.intent == "browser.interact":
            categories.add("browser_interaction")
        elif browser_intent.intent == "browser.transfer":
            categories.add("browser_transfer")
        elif browser_intent.intent == "browser.privileged":
            categories.add("browser_privileged")

        if browser_intent.profile_mode in ("shared", "remote-debugging"):
            categories.add("browser_shared_profile")

        if browser_intent.sensitive_surface_flags:
            categories.add("browser_sensitive_surface")

    return categories


def _serialized_tool_arguments(arguments: object) -> str:
    if arguments is None:
        return ""
    try:
        return json.dumps(arguments, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(arguments)


def _contains_ip_address(value: str) -> bool:
    # An IPv4 string contains a dot. IPv6 either compresses with :: or has
    # at least seven colons. Reject only impossible shapes before the exact
    # existing candidate extraction and ip_address validation.
    if "." not in value and "::" not in value and value.count(":") < 7:
        return False
    for match in re.finditer(r"(?<![0-9a-z])\[?([0-9a-f:.]{3,})\]?(?![0-9a-z])", value, flags=re.IGNORECASE):
        candidate = match.group(1)
        if candidate.count(":") == 1 and "." in candidate:
            candidate = candidate.partition(":")[0]
        try:
            ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


@dataclass(frozen=True)
class _LiteralRiskPattern:
    literals: tuple[str, ...]
    expression: str


@lru_cache(maxsize=128)
def _literal_pattern(*tokens: str, prefix: str = "", suffix: str = "") -> _LiteralRiskPattern:
    # Both the fast necessary-condition check and the authoritative regex
    # derive from these same literal alternatives. Adding an alternative
    # cannot leave a separately maintained prefilter behind.
    alternatives = "|".join(re.escape(token) for token in tokens)
    return _LiteralRiskPattern(tokens or ("",), rf"{prefix}({alternatives}){suffix}")


def _matches_any(value: str, patterns: tuple[str | _LiteralRiskPattern, ...]) -> bool:
    for pattern in patterns:
        if isinstance(pattern, _LiteralRiskPattern):
            if not any(token in value for token in pattern.literals):
                continue
            expression = pattern.expression
        else:
            expression = pattern
        if re.search(expression, value) is not None:
            return True
    return False


def _token_pattern(*tokens: str) -> _LiteralRiskPattern:
    return _literal_pattern(*tokens, prefix=r"(?<![a-z0-9])", suffix=r"(?![a-z0-9])")


def _argument_key_risk_categories(arguments: object) -> set[str]:
    if not isinstance(arguments, Mapping):
        return set()
    categories: set[str] = set()
    keys = _argument_key_names(arguments)
    if keys.intersection(
        {
            "file",
            "filepath",
            "filepaths",
            "files",
            "path",
            "paths",
            "source",
            "sourcepath",
            "sourcepaths",
            "sources",
            "target",
            "targetpath",
            "targetpaths",
            "targets",
        }
    ):
        categories.add("filesystem_access")
    if keys.intersection({"command", "cmd", "script", "shell"}):
        categories.add("command_execution")
    if keys.intersection({"callback", "endpoint", "uri", "url", "urls", "webhook"}):
        categories.add("outbound_network")
    return categories


def _argument_key_names(value: object) -> set[str]:
    names: set[str] = set()
    pending: list[object] = [value]
    visited_ids: set[int] = set()
    while pending:
        current = pending.pop()
        if isinstance(current, Mapping):
            current_id = id(current)
            if current_id in visited_ids:
                continue
            visited_ids.add(current_id)
            for key, item in current.items():
                names.add(_normalized_argument_key(str(key)))
                pending.append(item)
        elif isinstance(current, list | tuple):
            current_id = id(current)
            if current_id in visited_ids:
                continue
            visited_ids.add(current_id)
            pending.extend(current)
    return names


def _schema_risk_categories(schema: object) -> set[str]:
    keys = _schema_property_key_names(schema)
    categories: set[str] = set()
    if keys.intersection(
        {
            "file",
            "filepath",
            "filepaths",
            "files",
            "path",
            "paths",
            "source",
            "sourcepath",
            "sourcepaths",
            "sources",
            "target",
            "targetpath",
            "targetpaths",
            "targets",
        }
    ):
        categories.add("filesystem_access")
    if keys.intersection({"command", "cmd", "script", "shell"}):
        categories.add("command_execution")
    if keys.intersection({"callback", "endpoint", "uri", "url", "urls", "webhook"}):
        categories.add("outbound_network")
    return categories


def _schema_property_key_names(
    value: object,
    *,
    _root_schema: Mapping[str, object] | None = None,
    _visited_refs: set[str] | None = None,
    _visited_ids: set[int] | None = None,
) -> set[str]:
    names: set[str] = set()
    if isinstance(value, Mapping):
        root_schema = value if _root_schema is None else _root_schema
        visited_refs = set() if _visited_refs is None else _visited_refs
        visited_ids = set() if _visited_ids is None else _visited_ids
        val_id = id(value)
        if val_id in visited_ids:
            return names
        visited_ids.add(val_id)
        ref_value = value.get("$ref")
        if isinstance(ref_value, str) and ref_value not in visited_refs:
            visited_refs.add(ref_value)
            resolved = _resolve_local_schema_ref(root_schema, ref_value)
            if resolved is not None:
                names.update(
                    _schema_property_key_names(
                        resolved,
                        _root_schema=root_schema,
                        _visited_refs=visited_refs,
                        _visited_ids=visited_ids,
                    )
                )
        properties = value.get("properties")
        if isinstance(properties, Mapping):
            for key, item in properties.items():
                names.add(_normalized_argument_key(str(key)))
                names.update(
                    _schema_property_key_names(
                        item,
                        _root_schema=root_schema,
                        _visited_refs=visited_refs,
                        _visited_ids=visited_ids,
                    )
                )
        for collection_key in (
            "additionalProperties",
            "allOf",
            "anyOf",
            "contains",
            "else",
            "if",
            "items",
            "oneOf",
            "prefixItems",
            "propertyNames",
            "then",
            "unevaluatedItems",
            "unevaluatedProperties",
        ):
            child = value.get(collection_key)
            names.update(
                _schema_property_key_names(
                    child,
                    _root_schema=root_schema,
                    _visited_refs=visited_refs,
                    _visited_ids=visited_ids,
                )
            )
        dependent_schemas = value.get("dependentSchemas")
        if isinstance(dependent_schemas, Mapping):
            for child in dependent_schemas.values():
                names.update(
                    _schema_property_key_names(
                        child,
                        _root_schema=root_schema,
                        _visited_refs=visited_refs,
                        _visited_ids=visited_ids,
                    )
                )
        pattern_properties = value.get("patternProperties")
        if isinstance(pattern_properties, Mapping):
            for child in pattern_properties.values():
                names.update(
                    _schema_property_key_names(
                        child,
                        _root_schema=root_schema,
                        _visited_refs=visited_refs,
                        _visited_ids=visited_ids,
                    )
                )
        return names
    if isinstance(value, list | tuple):
        root_schema = _root_schema
        visited_refs = set() if _visited_refs is None else _visited_refs
        visited_ids = set() if _visited_ids is None else _visited_ids
        for item in value:
            names.update(
                _schema_property_key_names(
                    item,
                    _root_schema=root_schema,
                    _visited_refs=visited_refs,
                    _visited_ids=visited_ids,
                )
            )
    return names


def _resolve_local_schema_ref(root_schema: Mapping[str, object], reference: str) -> object | None:
    if reference.startswith("#/"):
        current: object = root_schema
        for part in reference[2:].split("/"):
            token = part.replace("~1", "/").replace("~0", "~")
            if isinstance(current, Mapping):
                if token not in current:
                    return None
                current = current[token]
            elif isinstance(current, list | tuple):
                if not token.isdigit():
                    return None
                index = int(token)
                if index >= len(current):
                    return None
                current = current[index]
            else:
                return None
        return current
    if not reference.startswith("#"):
        return None
    anchor_name = reference[1:]
    if not anchor_name:
        return root_schema
    return _resolve_local_schema_anchor(root_schema, anchor_name)


def _resolve_local_schema_anchor(root_schema: object, anchor_name: str) -> object | None:
    pending: list[object] = [root_schema]
    visited_ids: set[int] = set()
    while pending:
        current = pending.pop()
        current_id = id(current)
        if current_id in visited_ids:
            continue
        visited_ids.add(current_id)
        if not isinstance(current, Mapping):
            if isinstance(current, list | tuple):
                pending.extend(item for item in current if isinstance(item, (Mapping, list, tuple)))
            continue
        anchor = current.get("$anchor")
        dynamic_anchor = current.get("$dynamicAnchor")
        if anchor == anchor_name or dynamic_anchor == anchor_name:
            return current
        pending.extend(item for item in current.values() if isinstance(item, (Mapping, list, tuple)))
    return None


def _description_risk_categories(description: object) -> set[str]:
    if not isinstance(description, str):
        return set()
    normalized = _risk_match_text(description)
    categories: set[str] = set()
    if _matches_any(normalized, (r"\bread files?\b", r"\bopen files?\b", r"\bview files?\b")):
        categories.add("filesystem_access")
    if _matches_any(normalized, (_token_pattern("delete", "remove", "write"),)):
        categories.add("destructive_mutation")
    if _matches_any(normalized, (r"\brun command", _token_pattern("execute", "shell"))):
        categories.add("command_execution")
    return categories


def _tool_schema_understates_name(tool_name_tokens: set[str], schema_categories: set[str]) -> bool:
    dangerous_categories = {"command_execution", "destructive_mutation", "outbound_network"}
    if len(schema_categories.intersection(dangerous_categories)) == 0:
        return False
    name_sounds_dangerous = (
        len(
            tool_name_tokens.intersection(
                {
                    "bash",
                    "cmd",
                    "command",
                    "delete",
                    "destroy",
                    "exec",
                    "execute",
                    "patch",
                    "remove",
                    "rm",
                    "run",
                    "script",
                    "shell",
                    "write",
                }
            )
        )
        > 0
    )
    return not name_sounds_dangerous


def _normalized_argument_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _risk_match_text(value))


def tool_call_risk_summary(artifact: GuardArtifact, arguments: object) -> str:
    return _tool_call_summary_for_signals(tool_call_risk_signals(artifact, arguments))


def _tool_call_summary_for_signals(signals: tuple[str, ...]) -> str:
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


def _tool_name_tokens(tool_name: str) -> tuple[str, ...]:
    camel_normalized = _camel_token_normalized(tool_name)
    return tuple(token for token in re.findall(r"[a-z0-9]+", camel_normalized.lower()) if token)


def _risk_match_text(value: str) -> str:
    return _camel_token_normalized(value).lower()


def _camel_token_normalized(value: str) -> str:
    if value.islower():
        return value
    return re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)


def _invocation_tool_call_risk_categories(
    facts: InvocationRiskFacts | None,
    artifact: GuardArtifact,
    arguments: object,
    *,
    consumer: str,
) -> tuple[str, ...]:
    shared = invocation_categories(facts, artifact, arguments, consumer=consumer, derive=tool_call_risk_categories)
    return shared if shared is not None else tool_call_risk_categories(artifact, arguments)


# Capture source-default implementations at import, never during a callback.
_RISK_PAIR_HELPERS = ReviewedRiskHelpers(
    namespace=globals(),
    pure_roots=("tool_call_risk_categories", "_tool_call_risk_signals_for_categories"),
    consumers=(
        "build_tool_call_hash",
        "evaluate_tool_call",
        "_build_tool_call_hash_for_categories",
        "_evaluate_current_tool_call",
        "_evaluate_current_tool_call_for_categories",
        "_matching_tool_call_risk_snapshot",
        "_invocation_tool_call_risk_categories",
        "_tool_call_policy_context",
        "tool_call_risk_summary",
        "tool_call_risk_signals",
        "_tool_call_summary_for_signals",
        "_configured_risk_action",
        "resolve_risk_action",
    ),
    policy_type=GuardConfig,
    policy_methods=("resolve_action_override", "resolve_artifact_or_publisher_action_override"),
)


def _tool_call_risk_pair(
    *,
    artifact: GuardArtifact,
    arguments: object,
    config: GuardConfig,
    aliases: Mapping[str, object],
    admitted: bool,
) -> AbstractContextManager[InvocationRiskFacts | None]:
    return invocation_risk_facts(
        artifact=artifact,
        arguments=arguments,
        authority_check=current_mcp_authority_check(),
        support_check=lambda: type(config) is GuardConfig and _RISK_PAIR_HELPERS.unchanged(config, aliases),
        admitted=admitted,
    )
