"""Guard consumer-facing orchestration."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict, TypeGuard, cast

from ...models import ScanOptions
from ..action_lattice import is_guard_action as _is_guard_action
from ..action_lattice import most_restrictive_guard_action
from ..adapters.base import HarnessContext
from ..approval_gate import ApprovalGateGrant
from ..capabilities import compute_capability_delta, normalize_artifact_capabilities, severity_from_deltas
from ..config import GuardConfig
from ..incident import build_incident_context
from ..models import (
    DECISION_SCOPE_VALUES,
    DecisionScope,
    GuardAction,
    GuardArtifact,
    HarnessDetection,
    PolicyDecision,
)
from ..policy import decide_action
from ..receipts import build_receipt
from ..risk import artifact_risk_signals_typed, artifact_risk_summary, summarize_signals
from ..runtime.approval_context import (
    approval_context_tokens_validation_reason,
    build_approval_context_token,
    build_runtime_launch_identity,
)
from ..runtime.approval_reuse import (
    APPROVAL_REUSE_ACCEPTED,
    APPROVAL_REUSE_NO_SAVED_DECISION,
    ApprovalReuseDecision,
    ApprovalReuseValidationFailure,
    evaluate_approval_reuse,
)
from ..runtime.decisions import build_authoritative_decision, evaluation_authority_error
from ..runtime.signals import RiskSignalV2
from ..schemas import build_consumer_mode_contract
from ..skill_directory_identity import validated_complete_skill_directory_hash
from ..store import GuardStore
from ..types import (
    CapabilityDelta,
    EvidenceSource,
    GuardSignal,
    GuardVerdict,
    GuardVerdictAction,
    HistoryContext,
    ProvenanceBundle,
    PublisherTrust,
    ReviewPriority,
)

_EVIDENCE_SOURCE_VALUES: tuple[EvidenceSource, ...] = ("artifact", "prompt", "history", "cloud")
_GUARD_VERDICT_ACTION_VALUES: tuple[GuardVerdictAction, ...] = (
    "allow",
    "warn",
    "block",
    "require_reapproval",
    "sandbox_required",
)
_REVIEW_PRIORITY_VALUES: tuple[ReviewPriority, ...] = ("low", "medium", "high", "critical")
_PROMPT_FILE_HASH_VOLATILE_METADATA_KEYS = frozenset(
    {
        "prompt_display_text",
        "prompt_matched_text",
        "prompt_signals",
        "request_summary",
        "runtime_request_reason",
        "runtime_request_summary",
    }
)
_CONSUMER_APPROVAL_POLICY_VERSION = "consumer-evaluation-v1"
_TRUSTED_REQUEST_OVERRIDE_REASON = "trusted_request_override_exact_context"
_RUNTIME_DETECTOR_BLOCK_REASON = "runtime_detector_block"
_RUNTIME_DETECTOR_REVIEW_REASON = "runtime_detector_review"
_RUNTIME_DETECTOR_WARN_REASON = "runtime_detector_warn"
_SKILL_DIRECTORY_IDENTITY_REASON = "skill_directory_identity_non_reusable"


class ArtifactDiff(TypedDict):
    changed: bool
    changed_fields: list[str]
    previous_hash: str | None
    current_hash: str | None
    current_snapshot: dict[str, object]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_decision_scope(value: object) -> TypeGuard[DecisionScope]:
    return isinstance(value, str) and value in DECISION_SCOPE_VALUES


def _is_evidence_source(value: object) -> TypeGuard[EvidenceSource]:
    return isinstance(value, str) and value in _EVIDENCE_SOURCE_VALUES


def _sorted_evidence_sources(values: Iterable[str]) -> tuple[EvidenceSource, ...]:
    sources: list[EvidenceSource] = []
    for value in sorted(set(values)):
        if _is_evidence_source(value):
            sources.append(value)
    return tuple(sources)


def _serialize_artifact(artifact: GuardArtifact) -> dict[str, object]:
    payload = artifact.to_dict()
    metadata = payload.get("metadata")
    payload["env_keys"] = metadata.get("env_keys", []) if isinstance(metadata, dict) else []
    return payload


def _hash_payload(artifact: GuardArtifact) -> dict[str, object]:
    payload = artifact.to_dict()
    metadata = artifact.metadata
    if (
        isinstance(metadata, dict)
        and artifact.artifact_type == "prompt_request"
        and isinstance(metadata.get("normalized_path"), str)
    ):
        redacted_metadata = payload.get("metadata")
        metadata = (
            {
                key: value
                for key, value in redacted_metadata.items()
                if key not in _PROMPT_FILE_HASH_VOLATILE_METADATA_KEYS
            }
            if isinstance(redacted_metadata, dict)
            else {}
        )
        prompt_intent_hash = (
            redacted_metadata.get("prompt_intent_hash") if isinstance(redacted_metadata, dict) else None
        )
        if isinstance(prompt_intent_hash, str) and prompt_intent_hash.strip():
            metadata["prompt_intent_hash"] = prompt_intent_hash.strip()
    payload["metadata"] = metadata
    payload["env_keys"] = metadata.get("env_keys", []) if isinstance(metadata, dict) else []
    return payload


def artifact_hash(artifact: GuardArtifact) -> str:
    """Hash a detected artifact definition."""

    payload = _hash_payload(artifact)
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def diff_artifact(previous: dict[str, object] | None, current: GuardArtifact) -> ArtifactDiff:
    """Compare a stored snapshot to the current artifact."""

    current_payload = _serialize_artifact(current)
    current_hash = artifact_hash(current)
    if previous is None:
        changed_fields = _first_seen_changed_fields(current)
        return {
            "changed": True,
            "changed_fields": changed_fields,
            "previous_hash": None,
            "current_hash": current_hash,
            "current_snapshot": current_payload,
        }
    previous_payload = dict(previous)
    if "env_keys" not in previous_payload:
        previous_payload["env_keys"] = []
    changed_fields = [key for key, value in current_payload.items() if previous_payload.get(key) != value]
    previous_hash = previous.get("artifact_hash")
    previous_hash_value = previous_hash if isinstance(previous_hash, str) else None
    if previous_hash_value is not None and previous_hash_value != current_hash and not changed_fields:
        changed_fields = ["metadata"]
    return {
        "changed": bool(changed_fields),
        "changed_fields": changed_fields,
        "previous_hash": previous_hash_value,
        "current_hash": current_hash,
        "current_snapshot": current_payload,
    }


def diff_removed_artifact(previous: dict[str, object]) -> ArtifactDiff:
    previous_hash = previous.get("artifact_hash")
    return {
        "changed": True,
        "changed_fields": ["removed"],
        "previous_hash": previous_hash if isinstance(previous_hash, str) else None,
        "current_hash": None,
        "current_snapshot": previous,
    }


def _guard_default_action(artifact: GuardArtifact) -> GuardAction | None:
    value = artifact.metadata.get("guard_default_action")
    if _is_guard_action(value):
        return value
    return None


def _build_removed_provenance(previous: dict[str, object]) -> str:
    scope = previous.get("source_scope")
    config_path = previous.get("config_path")
    scope_label = str(scope) if isinstance(scope, str) else "unknown"
    path_label = str(config_path) if isinstance(config_path, str) else "unknown config"
    return f"{scope_label} artifact removed from {path_label}"


def _capabilities_summary(artifact: GuardArtifact) -> str:
    parts = [artifact.artifact_type.replace("_", " ")]
    if artifact.transport is not None:
        parts.append(artifact.transport)
    if artifact.command is not None:
        parts.append(artifact.command)
    return " • ".join(parts)


def _removed_capabilities_summary(previous: dict[str, object]) -> str:
    artifact_type = previous.get("artifact_type")
    source_scope = previous.get("source_scope")
    parts: list[str] = []
    if isinstance(artifact_type, str):
        parts.append(artifact_type.replace("_", " "))
    if isinstance(source_scope, str):
        parts.append(f"{source_scope} artifact")
    return " • ".join(parts) if parts else "removed artifact"


def _build_diff_summary(diff: Mapping[str, object]) -> str | None:
    """Build a prose diff summary from a diff result dict."""
    if not diff.get("changed"):
        return None
    changed_fields = diff.get("changed_fields")
    if not isinstance(changed_fields, list) or not changed_fields:
        return "artifact changed"
    count = len(changed_fields)
    sample = ", ".join(str(f) for f in changed_fields[:3])
    suffix = " ..." if count > 3 else ""
    return f"{count} change(s): {sample}{suffix}"


def build_history_context(
    store: GuardStore,
    harness: str,
    artifact_id: str,
    publisher: str | None,
) -> HistoryContext:
    """Collect local artifact history signals for verdict enrichment."""

    inventory_item = store.find_inventory_item(artifact_id)
    decision_counts = store.receipt_decision_counts(harness, artifact_id)
    prior_approvals = sum(decision_counts.get(decision, 0) for decision in {"allow", "warn"})
    prior_blocks = sum(
        decision_counts.get(decision, 0) for decision in {"review", "require-reapproval", "sandbox-required", "block"}
    )
    prior_incidents = 0
    for event in store.list_events(limit=1000):
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if payload.get("artifact_id") != artifact_id:
            continue
        if event.get("event_name") in {
            "changed_artifact_caught",
            "premium_advisory",
            "install_time_block",
            "install_time_review",
            "install_time_require-reapproval",
            "install_time_sandbox-required",
        }:
            prior_incidents += 1
    publisher_trust: PublisherTrust = "unknown"
    if publisher:
        advisories = [item for item in store.list_cached_advisories(limit=200) if item.get("publisher") == publisher]
        if advisories:
            severity_labels = {str(item.get("severity", "")).lower() for item in advisories}
            publisher_trust = "flagged" if {"critical", "high", "revoked"} & severity_labels else "known-good"
    return HistoryContext(
        first_seen_at=(
            str(inventory_item.get("first_seen_at"))
            if isinstance(inventory_item, dict) and isinstance(inventory_item.get("first_seen_at"), str)
            else None
        ),
        last_seen_at=(
            str(inventory_item.get("last_seen_at"))
            if isinstance(inventory_item, dict) and isinstance(inventory_item.get("last_seen_at"), str)
            else None
        ),
        prior_approvals=prior_approvals,
        prior_incidents=prior_incidents,
        prior_blocks=prior_blocks,
        publisher_trust=publisher_trust,
    )


def build_provenance_bundle(store: GuardStore, publisher: str | None) -> ProvenanceBundle:
    """Build provenance context from local cache and advisories."""

    if publisher is None:
        return ProvenanceBundle()
    advisories = [item for item in store.list_cached_advisories(limit=200) if item.get("publisher") == publisher]
    if not advisories:
        return ProvenanceBundle(
            source_kind="self-declared",
            publisher_trust="unknown",
            signature_verified=False,
            attestation_verified=False,
            evidence_refs=(f"publisher:{publisher}",),
        )
    severity_labels = {str(item.get("severity", "")).lower() for item in advisories}
    trust: PublisherTrust = "known-good"
    if {"critical", "high", "revoked"} & severity_labels:
        trust = "flagged"
    signature_verified = any(bool(item.get("signatureVerified")) for item in advisories)
    attestation_verified = any(bool(item.get("attestationVerified")) for item in advisories)
    references = tuple(
        sorted(
            {
                str(item.get("advisoryId"))
                for item in advisories
                if isinstance(item.get("advisoryId"), str) and str(item.get("advisoryId"))
            }
        )
    )
    return ProvenanceBundle(
        source_kind="curated",
        publisher_trust=trust,
        signature_verified=signature_verified,
        attestation_verified=attestation_verified,
        evidence_refs=references or (f"publisher:{publisher}",),
    )


def score_verdict(
    signals: tuple[GuardSignal, ...],
    deltas: tuple[CapabilityDelta, ...],
    provenance: ProvenanceBundle,
    history: HistoryContext,
) -> GuardVerdict:
    """Produce a structured verdict before explicit policy override."""

    signal_severity = max((signal.severity for signal in signals), default=1)
    delta_severity = severity_from_deltas(deltas)
    severity = max(signal_severity, delta_severity)
    confidence_pool = [signal.confidence for signal in signals]
    if deltas:
        confidence_pool.append(0.78)
    if provenance.source_kind != "none":
        confidence_pool.append(0.74)
    confidence = max(confidence_pool) if confidence_pool else 0.55
    reasons = [signal.explanation for signal in sorted(signals, key=lambda item: item.severity, reverse=True)[:3]]
    reasons.extend(delta.explanation for delta in deltas[:2])
    if history.prior_approvals > 0 and history.prior_incidents == 0 and severity < 8:
        reasons.append("Artifact has prior local approvals without recent incidents.")
        confidence = min(0.98, confidence + 0.05)
    if provenance.publisher_trust in {"flagged", "revoked"}:
        severity = max(severity, 9)
        reasons.append("Publisher trust is flagged by local advisory intelligence.")
    evidence_sources = _sorted_evidence_sources(signal.evidence_source for signal in signals)
    if history.prior_approvals > 0 or history.prior_incidents > 0:
        evidence_sources = _sorted_evidence_sources((*evidence_sources, "history"))
    if provenance.source_kind in {"curated", "signed", "attested"}:
        evidence_sources = _sorted_evidence_sources((*evidence_sources, "cloud"))

    recommended_actions = _recommended_actions(signals, deltas, severity)
    suppressible = severity <= 6 and provenance.publisher_trust != "flagged"
    review_priority = _review_priority_from_severity(severity)
    action = _action_from_scoring(severity, confidence, provenance, deltas)

    return GuardVerdict(
        action=action,
        severity=severity,
        confidence=round(confidence, 3),
        reasons=tuple(reasons[:4]),
        recommended_next_actions=tuple(recommended_actions),
        suppressible=suppressible,
        review_priority=review_priority,
        evidence_sources=evidence_sources or ("artifact",),
        provenance_state=provenance.source_kind,
        capability_delta=deltas,
    )


def _action_from_scoring(
    severity: int,
    confidence: float,
    provenance: ProvenanceBundle,
    deltas: tuple[CapabilityDelta, ...],
) -> GuardVerdictAction:
    if provenance.publisher_trust in {"flagged", "revoked"} and confidence >= 0.7:
        return "block"
    if severity >= 9 and confidence >= 0.75:
        return "block"
    if severity >= 8 and provenance.source_kind == "none":
        return "sandbox_required"
    if severity >= 7 or any(
        delta.delta_type in {"secret_scope_expanded", "subprocess_added", "approval_surface_changed"}
        for delta in deltas
    ):
        return "require_reapproval"
    if severity >= 5:
        return "warn"
    return "allow"


def _review_priority_from_severity(severity: int) -> ReviewPriority:
    if severity >= 9:
        return "critical"
    if severity >= 7:
        return "high"
    if severity >= 5:
        return "medium"
    return "low"


def _recommended_actions(
    signals: tuple[GuardSignal, ...],
    deltas: tuple[CapabilityDelta, ...],
    severity: int,
) -> list[str]:
    actions: list[str] = []
    delta_types = {delta.delta_type for delta in deltas}
    if "new_network_host" in delta_types:
        actions.append("review_network_destination")
    if "secret_scope_expanded" in delta_types:
        actions.append("rotate_exposed_secret")
    if "subprocess_added" in delta_types or "approval_surface_changed" in delta_types:
        actions.append("approve_once")
    if any(signal.family == "policy" for signal in signals):
        actions.append("open_investigation")
    if severity >= 8:
        actions.append("run_in_sandbox")
    if not actions:
        actions.extend(["approve_once", "defer_and_notify_team"])
    ordered: list[str] = []
    for action in actions:
        if action not in ordered:
            ordered.append(action)
    return ordered


def _default_action_from_verdict(verdict: GuardVerdict) -> GuardAction:
    mapping: dict[GuardVerdictAction, GuardAction] = {
        "allow": "allow",
        "warn": "warn",
        "block": "block",
        "require_reapproval": "require-reapproval",
        "sandbox_required": "sandbox-required",
    }
    return mapping[verdict.action]


def _normalized_consumer_path(path: Path) -> str:
    try:
        return str(path.expanduser().resolve(strict=False))
    except (OSError, RuntimeError):
        return str(path.expanduser().absolute())


def _consumer_effective_cwd(config: GuardConfig) -> Path:
    return config.workspace if config.workspace is not None else Path.cwd()


def _consumer_policy_workspace(config: GuardConfig) -> str:
    return _normalized_consumer_path(_consumer_effective_cwd(config))


def _consumer_execution_identity(
    command: str | None,
    *,
    args: Sequence[object] = (),
    cwd: Path,
    structured_command: bool = False,
) -> dict[str, object]:
    requested = command.strip() if isinstance(command, str) else command
    launch_identity = build_runtime_launch_identity(
        command,
        args=args,
        structured_command=structured_command,
        cwd=cwd,
        launch_env=os.environ,
    )
    return {
        "requested": requested,
        "argv_sha256": launch_identity["argv_sha256"],
        "entrypoint": launch_identity["entrypoint"],
        "launch_cwd": launch_identity["launch_cwd"],
        "resolved": launch_identity["executable"],
    }


def _consumer_context_metadata(artifact: GuardArtifact) -> dict[str, object]:
    if artifact.artifact_type != "prompt_request":
        return dict(artifact.metadata)
    return {
        key: value for key, value in artifact.metadata.items() if key not in _PROMPT_FILE_HASH_VOLATILE_METADATA_KEYS
    }


def _skill_directory_identity_reusable(
    *,
    artifact_type: object,
    metadata: object,
) -> bool | None:
    """Classify the optional migrated skill identity boundary.

    ``None`` preserves legacy behavior for adapters that do not emit the
    marker.  Once the marker key is present, only a complete, reusable v1
    envelope whose digest agrees with ``directory_hash`` may reuse approval.
    """

    if artifact_type != "skill" or not isinstance(metadata, Mapping):
        return None
    if "skillDirectoryIdentity" not in metadata:
        return None
    if metadata.get("inspection_complete") is False:
        return False
    return validated_complete_skill_directory_hash(metadata) is not None


def _skill_directory_identity_evidence(reusable: bool | None) -> tuple[dict[str, object], ...]:
    if reusable is not False:
        return ()
    return (
        {
            "source": "skill_directory_identity",
            "status": "incomplete",
            "reason_code": _SKILL_DIRECTORY_IDENTITY_REASON,
            "reusable": False,
            "action_floor": "require-reapproval",
        },
    )


def _consumer_policy_context(
    config: GuardConfig,
    *,
    harness: str,
    artifact_id: str | None,
    publisher: str | None,
    configured_action: GuardAction | None,
    effective_default_action: GuardAction | None,
    current_action: GuardAction,
) -> dict[str, object]:
    return {
        "artifact_override": configured_action,
        "changed_hash_action": config.changed_hash_action,
        "current_action": current_action,
        "default_action": config.default_action,
        "effective_default_action": effective_default_action,
        "harness": harness,
        "harness_risk_actions": config.harness_risk_actions or {},
        "managed_locked_settings": list(config.managed_locked_settings),
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "mode": config.mode,
        "new_network_domain_action": config.new_network_domain_action,
        "policy_version": _CONSUMER_APPROVAL_POLICY_VERSION,
        "resolved_override": config.resolve_action_override(harness, artifact_id, publisher),
        "risk_actions": config.risk_actions or {},
        "security_level": config.security_level,
        "subprocess_action": config.subprocess_action,
        "unknown_publisher_action": config.unknown_publisher_action,
    }


def _consumer_approval_context_token(
    *,
    detection: HarnessDetection,
    artifact: GuardArtifact,
    content_hash: str,
    capability_snapshot: Mapping[str, object],
    structured_signals: tuple[GuardSignal, ...],
    provenance: ProvenanceBundle,
    config: GuardConfig,
    configured_action: GuardAction | None,
    effective_default_action: GuardAction | None,
    current_action: GuardAction,
    runtime_detector_context: Mapping[str, object] | None,
) -> str:
    effective_cwd = _consumer_effective_cwd(config)
    normalized_cwd = _normalized_consumer_path(effective_cwd)
    normalized_workspace = _normalized_consumer_path(config.workspace) if config.workspace is not None else None
    return build_approval_context_token(
        identity={
            "artifact_id": artifact.artifact_id,
            "artifact_name": artifact.name,
            "artifact_type": artifact.artifact_type,
            "config_path": artifact.config_path,
            "cwd": normalized_cwd,
            "detection_harness": detection.harness,
            "executable": _consumer_execution_identity(
                artifact.command,
                args=artifact.args,
                cwd=effective_cwd,
                structured_command=artifact.artifact_type == "mcp_server",
            ),
            "harness": artifact.harness,
            "publisher": artifact.publisher,
            "source_scope": artifact.source_scope,
            "workspace": normalized_workspace,
        },
        content={
            "args": list(artifact.args),
            "artifact_hash": content_hash,
            "command": artifact.command,
            "metadata": _consumer_context_metadata(artifact),
            "url": artifact.url,
        },
        capabilities={
            "artifact_capabilities": dict(capability_snapshot),
            "command_available": detection.command_available,
            "installed": detection.installed,
            "provenance": provenance.to_dict(),
            "runtime_detector": dict(runtime_detector_context or {}),
            "scanner_policy_version": _CONSUMER_APPROVAL_POLICY_VERSION,
            "signals": [signal.to_dict() for signal in structured_signals],
            "transport": artifact.transport,
        },
        policy=_consumer_policy_context(
            config,
            harness=detection.harness,
            artifact_id=artifact.artifact_id,
            publisher=artifact.publisher,
            configured_action=configured_action,
            effective_default_action=effective_default_action,
            current_action=current_action,
        ),
        sandbox={
            "analysis": config.sandbox_analysis,
            "required": current_action == "sandbox-required",
        },
    )


def _removed_consumer_approval_context_token(
    *,
    harness: str,
    artifact_id: str,
    previous: Mapping[str, object],
    previous_hash: str,
    config: GuardConfig,
    configured_action: GuardAction | None,
    effective_default_action: GuardAction | None,
    current_action: GuardAction,
    runtime_detector_context: Mapping[str, object] | None,
) -> str:
    effective_cwd = _consumer_effective_cwd(config)
    command = previous.get("command")
    publisher = previous.get("publisher")
    raw_args = previous.get("args")
    previous_args = tuple(str(argument) for argument in raw_args) if isinstance(raw_args, (list, tuple)) else ()
    return build_approval_context_token(
        identity={
            "artifact_id": artifact_id,
            "artifact_name": previous.get("name"),
            "artifact_type": previous.get("artifact_type"),
            "config_path": previous.get("config_path"),
            "cwd": _normalized_consumer_path(effective_cwd),
            "executable": _consumer_execution_identity(
                command if isinstance(command, str) else None,
                args=previous_args,
                cwd=effective_cwd,
                structured_command=previous.get("artifact_type") == "mcp_server",
            ),
            "harness": harness,
            "publisher": publisher if isinstance(publisher, str) else None,
            "source_scope": previous.get("source_scope"),
            "workspace": (_normalized_consumer_path(config.workspace) if config.workspace is not None else None),
        },
        content={"artifact_hash": previous_hash, "removed": True, "snapshot": dict(previous)},
        capabilities={
            "removed": True,
            "runtime_detector": dict(runtime_detector_context or {}),
            "snapshot": dict(previous),
        },
        policy=_consumer_policy_context(
            config,
            harness=harness,
            artifact_id=artifact_id,
            publisher=publisher if isinstance(publisher, str) else None,
            configured_action=configured_action,
            effective_default_action=effective_default_action,
            current_action=current_action,
        ),
        sandbox={
            "analysis": config.sandbox_analysis,
            "required": current_action == "sandbox-required",
        },
    )


def _consumer_saved_allow_validation_reason(
    decision: Mapping[str, object],
    *,
    approval_context_hash: str,
) -> ApprovalReuseValidationFailure | None:
    if decision.get("action") != "allow":
        return None
    return cast(
        ApprovalReuseValidationFailure,
        approval_context_tokens_validation_reason(
            decision.get("artifact_hash"),
            approval_context_hash,
        ),
    )


def _compose_consumer_saved_policy(
    *,
    store: GuardStore,
    harness: str,
    artifact_id: str,
    artifact_hash: str,
    workspace: str | None,
    publisher: str | None,
    current_action: GuardAction,
    now: str,
    memory_command: str | None = None,
    memory_artifact_type: str | None = None,
    memory_artifact_name: str | None = None,
    pending_approval_claims: list[tuple[Mapping[str, object], str, str]] | None = None,
) -> tuple[ApprovalReuseDecision, bool]:
    lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        harness,
        artifact_id,
        artifact_hash=artifact_hash,
        workspace=workspace,
        publisher=publisher,
        now=now,
        memory_command=memory_command,
        memory_artifact_type=memory_artifact_type,
        memory_artifact_name=memory_artifact_name,
        consume_one_shot=False,
    )
    saved_decision = lookup["decision"]
    ignored_integrity = lookup["ignored_local_integrity"]
    has_saved_state = saved_decision is not None or ignored_integrity is not None
    validation_reason: ApprovalReuseValidationFailure | None = None
    saved_action: object | None = None
    if saved_decision is not None:
        saved_action = saved_decision.get("action")
        validation_reason = (
            "approval_reuse_integrity_failure"
            if ignored_integrity is not None
            else _consumer_saved_allow_validation_reason(
                saved_decision,
                approval_context_hash=artifact_hash,
            )
        )
    elif ignored_integrity is not None:
        saved_action = "require-reapproval"
        validation_reason = "approval_reuse_integrity_failure"
    else:
        diagnosed_reason = store.approval_reuse_validation_reason(
            harness,
            artifact_id,
            artifact_hash,
            workspace,
            publisher,
            now,
        )
        if diagnosed_reason is not None:
            has_saved_state = True
            saved_action = "allow"
            validation_reason = cast(ApprovalReuseValidationFailure, diagnosed_reason)

    if not has_saved_state:
        return evaluate_approval_reuse(current_action), False

    reuse = evaluate_approval_reuse(
        current_action,
        saved_action,
        saved_decision_present=True,
        validation_reason=validation_reason,
    )
    if reuse.should_claim and saved_decision is not None and pending_approval_claims is not None:
        pending_approval_claims.append((saved_decision, artifact_id, artifact_hash))
    return reuse, True


def _approval_reuse_scanner_evidence(
    reuse: ApprovalReuseDecision,
    *,
    has_saved_state: bool,
) -> tuple[dict[str, object], ...]:
    if not has_saved_state and reuse.reason_code == APPROVAL_REUSE_NO_SAVED_DECISION:
        return ()
    return ({"source": "approval_reuse", **reuse.to_evidence()},)


def _runtime_detector_scanner_evidence(block_reason: str | None) -> tuple[dict[str, object], ...]:
    if not block_reason:
        return ()
    return (
        {
            "source": "runtime_detector_registry",
            "status": "blocked",
            "reason_code": _RUNTIME_DETECTOR_BLOCK_REASON,
            "reason": block_reason,
        },
    )


def _runtime_detector_risk_signals(
    runtime_detector_context: Mapping[str, object] | None,
) -> tuple[RiskSignalV2, ...]:
    if runtime_detector_context is None:
        return ()
    raw_signals = runtime_detector_context.get("signals_v2")
    if not isinstance(raw_signals, list):
        return ()
    signals: list[RiskSignalV2] = []
    seen: set[str] = set()
    for raw_signal in raw_signals:
        if not isinstance(raw_signal, Mapping):
            continue
        try:
            signal = RiskSignalV2.from_dict(raw_signal)
        except (TypeError, ValueError):
            continue
        if signal.signal_id in seen:
            continue
        seen.add(signal.signal_id)
        signals.append(signal)
    return tuple(signals)


def _runtime_detector_context_authority(
    runtime_detector_context: Mapping[str, object] | None,
) -> tuple[GuardAction | None, str | None]:
    if runtime_detector_context is None:
        return None, None
    raw_composition = runtime_detector_context.get("composition")
    if not isinstance(raw_composition, Mapping):
        return None, None
    action = raw_composition.get("action")
    if not _is_guard_action(action) or action not in {"allow", "warn", "review", "block"}:
        return None, None
    reason = raw_composition.get("reason")
    return action, reason if isinstance(reason, str) and reason.strip() else None


def _merge_risk_signals(
    static_signals: tuple[RiskSignalV2, ...],
    runtime_signals: tuple[RiskSignalV2, ...],
) -> tuple[RiskSignalV2, ...]:
    merged: list[RiskSignalV2] = []
    seen: set[str] = set()
    for signal in (*static_signals, *runtime_signals):
        if signal.signal_id in seen:
            continue
        seen.add(signal.signal_id)
        merged.append(signal)
    return tuple(merged)


def _runtime_signal_scanner_evidence(signals: tuple[RiskSignalV2, ...]) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "source": "runtime_detector_registry",
            "kind": "risk_signal_v2",
            "signal": signal.to_dict(),
        }
        for signal in signals
    )


def _trusted_request_override_applies(
    trusted_request_overrides: Mapping[str, str] | None,
    *,
    artifact_id: str,
    approval_context_hash: str,
    approval_reuse: ApprovalReuseDecision,
) -> bool:
    """Accept a freshly resolved request only for the exact re-evaluated context.

    This is a trusted, current-request authority input, not saved approval
    reuse.  It may satisfy a review/reapproval prompt after the launch state is
    re-detected, but can never lower a terminal block, sandbox requirement, or
    local-integrity failure.
    """

    expected_hash = (trusted_request_overrides or {}).get(artifact_id)
    return bool(
        expected_hash == approval_context_hash
        and approval_reuse.action in {"review", "require-reapproval"}
        and approval_reuse.reason_code != "approval_reuse_integrity_failure"
    )


def _claimed_saved_approval_applies(
    claimed_saved_approval_overrides: Mapping[str, str] | None,
    retained_saved_approval_overrides: Mapping[str, str] | None,
    *,
    artifact_id: str,
    approval_context_hash: str,
    current_action: GuardAction,
    has_saved_state: bool,
    approval_reuse: ApprovalReuseDecision,
) -> bool:
    """Carry an atomically claimed saved allow into final persistence.

    The claim may consume a one-shot or validate a persistent/reusable row.
    Unlike a fresh request override, preclaimed saved evidence can satisfy only
    an exact current ``review``. It cannot satisfy reapproval or lower a
    sandbox/block result.
    """

    consumed_claim_matches = (claimed_saved_approval_overrides or {}).get(artifact_id) == approval_context_hash
    retained_claim_matches = (retained_saved_approval_overrides or {}).get(artifact_id) == approval_context_hash
    if current_action != "review" or not (consumed_claim_matches or retained_claim_matches):
        return False
    if consumed_claim_matches and not has_saved_state:
        # A consuming one-shot disappears after the atomic claim. The exact
        # claim override is therefore the only remaining proof carried into
        # this persistence-phase evaluation.
        return True
    # Persistent policies and explicitly reusable local approvals remain in
    # the store after a successful claim. Finalize them only while the fresh
    # lookup still resolves the same context to an accepted saved allow. This
    # prevents a stale claim proof from bypassing a changed, expired, corrupt,
    # blocking, or otherwise non-exact row.
    return bool(
        approval_reuse.accepted
        and approval_reuse.saved_action == "allow"
        and approval_reuse.reason_code == APPROVAL_REUSE_ACCEPTED
        and approval_reuse.should_claim
    )


def _saved_approval_claim_evidence(
    claimed_saved_approval_overrides: Mapping[str, str] | None,
    retained_saved_approval_overrides: Mapping[str, str] | None,
    *,
    artifact_id: str,
    approval_context_hash: str,
    claimed: bool,
) -> dict[str, str] | None:
    """Serialize the exact internal claim proof that finalized this authority."""

    if not claimed:
        return None
    if (claimed_saved_approval_overrides or {}).get(artifact_id) == approval_context_hash:
        disposition = "consumed"
    elif (retained_saved_approval_overrides or {}).get(artifact_id) == approval_context_hash:
        disposition = "retained"
    else:
        raise ValueError("claimed saved approval is missing its exact context proof")
    return {
        "status": disposition,
        "approval_context_hash": approval_context_hash,
        "reason_code": APPROVAL_REUSE_ACCEPTED,
    }


def detect_all(context: HarnessContext) -> list[HarnessDetection]:
    """Run detection across all adapters."""

    from ..adapters import list_adapters

    return [adapter.detect(context) for adapter in list_adapters()]


def detect_harness(harness: str, context: HarnessContext) -> HarnessDetection:
    """Detect a single harness."""

    from ..adapters import get_adapter

    return get_adapter(harness).detect(context)


def evaluate_detection(
    detection: HarnessDetection,
    store: GuardStore,
    config: GuardConfig,
    default_action: str | None = None,
    persist: bool = True,
    trusted_request_overrides: Mapping[str, str] | None = None,
    trusted_request_override_labels: Mapping[str, str] | None = None,
    pending_approval_claims: list[tuple[Mapping[str, object], str, str]] | None = None,
    claimed_saved_approval_overrides: Mapping[str, str] | None = None,
    retained_saved_approval_overrides: Mapping[str, str] | None = None,
    runtime_detector_block_reason: str | None = None,
    runtime_detector_context: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Apply policy, generate diffs, and persist receipts for a harness."""

    workspace = _consumer_policy_workspace(config)
    results: list[dict[str, object]] = []
    blocked = False
    receipts_recorded = 0
    now = _now()
    effective_default_action = default_action if _is_guard_action(default_action) else None
    prior_receipts = store.count_receipts(detection.harness) if persist else 0
    previous_snapshots = store.list_snapshots(detection.harness)
    runtime_risk_signals_v2 = _runtime_detector_risk_signals(runtime_detector_context)
    runtime_context_action, runtime_context_reason = _runtime_detector_context_authority(runtime_detector_context)
    current_artifact_ids: set[str] = set()
    for artifact in detection.artifacts:
        current_artifact_ids.add(artifact.artifact_id)
        previous = previous_snapshots.get(artifact.artifact_id)
        diff = diff_artifact(previous, artifact)
        is_first_seen = diff["changed_fields"] == ["first_seen"]
        configured_action = config.resolve_action_override(
            detection.harness,
            artifact.artifact_id,
            artifact.publisher,
        )
        previous_capabilities = store.get_artifact_capability(detection.harness, artifact.artifact_id)
        current_capabilities = normalize_artifact_capabilities(artifact)
        capability_delta = compute_capability_delta(previous_capabilities, current_capabilities)
        structured_signals = artifact_risk_signals_typed(artifact)
        risk_signals_v2 = _merge_risk_signals(
            tuple(RiskSignalV2.from_guard_signal(signal) for signal in structured_signals),
            runtime_risk_signals_v2,
        )
        history_context = build_history_context(store, detection.harness, artifact.artifact_id, artifact.publisher)
        provenance_bundle = build_provenance_bundle(store, artifact.publisher)
        verdict = score_verdict(structured_signals, capability_delta, provenance_bundle, history_context)
        if configured_action is None and artifact.artifact_type in {
            "prompt_request",
            "file_read_request",
            "tool_action_request",
        }:
            current_policy_action = _guard_default_action(artifact) or "require-reapproval"
        elif is_first_seen and configured_action is None and effective_default_action is not None:
            current_policy_action = effective_default_action
        else:
            current_policy_action = decide_action(
                configured_action=configured_action,
                default_action=effective_default_action,
                config=config,
                changed=bool(diff["changed"]),
            )
        scanner_action = _default_action_from_verdict(verdict)
        current_policy_action = most_restrictive_guard_action(
            current_policy_action,
            scanner_action,
        )
        skill_directory_identity_reusable = _skill_directory_identity_reusable(
            artifact_type=artifact.artifact_type,
            metadata=artifact.metadata,
        )
        if skill_directory_identity_reusable is False:
            current_policy_action = most_restrictive_guard_action(
                current_policy_action,
                "require-reapproval",
            )
        approval_context_hash = _consumer_approval_context_token(
            detection=detection,
            artifact=artifact,
            content_hash=str(diff["current_hash"]),
            capability_snapshot=current_capabilities.to_dict(),
            structured_signals=structured_signals,
            provenance=provenance_bundle,
            config=config,
            configured_action=configured_action,
            effective_default_action=effective_default_action,
            current_action=current_policy_action,
            runtime_detector_context=runtime_detector_context,
        )
        approval_reuse, has_saved_state = _compose_consumer_saved_policy(
            store=store,
            harness=detection.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=approval_context_hash,
            workspace=workspace,
            publisher=artifact.publisher,
            current_action=current_policy_action,
            now=now,
            memory_command=artifact.command,
            memory_artifact_type=artifact.artifact_type,
            memory_artifact_name=artifact.name,
            pending_approval_claims=pending_approval_claims,
        )
        claimed_saved_approval = _claimed_saved_approval_applies(
            claimed_saved_approval_overrides,
            retained_saved_approval_overrides,
            artifact_id=artifact.artifact_id,
            approval_context_hash=approval_context_hash,
            current_action=current_policy_action,
            has_saved_state=has_saved_state,
            approval_reuse=approval_reuse,
        )
        approval_claim = _saved_approval_claim_evidence(
            claimed_saved_approval_overrides,
            retained_saved_approval_overrides,
            artifact_id=artifact.artifact_id,
            approval_context_hash=approval_context_hash,
            claimed=claimed_saved_approval,
        )
        if claimed_saved_approval:
            approval_reuse = evaluate_approval_reuse(
                current_policy_action,
                "allow",
                saved_decision_present=True,
            )
            has_saved_state = True
        trusted_request_override = _trusted_request_override_applies(
            trusted_request_overrides,
            artifact_id=artifact.artifact_id,
            approval_context_hash=approval_context_hash,
            approval_reuse=approval_reuse,
        )
        policy_action: GuardAction = "allow" if trusted_request_override else approval_reuse.action
        runtime_review_approved = bool(
            trusted_request_override
            or (
                approval_reuse.accepted
                and approval_reuse.current_action == "review"
                and approval_reuse.saved_action == "allow"
            )
        )
        if runtime_context_action == "warn":
            policy_action = most_restrictive_guard_action(policy_action, "warn")
        if runtime_context_action == "review" and not runtime_review_approved:
            policy_action = most_restrictive_guard_action(policy_action, "review")
        if runtime_context_action == "block" or runtime_detector_block_reason:
            policy_action = "block"
        approval_authority_finalized = (
            not approval_reuse.should_claim or claimed_saved_approval or trusted_request_override
        )
        approval_reuse_evidence = _approval_reuse_scanner_evidence(
            approval_reuse,
            has_saved_state=has_saved_state,
        )
        scanner_evidence = (
            *_skill_directory_identity_evidence(skill_directory_identity_reusable),
            *approval_reuse_evidence,
            *_runtime_signal_scanner_evidence(runtime_risk_signals_v2),
            *(
                (
                    {
                        "source": "trusted_request_override",
                        "status": "accepted",
                        "reason_code": _TRUSTED_REQUEST_OVERRIDE_REASON,
                        "artifact_hash": approval_context_hash,
                    },
                )
                if trusted_request_override
                else ()
            ),
            *_runtime_detector_scanner_evidence(runtime_detector_block_reason),
        )
        decision_reason = (
            _RUNTIME_DETECTOR_BLOCK_REASON
            if runtime_detector_block_reason
            else _RUNTIME_DETECTOR_WARN_REASON
            if runtime_context_action == "warn" and policy_action == "warn"
            else _RUNTIME_DETECTOR_REVIEW_REASON
            if runtime_context_action == "review" and policy_action == "review"
            else _TRUSTED_REQUEST_OVERRIDE_REASON
            if trusted_request_override
            else approval_reuse.reason_code
            if has_saved_state
            else policy_action
        )
        policy_composition = {
            "configured_action": configured_action,
            "current_action": current_policy_action,
            "saved_action": approval_reuse.saved_action,
            "saved_state_present": has_saved_state,
            "scanner_action": scanner_action,
            "raw_scoring_recommendation": verdict.action,
            "scoring_recommendation_non_authoritative": True,
            "trusted_request_override": trusted_request_override,
            **(
                {
                    "skill_directory_identity_reusable": skill_directory_identity_reusable,
                    "skill_directory_identity_floor": "require-reapproval",
                }
                if skill_directory_identity_reusable is False
                else {}
            ),
            **({"saved_approval_claim": approval_claim} if approval_claim is not None else {}),
            **(
                {
                    "runtime_detector_action": "block" if runtime_detector_block_reason else runtime_context_action,
                    "runtime_detector_reason": runtime_detector_block_reason or runtime_context_reason,
                }
                if runtime_detector_block_reason or runtime_context_action is not None
                else {}
            ),
            "final_action": policy_action,
        }
        authoritative_decision = build_authoritative_decision(
            policy_action,
            reason=decision_reason,
            composition_trace=policy_composition,
            signals=risk_signals_v2,
            authority_finalized=approval_authority_finalized,
        )
        policy_action = authoritative_decision.action
        if authoritative_decision.enforcement.blocking:
            blocked = True
        risk_signals = tuple(signal.plain_reason for signal in authoritative_decision.signals)
        has_runtime_authority = bool(
            runtime_risk_signals_v2 or runtime_detector_block_reason or runtime_context_action is not None
        )
        risk_summary = (
            authoritative_decision.decision_v2.dashboard_primary_detail
            if has_runtime_authority
            else artifact_risk_summary(artifact)
            if structured_signals
            else summarize_signals(())
        )
        changed_capabilities = [delta.delta_type for delta in capability_delta] or list(diff["changed_fields"])
        launch_target = _launch_target_from_artifact(artifact)
        incident = build_incident_context(
            harness=detection.harness,
            artifact=artifact,
            artifact_id=artifact.artifact_id,
            artifact_name=artifact.name,
            artifact_type=artifact.artifact_type,
            source_scope=artifact.source_scope,
            config_path=artifact.config_path,
            changed_fields=list(diff["changed_fields"]),
            policy_action=policy_action,
            launch_target=launch_target,
            risk_summary=risk_summary,
        )
        receipt = build_receipt(
            harness=detection.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=str(diff["current_hash"]),
            policy_decision=policy_action,
            capabilities_summary=_capabilities_summary(artifact),
            changed_capabilities=changed_capabilities,
            provenance_summary=(
                f"{artifact.source_scope} artifact defined at {artifact.config_path} "
                f"(provenance: {provenance_bundle.source_kind})"
            ),
            artifact_name=artifact.name,
            source_scope=artifact.source_scope,
            user_override=(
                (trusted_request_override_labels or {}).get(artifact.artifact_id)
                if trusted_request_override and not runtime_detector_block_reason
                else None
            ),
            diff_summary=_build_diff_summary(diff),
            approval_source=(
                "runtime-detector"
                if runtime_detector_block_reason
                else "fresh-approval"
                if trusted_request_override
                else "saved-approval"
                if approval_reuse.accepted and approval_reuse.saved_action == "allow"
                else "saved-policy"
                if approval_reuse.saved_action == "block"
                else "policy"
            ),
            scanner_evidence=scanner_evidence,
        )
        if persist:
            store.record_inventory_artifact(
                artifact=artifact,
                artifact_hash=str(diff["current_hash"]),
                policy_action=policy_action,
                changed=bool(diff["changed"]),
                now=now,
                approved=authoritative_decision.enforcement.snapshot_permitted,
            )
            store.save_artifact_capability(
                harness=detection.harness,
                artifact_id=artifact.artifact_id,
                capability_snapshot=current_capabilities.to_dict(),
                now=now,
            )
            store.upsert_provenance_cache(
                artifact_hash=str(diff["current_hash"]),
                payload=provenance_bundle.to_dict(),
                now=now,
            )
            if diff["changed"]:
                previous_hash = diff["previous_hash"] if isinstance(diff["previous_hash"], str) else None
                store.record_diff(
                    detection.harness,
                    artifact.artifact_id,
                    list(diff["changed_fields"]),
                    previous_hash,
                    str(diff["current_hash"]),
                    now,
                )
            if authoritative_decision.enforcement.snapshot_permitted:
                store.save_snapshot(
                    detection.harness,
                    artifact.artifact_id,
                    {**diff["current_snapshot"], "artifact_hash": diff["current_hash"]},
                    str(diff["current_hash"]),
                    now,
                )
            store.add_receipt(receipt)
            if diff["changed"] and not is_first_seen:
                store.add_event(
                    "changed_artifact_caught",
                    {
                        "harness": detection.harness,
                        "artifact_id": artifact.artifact_id,
                        "artifact_name": artifact.name,
                        "policy_action": policy_action,
                        "changed_fields": list(diff["changed_fields"]),
                        "approval_reuse_status": approval_reuse.status,
                        "approval_reuse_reason_code": approval_reuse.reason_code,
                    },
                    now,
                )
            receipts_recorded += 1
        results.append(
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "changed": diff["changed"],
                "changed_fields": diff["changed_fields"],
                **authoritative_decision.to_artifact_projection(),
                "artifact_hash": diff["current_hash"],
                "approval_context_hash": approval_context_hash,
                "effective_workspace": workspace,
                "approval_reuse_status": approval_reuse.status,
                "approval_reuse_reason_code": approval_reuse.reason_code,
                "approval_reuse": approval_reuse.to_evidence(),
                "scanner_evidence": list(scanner_evidence),
                "trusted_request_override": {
                    "applied": trusted_request_override,
                    "reason_code": _TRUSTED_REQUEST_OVERRIDE_REASON if trusted_request_override else None,
                },
                **({"approval_claim": approval_claim} if approval_claim is not None else {}),
                "scoring_recommendation": {
                    "non_authoritative": True,
                    "action": verdict.action,
                    "mapped_guard_action": scanner_action,
                    "reasons": list(verdict.reasons),
                    "confidence": verdict.confidence,
                    "severity": verdict.severity,
                    "evidence_sources": list(verdict.evidence_sources),
                },
                "risk_signals": list(risk_signals),
                "risk_summary": risk_summary,
                "signals": [signal.to_dict() for signal in structured_signals],
                "confidence": verdict.confidence,
                "severity": verdict.severity,
                "evidence_sources": list(verdict.evidence_sources),
                "provenance_state": verdict.provenance_state,
                "provenance": provenance_bundle.to_dict(),
                "history_context": history_context.to_dict(),
                "capability_snapshot": current_capabilities.to_dict(),
                "capability_delta": [delta.to_dict() for delta in capability_delta],
                "remediation": list(verdict.recommended_next_actions),
                "suppressibility": verdict.suppressible,
                "review_priority": verdict.review_priority,
                "artifact_type": artifact.artifact_type,
                "config_path": artifact.config_path,
                "source_scope": artifact.source_scope,
                "artifact_label": incident["artifact_label"],
                "source_label": incident["source_label"],
                "trigger_summary": incident["trigger_summary"],
                "why_now": incident["why_now"],
                "launch_summary": incident["launch_summary"],
                "risk_headline": incident["risk_headline"],
            }
        )
    removed_artifact_ids = sorted(set(previous_snapshots) - current_artifact_ids)
    for artifact_id in removed_artifact_ids:
        previous = previous_snapshots[artifact_id]
        diff = diff_removed_artifact(previous)
        previous_hash = diff["previous_hash"] if isinstance(diff["previous_hash"], str) else "removed"
        previous_publisher_value = previous.get("publisher")
        previous_publisher = previous_publisher_value if isinstance(previous_publisher_value, str) else None
        configured_action = config.resolve_action_override(
            detection.harness,
            artifact_id,
            previous_publisher,
        )
        current_policy_action = decide_action(
            configured_action=configured_action,
            default_action=effective_default_action,
            config=config,
            changed=True,
        )
        skill_directory_identity_reusable = _skill_directory_identity_reusable(
            artifact_type=previous.get("artifact_type"),
            metadata=previous.get("metadata"),
        )
        if skill_directory_identity_reusable is False:
            current_policy_action = most_restrictive_guard_action(
                current_policy_action,
                "require-reapproval",
            )
        approval_context_hash = _removed_consumer_approval_context_token(
            harness=detection.harness,
            artifact_id=artifact_id,
            previous=previous,
            previous_hash=previous_hash,
            config=config,
            configured_action=configured_action,
            effective_default_action=effective_default_action,
            current_action=current_policy_action,
            runtime_detector_context=runtime_detector_context,
        )
        previous_command_value = previous.get("command")
        previous_artifact_type_value = previous.get("artifact_type")
        previous_name_value = previous.get("name")
        approval_reuse, has_saved_state = _compose_consumer_saved_policy(
            store=store,
            harness=detection.harness,
            artifact_id=artifact_id,
            artifact_hash=approval_context_hash,
            workspace=workspace,
            publisher=previous_publisher,
            current_action=current_policy_action,
            now=now,
            memory_command=previous_command_value if isinstance(previous_command_value, str) else None,
            memory_artifact_type=(
                previous_artifact_type_value if isinstance(previous_artifact_type_value, str) else None
            ),
            memory_artifact_name=previous_name_value if isinstance(previous_name_value, str) else None,
            pending_approval_claims=pending_approval_claims,
        )
        claimed_saved_approval = _claimed_saved_approval_applies(
            claimed_saved_approval_overrides,
            retained_saved_approval_overrides,
            artifact_id=artifact_id,
            approval_context_hash=approval_context_hash,
            current_action=current_policy_action,
            has_saved_state=has_saved_state,
            approval_reuse=approval_reuse,
        )
        approval_claim = _saved_approval_claim_evidence(
            claimed_saved_approval_overrides,
            retained_saved_approval_overrides,
            artifact_id=artifact_id,
            approval_context_hash=approval_context_hash,
            claimed=claimed_saved_approval,
        )
        if claimed_saved_approval:
            approval_reuse = evaluate_approval_reuse(
                current_policy_action,
                "allow",
                saved_decision_present=True,
            )
            has_saved_state = True
        trusted_request_override = _trusted_request_override_applies(
            trusted_request_overrides,
            artifact_id=artifact_id,
            approval_context_hash=approval_context_hash,
            approval_reuse=approval_reuse,
        )
        policy_action = "allow" if trusted_request_override else approval_reuse.action
        runtime_review_approved = bool(
            trusted_request_override
            or (
                approval_reuse.accepted
                and approval_reuse.current_action == "review"
                and approval_reuse.saved_action == "allow"
            )
        )
        if runtime_context_action == "warn":
            policy_action = most_restrictive_guard_action(policy_action, "warn")
        if runtime_context_action == "review" and not runtime_review_approved:
            policy_action = most_restrictive_guard_action(policy_action, "review")
        if runtime_context_action == "block" or runtime_detector_block_reason:
            policy_action = "block"
        approval_authority_finalized = (
            not approval_reuse.should_claim or claimed_saved_approval or trusted_request_override
        )
        approval_reuse_evidence = _approval_reuse_scanner_evidence(
            approval_reuse,
            has_saved_state=has_saved_state,
        )
        scanner_evidence = (
            *_skill_directory_identity_evidence(skill_directory_identity_reusable),
            *approval_reuse_evidence,
            *_runtime_signal_scanner_evidence(runtime_risk_signals_v2),
            *(
                (
                    {
                        "source": "trusted_request_override",
                        "status": "accepted",
                        "reason_code": _TRUSTED_REQUEST_OVERRIDE_REASON,
                        "artifact_hash": approval_context_hash,
                    },
                )
                if trusted_request_override
                else ()
            ),
            *_runtime_detector_scanner_evidence(runtime_detector_block_reason),
        )
        decision_reason = (
            _RUNTIME_DETECTOR_BLOCK_REASON
            if runtime_detector_block_reason
            else _RUNTIME_DETECTOR_WARN_REASON
            if runtime_context_action == "warn" and policy_action == "warn"
            else _RUNTIME_DETECTOR_REVIEW_REASON
            if runtime_context_action == "review" and policy_action == "review"
            else _TRUSTED_REQUEST_OVERRIDE_REASON
            if trusted_request_override
            else approval_reuse.reason_code
            if has_saved_state
            else policy_action
        )
        policy_composition = {
            "configured_action": configured_action,
            "current_action": current_policy_action,
            "saved_action": approval_reuse.saved_action,
            "saved_state_present": has_saved_state,
            # Removal has no artifact body to score. Keep the historical warn
            # recommendation as diagnostic evidence, but do not claim it was
            # an enforcement input.
            "scanner_action": None,
            "raw_scoring_recommendation": "warn",
            "scoring_recommendation_non_authoritative": True,
            "trusted_request_override": trusted_request_override,
            **(
                {
                    "skill_directory_identity_reusable": skill_directory_identity_reusable,
                    "skill_directory_identity_floor": "require-reapproval",
                }
                if skill_directory_identity_reusable is False
                else {}
            ),
            **({"saved_approval_claim": approval_claim} if approval_claim is not None else {}),
            **(
                {
                    "runtime_detector_action": "block" if runtime_detector_block_reason else runtime_context_action,
                    "runtime_detector_reason": runtime_detector_block_reason or runtime_context_reason,
                }
                if runtime_detector_block_reason or runtime_context_action is not None
                else {}
            ),
            "final_action": policy_action,
        }
        authoritative_decision = build_authoritative_decision(
            policy_action,
            reason=decision_reason,
            composition_trace=policy_composition,
            signals=runtime_risk_signals_v2,
            authority_finalized=approval_authority_finalized,
        )
        policy_action = authoritative_decision.action
        if authoritative_decision.enforcement.blocking:
            blocked = True
        removed_risk_signals = tuple(signal.plain_reason for signal in authoritative_decision.signals)
        has_runtime_authority = bool(
            runtime_risk_signals_v2 or runtime_detector_block_reason or runtime_context_action is not None
        )
        removed_risk_summary = (
            authoritative_decision.decision_v2.dashboard_primary_detail
            if has_runtime_authority
            else "Artifact was removed from the harness configuration."
        )
        artifact_name = previous.get("name")
        source_scope = previous.get("source_scope")
        config_path = previous.get("config_path")
        removed_artifact_type_value = previous.get("artifact_type")
        removed_artifact_type = (
            str(removed_artifact_type_value) if isinstance(removed_artifact_type_value, str) else "artifact"
        )
        incident = build_incident_context(
            harness=detection.harness,
            artifact=None,
            artifact_id=artifact_id,
            artifact_name=str(artifact_name) if isinstance(artifact_name, str) else artifact_id,
            artifact_type=removed_artifact_type,
            source_scope=str(source_scope) if isinstance(source_scope, str) else None,
            config_path=str(config_path) if isinstance(config_path, str) else None,
            changed_fields=["removed"],
            policy_action=policy_action,
            launch_target=None,
            risk_summary=removed_risk_summary,
        )
        receipt = build_receipt(
            harness=detection.harness,
            artifact_id=artifact_id,
            artifact_hash=previous_hash,
            policy_decision=policy_action,
            capabilities_summary=_removed_capabilities_summary(previous),
            changed_capabilities=["removed"],
            provenance_summary=_build_removed_provenance(previous),
            artifact_name=str(artifact_name) if isinstance(artifact_name, str) else artifact_id,
            source_scope=str(source_scope) if isinstance(source_scope, str) else None,
            user_override=(
                (trusted_request_override_labels or {}).get(artifact_id)
                if trusted_request_override and not runtime_detector_block_reason
                else None
            ),
            diff_summary="artifact removed",
            approval_source=(
                "runtime-detector"
                if runtime_detector_block_reason
                else "fresh-approval"
                if trusted_request_override
                else "saved-approval"
                if approval_reuse.accepted and approval_reuse.saved_action == "allow"
                else "saved-policy"
                if approval_reuse.saved_action == "block"
                else "policy"
            ),
            scanner_evidence=scanner_evidence,
        )
        if persist:
            store.mark_inventory_removed(
                harness=detection.harness,
                artifact_id=artifact_id,
                policy_action=policy_action,
                artifact_hash=previous_hash,
                now=now,
            )
            store.record_diff(
                detection.harness,
                artifact_id,
                ["removed"],
                diff["previous_hash"] if isinstance(diff["previous_hash"], str) else None,
                "removed",
                now,
            )
            if authoritative_decision.enforcement.snapshot_permitted:
                store.delete_snapshot(detection.harness, artifact_id)
            store.add_receipt(receipt)
            store.add_event(
                "changed_artifact_caught",
                {
                    "harness": detection.harness,
                    "artifact_id": artifact_id,
                    "artifact_name": str(artifact_name) if isinstance(artifact_name, str) else artifact_id,
                    "policy_action": policy_action,
                    "changed_fields": ["removed"],
                    "approval_reuse_status": approval_reuse.status,
                    "approval_reuse_reason_code": approval_reuse.reason_code,
                },
                now,
            )
            receipts_recorded += 1
        results.append(
            {
                "artifact_id": artifact_id,
                "artifact_name": str(artifact_name) if isinstance(artifact_name, str) else artifact_id,
                "changed": True,
                "changed_fields": ["removed"],
                **authoritative_decision.to_artifact_projection(),
                "artifact_hash": previous_hash,
                "approval_context_hash": approval_context_hash,
                "effective_workspace": workspace,
                "approval_reuse_status": approval_reuse.status,
                "approval_reuse_reason_code": approval_reuse.reason_code,
                "approval_reuse": approval_reuse.to_evidence(),
                "scanner_evidence": list(scanner_evidence),
                "trusted_request_override": {
                    "applied": trusted_request_override,
                    "reason_code": _TRUSTED_REQUEST_OVERRIDE_REASON if trusted_request_override else None,
                },
                **({"approval_claim": approval_claim} if approval_claim is not None else {}),
                "scoring_recommendation": {
                    "non_authoritative": True,
                    "action": "warn",
                    "mapped_guard_action": "warn",
                    "reasons": ["Artifact removal should be reviewed for intentionality."],
                    "confidence": 0.7,
                    "severity": 3,
                    "evidence_sources": ["history"],
                },
                "removed": True,
                "risk_signals": list(removed_risk_signals) or ["artifact removed from local harness configuration"],
                "risk_summary": removed_risk_summary,
                "signals": [signal.to_dict() for signal in authoritative_decision.signals],
                "confidence": 0.7,
                "severity": 3,
                "evidence_sources": ["history"],
                "provenance_state": "none",
                "provenance": ProvenanceBundle().to_dict(),
                "history_context": HistoryContext().to_dict(),
                "capability_snapshot": {},
                "capability_delta": [],
                "remediation": ["defer_and_notify_team"],
                "suppressibility": True,
                "review_priority": "low",
                "artifact_type": removed_artifact_type,
                "config_path": str(config_path) if isinstance(config_path, str) else None,
                "source_scope": str(source_scope) if isinstance(source_scope, str) else None,
                "artifact_label": incident["artifact_label"],
                "source_label": incident["source_label"],
                "trigger_summary": incident["trigger_summary"],
                "why_now": incident["why_now"],
                "launch_summary": incident["launch_summary"],
                "risk_headline": incident["risk_headline"],
            }
        )
    evaluation: dict[str, Any] = {
        "harness": detection.harness,
        "artifacts": results,
        "blocked": blocked,
        "receipts_recorded": receipts_recorded,
    }
    authority_error = evaluation_authority_error(evaluation)
    if authority_error is not None:
        raise RuntimeError(authority_error)
    if persist and prior_receipts == 0 and receipts_recorded > 0:
        store.add_event(
            "first_protected_harness_session",
            {
                "harness": detection.harness,
                "artifact_count": len(results),
                "blocked": blocked,
            },
            now,
        )
    if persist:
        from ..access_graph_events import queue_access_graph_snapshot

        queue_access_graph_snapshot(
            store=store,
            detection=detection,
            artifacts=results,
            now=now,
        )
    return evaluation


def record_policy(
    store: GuardStore,
    harness: str,
    action: str,
    scope: str,
    artifact_id: str | None,
    workspace: str | None,
    publisher: str | None = None,
    reason: str | None = None,
    owner: str | None = None,
    source: str = "local",
    expires_at: str | None = None,
    approval_gate_grant: ApprovalGateGrant | None = None,
) -> dict[str, object]:
    """Persist an allow or deny action."""

    if not _is_guard_action(action):
        raise ValueError(f"Invalid Guard action: {action}")
    if not _is_decision_scope(scope):
        raise ValueError(f"Invalid decision scope: {scope}")
    decision = PolicyDecision(
        harness=harness,
        scope=scope,
        action=action,
        artifact_id=artifact_id,
        artifact_hash=None,
        workspace=workspace,
        publisher=publisher,
        reason=reason,
        owner=owner,
        source=source,
        expires_at=expires_at,
    )
    store.upsert_policy(decision, _now(), approval_gate_grant=approval_gate_grant)
    return decision.to_dict()


def _launch_target_from_artifact(artifact: GuardArtifact) -> str | None:
    request_summary = artifact.metadata.get("request_summary")
    if isinstance(request_summary, str) and request_summary:
        return request_summary
    prompt_summary = artifact.metadata.get("prompt_summary")
    if isinstance(prompt_summary, str) and prompt_summary:
        return prompt_summary
    if artifact.url:
        return artifact.url
    if artifact.command:
        return " ".join([artifact.command, *artifact.args]).strip()
    return None


def _first_seen_changed_fields(artifact: GuardArtifact) -> list[str]:
    if artifact.artifact_type == "prompt_request":
        return ["prompt_request"]
    if artifact.artifact_type == "file_read_request":
        return ["file_read_request"]
    return ["first_seen"]


def run_consumer_scan(
    target: Path,
    intended_harness: str | None = None,
    options: ScanOptions | None = None,
) -> dict[str, object]:
    """Expose the consumer-mode scan contract."""

    return build_consumer_mode_contract(target, intended_harness=intended_harness, options=options)
