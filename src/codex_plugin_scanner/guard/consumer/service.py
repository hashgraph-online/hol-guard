"""Guard consumer-facing orchestration."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any, TypedDict, TypeGuard, cast

from ...models import ScanOptions
from ..action_lattice import is_guard_action as _is_guard_action
from ..adapters.base import HarnessContext
from ..approval_gate import ApprovalGateGrant
from ..capabilities import compute_capability_delta, normalize_artifact_capabilities
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
from ..native_consumer_artifact_compose import NativeConsumerComposeError, native_consumer_compose
from ..receipts import build_receipt
from ..risk import artifact_risk_signals_typed, artifact_risk_summary, summarize_signals
from ..runtime.approval_context import (
    build_approval_context_token,
    build_runtime_launch_identity,
)
from ..runtime.decisions import build_authoritative_decision
from ..runtime.runner_native_authority import authority_error as native_authority_error
from ..runtime.signals import RiskSignalV2
from ..schemas import build_consumer_mode_contract
from ..skill_directory_identity import validated_complete_skill_directory_hash
from ..store import GuardStore
from ..types import (
    CapabilityDelta,
    GuardSignal,
    HistoryContext,
    ProvenanceBundle,
    PublisherTrust,
)

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


def _serialize_artifact(artifact: GuardArtifact) -> dict[str, object]:
    payload = artifact.to_dict()
    metadata = payload.get("metadata")
    payload["env_keys"] = metadata.get("env_keys", []) if isinstance(metadata, dict) else []
    return payload


def _codex_hook_identity(artifact: GuardArtifact) -> str | None:
    if artifact.harness != "codex" or artifact.artifact_type != "hook":
        return None
    identity = artifact.metadata.get("codex_hook_identity")
    return identity if isinstance(identity, str) and identity else None


def _snapshot_codex_hook_identity(snapshot: Mapping[str, object]) -> str | None:
    if snapshot.get("harness") != "codex" or snapshot.get("artifact_type") != "hook":
        return None
    metadata = snapshot.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    identity = metadata.get("codex_hook_identity")
    return identity if isinstance(identity, str) and identity else None


def _hash_payload(artifact: GuardArtifact) -> dict[str, object]:
    codex_hook_identity = _codex_hook_identity(artifact)
    if codex_hook_identity is not None:
        return {
            "schema": "codex-hook-artifact-hash-v1",
            "harness": artifact.harness,
            "artifact_type": artifact.artifact_type,
            "source_scope": artifact.source_scope,
            "codex_hook_identity": codex_hook_identity,
        }
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
    previous_codex_hook_identity = _snapshot_codex_hook_identity(previous_payload)
    current_codex_hook_identity = _codex_hook_identity(current)
    if current_codex_hook_identity is not None and previous_codex_hook_identity == current_codex_hook_identity:
        previous_hash = previous.get("artifact_hash")
        previous_hash_value = previous_hash if isinstance(previous_hash, str) else None
        hash_changed = previous_hash_value is not None and previous_hash_value != current_hash
        return {
            "changed": hash_changed,
            "changed_fields": ["metadata"] if hash_changed else [],
            "previous_hash": previous_hash_value,
            "current_hash": current_hash,
            "current_snapshot": current_payload,
        }
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
    codex_hook_identity = _codex_hook_identity(artifact)
    if codex_hook_identity is not None:
        return {
            "codex_hook_identity_schema": artifact.metadata.get("codex_hook_identity_schema"),
            "codex_hook_identity": codex_hook_identity,
        }
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
    codex_hook_identity = _codex_hook_identity(artifact)
    if codex_hook_identity is not None:
        identity_payload: dict[str, object] = {
            "artifact_id": artifact.artifact_id,
            "artifact_name": artifact.name,
            "artifact_type": artifact.artifact_type,
            "codex_hook_identity": codex_hook_identity,
            "config_path": f"codex-hook://{artifact.source_scope}",
            "cwd": normalized_cwd,
            "detection_harness": detection.harness,
            "executable": {"codex_hook_identity": codex_hook_identity},
            "harness": artifact.harness,
            "publisher": artifact.publisher,
            "source_scope": artifact.source_scope,
            "workspace": normalized_workspace,
        }
        content_payload: dict[str, object] = {
            "artifact_hash": content_hash,
            "codex_hook_identity": codex_hook_identity,
            "metadata": _consumer_context_metadata(artifact),
        }
    else:
        identity_payload = {
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
        }
        content_payload = {
            "args": list(artifact.args),
            "artifact_hash": content_hash,
            "command": artifact.command,
            "metadata": _consumer_context_metadata(artifact),
            "url": artifact.url,
        }
    return build_approval_context_token(
        identity=identity_payload,
        content=content_payload,
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


def _runtime_detector_composition(
    runtime_detector_context: Mapping[str, object] | None,
) -> dict[str, object] | None:
    """Project the detector composition fields the resident's authority reads."""

    composition = (runtime_detector_context or {}).get("composition")
    if not isinstance(composition, Mapping):
        return None
    return {"action": composition.get("action"), "reason": composition.get("reason")}


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


_SAVED_DECISION_KEYS = ("action", "artifact_hash", "scope", "fresh_local_approval", "durable_exact_approval")
_QUALIFICATION_KEYS = ("fresh_local_approval", "durable_exact_approval")
_COMPOSE_UNAVAILABLE_REASON = "consumer_artifact_compose_unavailable"


def _scoring_inputs(
    signals: tuple[GuardSignal, ...],
    deltas: tuple[CapabilityDelta, ...],
    provenance: ProvenanceBundle,
    history: HistoryContext,
) -> dict[str, object]:
    """Project the scoring evidence the resident's current-action query reads."""

    return {
        "signals": [
            {
                "severity": int(signal.severity),
                "confidence": float(signal.confidence),
                "explanation": signal.explanation,
                "family": signal.family,
                "evidence_source": signal.evidence_source,
            }
            for signal in signals
        ],
        "deltas": [
            {"delta_type": delta.delta_type, "severity": int(delta.severity), "explanation": delta.explanation}
            for delta in deltas
        ],
        "provenance_source_kind": provenance.source_kind,
        "publisher_trust": provenance.publisher_trust,
        "prior_approvals": int(history.prior_approvals),
        "prior_incidents": int(history.prior_incidents),
    }


def _native_current_action(
    store: GuardStore,
    config: GuardConfig,
    *,
    removed: bool,
    artifact_type: str | None,
    configured_action: str | None,
    guard_default_action: str | None,
    first_seen: bool,
    changed: bool,
    effective_default_action: GuardAction | None,
    skill_directory_identity_reusable: bool | None,
    scoring: Mapping[str, object],
) -> dict[str, object]:
    """Ask the resident for the scoring recommendation and current action.

    Without an answer the artifact blocks (``compose_unavailable`` carries the
    reason) so the evaluation still completes instead of aborting midway.
    """

    try:
        return native_consumer_compose(
            "current_action",
            {
                "removed": removed,
                "artifact_type": artifact_type,
                "configured_action": configured_action,
                "guard_default_action": guard_default_action,
                "first_seen": first_seen,
                "changed": changed,
                "effective_default_action": effective_default_action,
                "config_changed_hash_action": config.changed_hash_action,
                "config_default_action": config.default_action,
                "skill_directory_identity_reusable": skill_directory_identity_reusable,
                **scoring,
            },
            guard_home=getattr(store, "guard_home", None),
        )
    except NativeConsumerComposeError as error:
        return {
            "current_action": "block",
            "scanner_action": None,
            "verdict": {
                "action": "block",
                "confidence": 0.0,
                "evidence_sources": [],
                "provenance_state": "none",
                "reasons": ["Guard could not score this artifact, so it stays blocked."],
                "recommended_next_actions": ["open_investigation"],
                "review_priority": "critical",
                "severity": 9,
                "suppressible": False,
            },
            "compose_unavailable": error.code,
        }


def _compose_unavailable_decision(
    code: str,
    *,
    configured_action: str | None,
    scanner_action: GuardAction | None,
    raw_scoring_recommendation: object,
) -> dict[str, object]:
    """Fail-closed runtime answer when the resident composed nothing.

    The artifact blocks, no saved approval is claimed and no override applies.
    """

    return {
        "approval_claim": None,
        "approval_reuse": {
            "action": "block",
            "current_action": "block",
            "current_normalization_reason_code": None,
            "original_current_action": "block",
            "original_current_type": "str",
            "original_saved_action": None,
            "original_saved_type": None,
            "reason_code": _COMPOSE_UNAVAILABLE_REASON,
            "saved_action": None,
            "saved_normalization_reason_code": None,
            "should_claim": False,
            "status": "not-applicable",
        },
        "approval_source": "policy",
        "append_pending_claim": False,
        "authority_finalized": True,
        "decision_reason": _COMPOSE_UNAVAILABLE_REASON,
        "policy_action": "block",
        "policy_composition": {
            "configured_action": configured_action,
            "current_action": "block",
            "final_action": "block",
            "native_compose_error": code,
            "raw_scoring_recommendation": raw_scoring_recommendation,
            "saved_action": None,
            "saved_state_present": False,
            "scanner_action": scanner_action,
            "scoring_recommendation_non_authoritative": True,
            "trusted_request_override": False,
        },
        "saved_state_present": False,
        "scanner_evidence": [],
        "trusted_request_override": False,
    }


@dataclass(frozen=True)
class _ConsumerAuthorityInputs:
    """Per-evaluation authority evidence shared by every artifact query."""

    store: GuardStore
    harness: str
    workspace: str | None
    now: str
    trusted_request_overrides: Mapping[str, str]
    claimed_saved_approval_overrides: Mapping[str, str]
    retained_saved_approval_overrides: Mapping[str, str]
    saved_approval_qualification_overrides: Mapping[str, Mapping[str, object]]
    runtime_detector_composition: dict[str, object] | None
    runtime_detector_block_reason: str | None
    runtime_signals: list[dict[str, object]]
    pending_approval_claims: list[tuple[Mapping[str, object], str, str]] | None


def _native_runtime_decision(
    inputs: _ConsumerAuthorityInputs,
    *,
    artifact_id: str,
    approval_context_hash: str,
    publisher: str | None,
    memory_command: str | None,
    memory_artifact_type: str | None,
    memory_artifact_name: str | None,
    current_action: GuardAction,
    configured_action: str | None,
    scanner_action: GuardAction | None,
    raw_scoring_recommendation: object,
    skill_directory_identity_reusable: bool | None,
    compose_unavailable: object = None,
) -> dict[str, object]:
    """Gather saved-decision evidence; the resident composes the final authority.

    A failed current-action query, or no answer here, blocks the artifact.
    """

    unavailable = partial(
        _compose_unavailable_decision,
        configured_action=configured_action,
        scanner_action=scanner_action,
        raw_scoring_recommendation=raw_scoring_recommendation,
    )
    if isinstance(compose_unavailable, str):
        return unavailable(compose_unavailable)
    store = inputs.store
    lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        inputs.harness,
        artifact_id,
        artifact_hash=approval_context_hash,
        workspace=inputs.workspace,
        publisher=publisher,
        now=inputs.now,
        memory_command=memory_command,
        memory_artifact_type=memory_artifact_type,
        memory_artifact_name=memory_artifact_name,
        consume_one_shot=False,
    )
    saved_decision = lookup["decision"]
    ignored_integrity = lookup["ignored_local_integrity"] is not None
    diagnosed_reason = (
        store.approval_reuse_validation_reason(
            inputs.harness,
            artifact_id,
            approval_context_hash,
            inputs.workspace,
            publisher,
            inputs.now,
        )
        if saved_decision is None and not ignored_integrity
        else None
    )
    qualification = inputs.saved_approval_qualification_overrides.get(artifact_id)
    try:
        answer = native_consumer_compose(
            "runtime_decision",
            {
                "current_action": current_action,
                "configured_action": configured_action,
                "scanner_action": scanner_action,
                "raw_scoring_recommendation": raw_scoring_recommendation,
                "skill_directory_identity_reusable": skill_directory_identity_reusable,
                "approval_context_hash": approval_context_hash,
                "saved_decision": (
                    None if saved_decision is None else {key: saved_decision.get(key) for key in _SAVED_DECISION_KEYS}
                ),
                "ignored_local_integrity": ignored_integrity,
                "diagnosed_reason": diagnosed_reason,
                "trusted_request_override_hash": inputs.trusted_request_overrides.get(artifact_id),
                "claimed_saved_approval_hash": inputs.claimed_saved_approval_overrides.get(artifact_id),
                "retained_saved_approval_hash": inputs.retained_saved_approval_overrides.get(artifact_id),
                "saved_approval_qualification": (
                    None
                    if qualification is None
                    else {key: qualification.get(key) is True for key in _QUALIFICATION_KEYS}
                ),
                "runtime_detector_composition": inputs.runtime_detector_composition,
                "runtime_detector_block_reason": inputs.runtime_detector_block_reason,
                "runtime_signals": inputs.runtime_signals,
            },
            guard_home=getattr(store, "guard_home", None),
        )
    except NativeConsumerComposeError as error:
        return unavailable(error.code)
    pending = inputs.pending_approval_claims
    if answer["append_pending_claim"] is True and saved_decision is not None and pending is not None:
        pending.append((saved_decision, artifact_id, approval_context_hash))
    return answer


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
    saved_approval_qualification_overrides: Mapping[str, Mapping[str, object]] | None = None,
    runtime_detector_block_reason: str | None = None,
    runtime_detector_context: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Apply policy, generate diffs, and persist receipts for a harness."""

    from ..native_context import bind_context_digest_home

    # Some consumer entry points run against partial stores (tests, shims)
    # that carry no guard_home; binding None is a valid no-op.
    bind_context_digest_home(getattr(store, "guard_home", None))
    workspace = _consumer_policy_workspace(config)
    results: list[dict[str, object]] = []
    blocked = False
    receipts_recorded = 0
    now = _now()
    effective_default_action = default_action if _is_guard_action(default_action) else None
    prior_receipts = store.count_receipts(detection.harness) if persist else 0
    previous_snapshots = store.list_snapshots(detection.harness)
    runtime_risk_signals_v2 = _runtime_detector_risk_signals(runtime_detector_context)
    authority_inputs = _ConsumerAuthorityInputs(
        store=store,
        harness=detection.harness,
        workspace=workspace,
        now=now,
        trusted_request_overrides=trusted_request_overrides or {},
        claimed_saved_approval_overrides=claimed_saved_approval_overrides or {},
        retained_saved_approval_overrides=retained_saved_approval_overrides or {},
        saved_approval_qualification_overrides=saved_approval_qualification_overrides or {},
        runtime_detector_composition=_runtime_detector_composition(runtime_detector_context),
        runtime_detector_block_reason=runtime_detector_block_reason,
        runtime_signals=[signal.to_dict() for signal in runtime_risk_signals_v2],
        pending_approval_claims=pending_approval_claims,
    )
    current_artifact_ids: set[str] = set()
    for artifact in detection.artifacts:
        current_artifact_ids.add(artifact.artifact_id)
        previous = previous_snapshots.get(artifact.artifact_id)
        diff = diff_artifact(previous, artifact)
        if (
            detection.harness == "codex"
            and artifact.artifact_type == "skill"
            and artifact.metadata.get("enabled") is False
            and artifact.runtime_private_metadata.get("inventory_only") is True
        ):
            inventory_decision = build_authoritative_decision(
                "allow",
                reason="inventory_only",
                composition_trace={"inventory_only": True},
                authority_finalized=False,
            )
            if persist:
                store.record_inventory_artifact(
                    artifact=artifact,
                    artifact_hash=str(diff["current_hash"]),
                    policy_action=inventory_decision.action,
                    changed=bool(diff["changed"]),
                    now=now,
                    approved=False,
                )
                store.save_artifact_capability(
                    harness=detection.harness,
                    artifact_id=artifact.artifact_id,
                    capability_snapshot=normalize_artifact_capabilities(artifact).to_dict(),
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
                store.save_snapshot(
                    detection.harness,
                    artifact.artifact_id,
                    {**diff["current_snapshot"], "artifact_hash": diff["current_hash"]},
                    str(diff["current_hash"]),
                    now,
                )
            results.append(
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "changed": diff["changed"],
                    "changed_fields": diff["changed_fields"],
                    **inventory_decision.to_artifact_projection(),
                    "artifact_hash": diff["current_hash"],
                    "artifact_type": artifact.artifact_type,
                    "config_path": artifact.config_path,
                    "source_scope": artifact.source_scope,
                    "inventory_only": True,
                }
            )
            continue
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
        skill_directory_identity_reusable = _skill_directory_identity_reusable(
            artifact_type=artifact.artifact_type,
            metadata=artifact.metadata,
        )
        guard_default_action = artifact.metadata.get("guard_default_action")
        current = _native_current_action(
            store,
            config,
            removed=False,
            artifact_type=artifact.artifact_type,
            configured_action=configured_action,
            guard_default_action=guard_default_action if isinstance(guard_default_action, str) else None,
            first_seen=is_first_seen,
            changed=bool(diff["changed"]),
            effective_default_action=effective_default_action,
            skill_directory_identity_reusable=skill_directory_identity_reusable,
            scoring=_scoring_inputs(structured_signals, capability_delta, provenance_bundle, history_context),
        )
        current_policy_action = cast(GuardAction, current["current_action"])
        scanner_action = cast(GuardAction, current["scanner_action"])
        verdict = cast(dict[str, Any], current["verdict"])
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
        runtime = _native_runtime_decision(
            authority_inputs,
            artifact_id=artifact.artifact_id,
            approval_context_hash=approval_context_hash,
            publisher=artifact.publisher,
            memory_command=artifact.command,
            memory_artifact_type=artifact.artifact_type,
            memory_artifact_name=artifact.name,
            current_action=current_policy_action,
            configured_action=configured_action,
            scanner_action=scanner_action,
            raw_scoring_recommendation=verdict["action"],
            skill_directory_identity_reusable=skill_directory_identity_reusable,
            compose_unavailable=current.get("compose_unavailable"),
        )
        approval_reuse = cast(dict[str, Any], runtime["approval_reuse"])
        approval_claim = runtime["approval_claim"]
        trusted_request_override = runtime["trusted_request_override"] is True
        scanner_evidence = cast(list[dict[str, object]], runtime["scanner_evidence"])
        policy_composition = cast(dict[str, object], runtime["policy_composition"])
        authoritative_decision = build_authoritative_decision(
            cast(GuardAction, runtime["policy_action"]),
            reason=cast(str, runtime["decision_reason"]),
            composition_trace=policy_composition,
            signals=risk_signals_v2,
            authority_finalized=runtime["authority_finalized"] is True,
        )
        policy_action = authoritative_decision.action
        if authoritative_decision.enforcement.blocking:
            blocked = True
        risk_signals = tuple(signal.plain_reason for signal in authoritative_decision.signals)
        has_runtime_authority = bool(runtime_risk_signals_v2) or "runtime_detector_action" in policy_composition
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
            approval_source=cast(str, runtime["approval_source"]),
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
                        "approval_reuse_status": approval_reuse["status"],
                        "approval_reuse_reason_code": approval_reuse["reason_code"],
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
                "approval_reuse_status": approval_reuse["status"],
                "approval_reuse_reason_code": approval_reuse["reason_code"],
                "approval_reuse": dict(approval_reuse),
                "scanner_evidence": list(scanner_evidence),
                "trusted_request_override": {
                    "applied": trusted_request_override,
                    "reason_code": _TRUSTED_REQUEST_OVERRIDE_REASON if trusted_request_override else None,
                },
                **({"approval_claim": approval_claim} if approval_claim is not None else {}),
                "scoring_recommendation": {
                    "non_authoritative": True,
                    "action": verdict["action"],
                    "mapped_guard_action": scanner_action,
                    "reasons": list(verdict["reasons"]),
                    "confidence": verdict["confidence"],
                    "severity": verdict["severity"],
                    "evidence_sources": list(verdict["evidence_sources"]),
                },
                "risk_signals": list(risk_signals),
                "risk_summary": risk_summary,
                "signals": [signal.to_dict() for signal in structured_signals],
                "confidence": verdict["confidence"],
                "severity": verdict["severity"],
                "evidence_sources": list(verdict["evidence_sources"]),
                "provenance_state": verdict["provenance_state"],
                "provenance": provenance_bundle.to_dict(),
                "history_context": history_context.to_dict(),
                "capability_snapshot": current_capabilities.to_dict(),
                "capability_delta": [delta.to_dict() for delta in capability_delta],
                "remediation": list(verdict["recommended_next_actions"]),
                "suppressibility": verdict["suppressible"],
                "review_priority": verdict["review_priority"],
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
        skill_directory_identity_reusable = _skill_directory_identity_reusable(
            artifact_type=previous.get("artifact_type"),
            metadata=previous.get("metadata"),
        )
        removed_current = _native_current_action(
            store,
            config,
            removed=True,
            artifact_type=None,
            configured_action=configured_action,
            guard_default_action=None,
            first_seen=False,
            changed=True,
            effective_default_action=effective_default_action,
            skill_directory_identity_reusable=skill_directory_identity_reusable,
            scoring=_scoring_inputs((), (), ProvenanceBundle(), HistoryContext()),
        )
        current_policy_action = cast(GuardAction, removed_current["current_action"])
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
        runtime = _native_runtime_decision(
            authority_inputs,
            artifact_id=artifact_id,
            approval_context_hash=approval_context_hash,
            publisher=previous_publisher,
            memory_command=previous_command_value if isinstance(previous_command_value, str) else None,
            memory_artifact_type=(
                previous_artifact_type_value if isinstance(previous_artifact_type_value, str) else None
            ),
            memory_artifact_name=previous_name_value if isinstance(previous_name_value, str) else None,
            current_action=current_policy_action,
            configured_action=configured_action,
            # Removal has no artifact body to score. Keep the historical warn
            # recommendation as diagnostic evidence, but do not claim it was
            # an enforcement input.
            scanner_action=None,
            raw_scoring_recommendation="warn",
            skill_directory_identity_reusable=skill_directory_identity_reusable,
            compose_unavailable=removed_current.get("compose_unavailable"),
        )
        approval_reuse = cast(dict[str, Any], runtime["approval_reuse"])
        approval_claim = runtime["approval_claim"]
        trusted_request_override = runtime["trusted_request_override"] is True
        scanner_evidence = cast(list[dict[str, object]], runtime["scanner_evidence"])
        policy_composition = cast(dict[str, object], runtime["policy_composition"])
        authoritative_decision = build_authoritative_decision(
            cast(GuardAction, runtime["policy_action"]),
            reason=cast(str, runtime["decision_reason"]),
            composition_trace=policy_composition,
            signals=runtime_risk_signals_v2,
            authority_finalized=runtime["authority_finalized"] is True,
        )
        policy_action = authoritative_decision.action
        if authoritative_decision.enforcement.blocking:
            blocked = True
        removed_risk_signals = tuple(signal.plain_reason for signal in authoritative_decision.signals)
        has_runtime_authority = bool(runtime_risk_signals_v2) or "runtime_detector_action" in policy_composition
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
            approval_source=cast(str, runtime["approval_source"]),
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
                    "approval_reuse_status": approval_reuse["status"],
                    "approval_reuse_reason_code": approval_reuse["reason_code"],
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
                "approval_reuse_status": approval_reuse["status"],
                "approval_reuse_reason_code": approval_reuse["reason_code"],
                "approval_reuse": dict(approval_reuse),
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
    authority_error = native_authority_error(evaluation, require_launch_permitted=False)
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
