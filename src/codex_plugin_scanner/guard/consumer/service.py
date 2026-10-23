"""Guard consumer-facing orchestration."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict, TypeGuard, cast

from ...models import ScanOptions
from ..action_lattice import is_guard_action as _is_guard_action
from ..adapters.base import HarnessContext
from ..approval_gate import ApprovalGateGrant
from ..config import GuardConfig
from ..models import (
    DECISION_SCOPE_VALUES,
    DecisionScope,
    GuardAction,
    GuardArtifact,
    HarnessDetection,
    PolicyDecision,
)
from ..native_artifact_content_hash import (
    native_artifact_content_hash,
    native_artifact_content_hashes,
)
from ..native_consumer_artifact_compose import native_consumer_compose
from ..receipts import build_receipt
from ..risk import NO_RISK_SIGNAL_SUMMARY, artifact_risk_profile
from ..runtime.approval_context import (
    build_approval_context_token,
    build_runtime_launch_identity,
)
from ..runtime.decisions import (
    build_authoritative_decision,
)
from ..runtime.runner_native_authority import authority_error as native_authority_error
from ..runtime.signals import RiskSignalV2
from ..schemas import build_consumer_mode_contract
from ..skill_directory_identity import validated_complete_skill_directory_hash
from ..store import GuardStore
from ..types import GuardSignal
from . import projection
from .low_trust import low_trust_floor
from .native_decision_projection import (
    _ConsumerAuthorityInputs as _ConsumerAuthorityInputs,
)
from .native_decision_projection import (
    _native_current_action as _native_current_action,
)
from .native_decision_projection import (
    _native_runtime_decision as _native_runtime_decision,
)
from .native_decision_projection import (
    _project_runtime_decision as _project_runtime_decision,
)
from .native_decision_projection import (
    _runtime_artifact_projection as _runtime_artifact_projection,
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


def diff_artifact(
    previous: dict[str, object] | None,
    current: GuardArtifact,
    *,
    guard_home: Path | None = None,
) -> ArtifactDiff:
    """Compare a stored snapshot to the current artifact (resident-decided)."""

    payload = _serialize_artifact(current)
    evidence = projection.artifact_evidence(
        None,
        current,
        payload=payload,
        content_hash=native_artifact_content_hash(current, guard_home=guard_home),
        previous=previous,
        with_history=False,
        guard_home=guard_home,
    )
    return {
        "changed": evidence["changed"],
        "changed_fields": list(evidence["changed_fields"]),
        "previous_hash": evidence["previous_hash"],
        "current_hash": evidence["current_hash"],
        "current_snapshot": payload,
    }


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
    provenance: Mapping[str, object],
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
            "provenance": dict(provenance),
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


def _scoring_inputs(signals: tuple[GuardSignal, ...], evidence_scoring: Mapping[str, object]) -> dict[str, object]:
    """Scoring evidence the resident's current-action query reads: the typed
    signals plus the delta, provenance and history evidence it projected."""

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
        **evidence_scoring,
    }


_REMOVED_SCORING: dict[str, object] = {
    "deltas": [],
    "provenance_source_kind": "none",
    "publisher_trust": "unknown",
    "prior_approvals": 0,
    "prior_incidents": 0,
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
    # Each hash is the approval key its artifact's saved decision is stored
    # under, and the resident spells it. A scan asks for the harness's whole
    # detection at once rather than crossing once per artifact.
    content_hashes = {
        artifact.artifact_id: digest
        for artifact, digest in zip(
            detection.artifacts,
            native_artifact_content_hashes(detection.artifacts),
            strict=True,
        )
    }
    for artifact in detection.artifacts:
        current_artifact_ids.add(artifact.artifact_id)
        previous = previous_snapshots.get(artifact.artifact_id)
        inventory_only = (
            detection.harness == "codex"
            and artifact.artifact_type == "skill"
            and artifact.metadata.get("enabled") is False
            and artifact.runtime_private_metadata.get("inventory_only") is True
        )
        current_snapshot = _serialize_artifact(artifact)
        evidence = projection.artifact_evidence(
            store,
            artifact,
            payload=current_snapshot,
            content_hash=content_hashes[artifact.artifact_id],
            previous=previous,
            with_history=not inventory_only,
        )
        diff = {
            "changed": evidence["changed"],
            "changed_fields": list(evidence["changed_fields"]),
            "previous_hash": evidence["previous_hash"],
            "current_hash": evidence["current_hash"],
            "current_snapshot": current_snapshot,
        }
        if inventory_only:
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
                    capability_snapshot=evidence["capability_snapshot"],
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
                    {**current_snapshot, "artifact_hash": diff["current_hash"]},
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
        is_first_seen = evidence["first_seen"]
        configured_action = config.resolve_action_override(
            detection.harness,
            artifact.artifact_id,
            artifact.publisher,
        )
        artifact_risk = artifact_risk_profile(artifact)
        structured_signals = artifact_risk.signals
        risk_signals_v2 = _merge_risk_signals(artifact_risk.signals_v2, runtime_risk_signals_v2)
        low_trust = low_trust_floor(
            getattr(store, "guard_home", None),
            config,
            harness=detection.harness,
            artifact=artifact,
            configured_action=configured_action,
            fresh_decision=bool(is_first_seen or diff["changed"]),
        )
        if low_trust is not None:
            risk_signals_v2 = _merge_risk_signals(risk_signals_v2, (low_trust.signal,))
        skill_directory_identity_reusable = _skill_directory_identity_reusable(
            artifact_type=artifact.artifact_type,
            metadata=artifact.metadata,
        )
        guard_default_action = artifact.metadata.get("guard_default_action")
        current = _native_current_action(
            store,
            config,
            composer=native_consumer_compose,
            removed=False,
            artifact_type=artifact.artifact_type,
            configured_action=configured_action,
            guard_default_action=guard_default_action if isinstance(guard_default_action, str) else None,
            first_seen=is_first_seen,
            changed=bool(diff["changed"]),
            effective_default_action=effective_default_action,
            skill_directory_identity_reusable=skill_directory_identity_reusable,
            scoring=_scoring_inputs(structured_signals, evidence["scoring"]),
            low_trust_action=low_trust.action if low_trust is not None else None,
        )
        current_policy_action = cast(GuardAction, current["current_action"])
        scanner_action = cast(GuardAction, current["scanner_action"])
        verdict = cast(dict[str, Any], current["verdict"])
        approval_context_hash = _consumer_approval_context_token(
            detection=detection,
            artifact=artifact,
            content_hash=str(diff["current_hash"]),
            capability_snapshot=evidence["capability_snapshot"],
            structured_signals=structured_signals,
            provenance=evidence["provenance"],
            config=config,
            configured_action=configured_action,
            effective_default_action=effective_default_action,
            current_action=current_policy_action,
            runtime_detector_context=runtime_detector_context,
        )
        runtime = _native_runtime_decision(
            authority_inputs,
            composer=native_consumer_compose,
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
            decision_signals=risk_signals_v2,
        )
        approval_reuse = cast(dict[str, Any], runtime["approval_reuse"])
        trusted_request_override = runtime["trusted_request_override"] is True
        scanner_evidence = cast(list[dict[str, object]], runtime["scanner_evidence"])
        policy_composition = cast(dict[str, object], runtime["policy_composition"])
        authoritative_decision = _project_runtime_decision(runtime)
        policy_action = authoritative_decision.action if authoritative_decision is not None else "block"
        if authoritative_decision is None or authoritative_decision.enforcement.blocking:
            blocked = True
        projected_signals = authoritative_decision.signals if authoritative_decision is not None else risk_signals_v2
        risk_signals = tuple(signal.plain_reason for signal in projected_signals)
        snapshot_permitted = (
            authoritative_decision is not None and authoritative_decision.enforcement.snapshot_permitted
        )
        has_runtime_authority = bool(runtime_risk_signals_v2) or "runtime_detector_action" in policy_composition
        risk_summary = (
            authoritative_decision.decision_v2.dashboard_primary_detail
            if authoritative_decision is not None and has_runtime_authority
            else artifact_risk.summary
            if structured_signals
            else NO_RISK_SIGNAL_SUMMARY
        )
        result = projection.artifact_result(
            store,
            detection.harness,
            artifact,
            evidence,
            projection=_runtime_artifact_projection(runtime, authoritative_decision),
            verdict=verdict,
            scanner_action=scanner_action,
            runtime=runtime,
            signals=[signal.to_dict() for signal in structured_signals],
            risk_signals=list(risk_signals),
            risk_summary=risk_summary,
            approval_context_hash=approval_context_hash,
            effective_workspace=workspace,
            policy_action=policy_action,
        )
        receipt = build_receipt(
            harness=detection.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=str(diff["current_hash"]),
            policy_decision=policy_action,
            capabilities_summary=evidence["capabilities_summary"],
            changed_capabilities=evidence["changed_capabilities"],
            provenance_summary=evidence["provenance_summary"],
            artifact_name=artifact.name,
            source_scope=artifact.source_scope,
            user_override=(
                (trusted_request_override_labels or {}).get(artifact.artifact_id)
                if trusted_request_override and not runtime_detector_block_reason
                else None
            ),
            diff_summary=evidence["diff_summary"],
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
                approved=snapshot_permitted,
            )
            store.save_artifact_capability(
                harness=detection.harness,
                artifact_id=artifact.artifact_id,
                capability_snapshot=evidence["capability_snapshot"],
                now=now,
            )
            store.upsert_provenance_cache(
                artifact_hash=str(diff["current_hash"]),
                payload=evidence["provenance"],
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
            if snapshot_permitted:
                store.save_snapshot(
                    detection.harness,
                    artifact.artifact_id,
                    {**current_snapshot, "artifact_hash": diff["current_hash"]},
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
        results.append(result)
    removed_artifact_ids = sorted(set(previous_snapshots) - current_artifact_ids)
    for artifact_id in removed_artifact_ids:
        previous = previous_snapshots[artifact_id]
        recorded_hash = previous.get("artifact_hash")
        previous_hash = recorded_hash if isinstance(recorded_hash, str) else "removed"
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
            composer=native_consumer_compose,
            removed=True,
            artifact_type=None,
            configured_action=configured_action,
            guard_default_action=None,
            first_seen=False,
            changed=True,
            effective_default_action=effective_default_action,
            skill_directory_identity_reusable=skill_directory_identity_reusable,
            scoring=_scoring_inputs((), _REMOVED_SCORING),
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
            composer=native_consumer_compose,
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
            decision_signals=runtime_risk_signals_v2,
        )
        approval_reuse = cast(dict[str, Any], runtime["approval_reuse"])
        trusted_request_override = runtime["trusted_request_override"] is True
        scanner_evidence = cast(list[dict[str, object]], runtime["scanner_evidence"])
        policy_composition = cast(dict[str, object], runtime["policy_composition"])
        authoritative_decision = _project_runtime_decision(runtime)
        policy_action = authoritative_decision.action if authoritative_decision is not None else "block"
        if authoritative_decision is None or authoritative_decision.enforcement.blocking:
            blocked = True
        projected_signals = (
            authoritative_decision.signals if authoritative_decision is not None else runtime_risk_signals_v2
        )
        removed_risk_signals = tuple(signal.plain_reason for signal in projected_signals)
        snapshot_permitted = (
            authoritative_decision is not None and authoritative_decision.enforcement.snapshot_permitted
        )
        has_runtime_authority = bool(runtime_risk_signals_v2) or "runtime_detector_action" in policy_composition
        removed = projection.removed_result(
            store,
            detection.harness,
            artifact_id=artifact_id,
            previous=dict(previous),
            previous_hash=previous_hash,
            projection=_runtime_artifact_projection(runtime, authoritative_decision),
            runtime=runtime,
            signals=[signal.to_dict() for signal in projected_signals],
            risk_signals=list(removed_risk_signals),
            has_runtime_authority=authoritative_decision is not None and has_runtime_authority,
            dashboard_detail=(
                authoritative_decision.decision_v2.dashboard_primary_detail
                if authoritative_decision is not None
                else None
            ),
            approval_context_hash=approval_context_hash,
            effective_workspace=workspace,
            policy_action=policy_action,
        )
        removed_receipt = removed["receipt"]
        artifact_name = removed_receipt["artifact_name"]
        receipt = build_receipt(
            harness=detection.harness,
            artifact_id=artifact_id,
            artifact_hash=previous_hash,
            policy_decision=policy_action,
            capabilities_summary=removed_receipt["capabilities_summary"],
            changed_capabilities=["removed"],
            provenance_summary=removed_receipt["provenance_summary"],
            artifact_name=artifact_name,
            source_scope=removed_receipt["source_scope"],
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
                recorded_hash if isinstance(recorded_hash, str) else None,
                "removed",
                now,
            )
            if snapshot_permitted:
                store.delete_snapshot(detection.harness, artifact_id)
            store.add_receipt(receipt)
            store.add_event(
                "changed_artifact_caught",
                {
                    "harness": detection.harness,
                    "artifact_id": artifact_id,
                    "artifact_name": artifact_name,
                    "policy_action": policy_action,
                    "changed_fields": ["removed"],
                    "approval_reuse_status": approval_reuse["status"],
                    "approval_reuse_reason_code": approval_reuse["reason_code"],
                },
                now,
            )
            receipts_recorded += 1
        results.append(removed["result"])
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


def run_consumer_scan(
    target: Path,
    intended_harness: str | None = None,
    options: ScanOptions | None = None,
) -> dict[str, object]:
    """Expose the consumer-mode scan contract."""

    return build_consumer_mode_contract(target, intended_harness=intended_harness, options=options)
