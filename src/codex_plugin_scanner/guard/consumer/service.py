"""Guard consumer-facing orchestration."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...models import ScanOptions
from ..adapters import get_adapter, list_adapters
from ..adapters.base import HarnessContext
from ..capabilities import compute_capability_delta, normalize_artifact_capabilities, severity_from_deltas
from ..config import GuardConfig
from ..incident import build_incident_context
from ..models import GuardArtifact, HarnessDetection, PolicyDecision
from ..policy import decide_action
from ..receipts import build_receipt
from ..risk import artifact_risk_signals_typed, artifact_risk_summary, summarize_signals
from ..schemas import build_consumer_mode_contract
from ..store import GuardStore
from ..types import (
    CapabilityDelta,
    GuardSignal,
    GuardVerdict,
    HistoryContext,
    ProvenanceBundle,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _serialize_artifact(artifact: GuardArtifact) -> dict[str, object]:
    payload = artifact.to_dict()
    metadata = payload.get("metadata")
    payload["env_keys"] = metadata.get("env_keys", []) if isinstance(metadata, dict) else []
    return payload


def _hash_payload(artifact: GuardArtifact) -> dict[str, object]:
    payload = artifact.to_dict()
    payload["metadata"] = artifact.metadata
    metadata = payload.get("metadata")
    payload["env_keys"] = metadata.get("env_keys", []) if isinstance(metadata, dict) else []
    return payload


def artifact_hash(artifact: GuardArtifact) -> str:
    """Hash a detected artifact definition."""

    payload = _hash_payload(artifact)
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def diff_artifact(previous: dict[str, object] | None, current: GuardArtifact) -> dict[str, object]:
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


def diff_removed_artifact(previous: dict[str, object]) -> dict[str, object]:
    previous_hash = previous.get("artifact_hash")
    return {
        "changed": True,
        "changed_fields": ["removed"],
        "previous_hash": previous_hash if isinstance(previous_hash, str) else None,
        "current_hash": None,
        "current_snapshot": previous,
    }


def _is_blocking_action(policy_action: str) -> bool:
    return policy_action in {"block", "sandbox-required", "require-reapproval"}


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


def build_history_context(
    store: GuardStore,
    harness: str,
    artifact_id: str,
    publisher: str | None,
) -> HistoryContext:
    """Collect local artifact history signals for verdict enrichment."""

    inventory_item = store.find_inventory_item(artifact_id)
    decision_counts = store.receipt_decision_counts(harness, artifact_id)
    prior_approvals = sum(decision_counts.get(decision, 0) for decision in {"allow", "warn", "review"})
    prior_blocks = sum(
        decision_counts.get(decision, 0) for decision in {"block", "sandbox-required", "require-reapproval"}
    )
    prior_incidents = 0
    for event in store.list_events(limit=1000):
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if payload.get("artifact_id") != artifact_id:
            continue
        if event.get("event_name") in {"changed_artifact_caught", "premium_advisory", "install_time_block"}:
            prior_incidents += 1
    publisher_trust = "unknown"
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
        publisher_trust=publisher_trust,  # type: ignore[arg-type]
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
    trust: str = "known-good"
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
        publisher_trust=trust,  # type: ignore[arg-type]
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
    evidence_sources = tuple(sorted({signal.evidence_source for signal in signals}))
    if history.prior_approvals > 0 or history.prior_incidents > 0:
        evidence_sources = tuple(sorted({*evidence_sources, "history"}))
    if provenance.source_kind in {"curated", "signed", "attested"}:
        evidence_sources = tuple(sorted({*evidence_sources, "cloud"}))

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
) -> str:
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


def _review_priority_from_severity(severity: int) -> str:
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


def _default_action_from_verdict(verdict: GuardVerdict) -> str:
    mapping = {
        "allow": "allow",
        "warn": "warn",
        "block": "block",
        "require_reapproval": "require-reapproval",
        "sandbox_required": "sandbox-required",
    }
    return mapping.get(verdict.action, "warn")


def detect_all(context: HarnessContext) -> list[HarnessDetection]:
    """Run detection across all adapters."""

    return [adapter.detect(context) for adapter in list_adapters()]


def detect_harness(harness: str, context: HarnessContext) -> HarnessDetection:
    """Detect a single harness."""

    return get_adapter(harness).detect(context)


def evaluate_detection(
    detection: HarnessDetection,
    store: GuardStore,
    config: GuardConfig,
    default_action: str | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Apply policy, generate diffs, and persist receipts for a harness."""

    workspace = str(config.workspace) if config.workspace is not None else None
    results: list[dict[str, object]] = []
    blocked = False
    receipts_recorded = 0
    now = _now()
    prior_receipts = store.count_receipts(detection.harness) if persist else 0
    previous_snapshots = store.list_snapshots(detection.harness)
    current_artifact_ids: set[str] = set()
    for artifact in detection.artifacts:
        current_artifact_ids.add(artifact.artifact_id)
        previous = previous_snapshots.get(artifact.artifact_id)
        diff = diff_artifact(previous, artifact)
        is_first_seen = diff["changed_fields"] == ["first_seen"]
        configured_action = store.resolve_policy(
            detection.harness,
            artifact.artifact_id,
            str(diff["current_hash"]),
            workspace,
            artifact.publisher,
        )
        if configured_action is None:
            configured_action = config.resolve_action_override(
                detection.harness,
                artifact.artifact_id,
                artifact.publisher,
            )
        previous_capabilities = store.get_artifact_capability(detection.harness, artifact.artifact_id)
        current_capabilities = normalize_artifact_capabilities(artifact)
        capability_delta = compute_capability_delta(previous_capabilities, current_capabilities)
        structured_signals = artifact_risk_signals_typed(artifact)
        history_context = build_history_context(store, detection.harness, artifact.artifact_id, artifact.publisher)
        provenance_bundle = build_provenance_bundle(store, artifact.publisher)
        verdict = score_verdict(structured_signals, capability_delta, provenance_bundle, history_context)
        effective_default_action = default_action
        if configured_action is None and artifact.artifact_type in {
            "prompt_request",
            "file_read_request",
            "tool_action_request",
        }:
            policy_action = "require-reapproval"
        elif is_first_seen and configured_action is None and effective_default_action is not None:
            policy_action = effective_default_action
        else:
            policy_action = decide_action(
                configured_action=configured_action,
                default_action=effective_default_action,
                config=config,
                changed=bool(diff["changed"]),
            )
        if _is_blocking_action(policy_action):
            blocked = True
        risk_signals = tuple(signal.explanation for signal in structured_signals)
        risk_summary = artifact_risk_summary(artifact) if structured_signals else summarize_signals(())
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
        )
        if persist:
            store.record_inventory_artifact(
                artifact=artifact,
                artifact_hash=str(diff["current_hash"]),
                policy_action=policy_action,
                changed=bool(diff["changed"]),
                now=now,
                approved=not _is_blocking_action(policy_action),
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
            if not _is_blocking_action(policy_action):
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
                "policy_action": policy_action,
                "artifact_hash": diff["current_hash"],
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
                "verdict_action": verdict.action,
                "verdict_reasons": list(verdict.reasons),
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
        policy_action = decide_action(
            configured_action=store.resolve_policy(detection.harness, artifact_id, previous_hash, workspace),
            default_action=default_action,
            config=config,
            changed=True,
        )
        if _is_blocking_action(policy_action):
            blocked = True
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
            risk_summary=None,
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
            if not _is_blocking_action(policy_action):
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
                "policy_action": policy_action,
                "artifact_hash": previous_hash,
                "removed": True,
                "risk_signals": ["artifact removed from local harness configuration"],
                "risk_summary": "Artifact was removed from the harness configuration.",
                "signals": [],
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
                "verdict_action": "warn",
                "verdict_reasons": ["Artifact removal should be reviewed for intentionality."],
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
    return {
        "harness": detection.harness,
        "artifacts": results,
        "blocked": blocked,
        "receipts_recorded": receipts_recorded,
    }


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
) -> dict[str, object]:
    """Persist an allow or deny action."""

    decision = PolicyDecision(
        harness=harness,
        scope=scope,  # type: ignore[arg-type]
        action=action,  # type: ignore[arg-type]
        artifact_id=artifact_id,
        artifact_hash=None,
        workspace=workspace,
        publisher=publisher,
        reason=reason,
        owner=owner,
        source=source,
        expires_at=expires_at,
    )
    store.upsert_policy(decision, _now())
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
