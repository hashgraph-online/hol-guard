"""Guard consumer-facing orchestration."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..adapters import get_adapter, list_adapters
from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..models import GuardArtifact, HarnessDetection, PolicyDecision
from ..policy import decide_action
from ..receipts import build_receipt
from ..schemas import build_consumer_mode_contract
from ..store import GuardStore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _serialize_artifact(artifact: GuardArtifact) -> dict[str, object]:
    payload = artifact.to_dict()
    metadata = payload.get("metadata")
    payload["env_keys"] = metadata.get("env_keys", []) if isinstance(metadata, dict) else []
    return payload


def artifact_hash(artifact: GuardArtifact) -> str:
    """Hash a detected artifact definition."""

    payload = _serialize_artifact(artifact)
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def diff_artifact(previous: dict[str, object] | None, current: GuardArtifact) -> dict[str, object]:
    """Compare a stored snapshot to the current artifact."""

    current_payload = _serialize_artifact(current)
    current_hash = artifact_hash(current)
    if previous is None:
        return {
            "changed": True,
            "changed_fields": ["first_seen"],
            "previous_hash": None,
            "current_hash": current_hash,
            "current_snapshot": current_payload,
        }
    changed_fields = [key for key, value in current_payload.items() if previous.get(key) != value]
    previous_hash = previous.get("artifact_hash")
    return {
        "changed": bool(changed_fields),
        "changed_fields": changed_fields,
        "previous_hash": previous_hash if isinstance(previous_hash, str) else None,
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
            workspace,
            artifact.publisher,
        )
        if configured_action is None:
            configured_action = config.resolve_action_override(
                detection.harness,
                artifact.artifact_id,
                artifact.publisher,
            )
        if is_first_seen and configured_action is None and default_action is not None:
            policy_action = default_action
        else:
            policy_action = decide_action(
                configured_action=configured_action,
                default_action=default_action,
                config=config,
                changed=bool(diff["changed"]),
            )
        if _is_blocking_action(policy_action):
            blocked = True
        receipt = build_receipt(
            harness=detection.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=str(diff["current_hash"]),
            policy_decision=policy_action,
            capabilities_summary=_capabilities_summary(artifact),
            changed_capabilities=list(diff["changed_fields"]),
            provenance_summary=f"{artifact.source_scope} artifact defined at {artifact.config_path}",
            artifact_name=artifact.name,
            source_scope=artifact.source_scope,
        )
        if persist:
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
            receipts_recorded += 1
        results.append(
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "changed": diff["changed"],
                "changed_fields": diff["changed_fields"],
                "policy_action": policy_action,
                "artifact_hash": diff["current_hash"],
            }
        )
    removed_artifact_ids = sorted(set(previous_snapshots) - current_artifact_ids)
    for artifact_id in removed_artifact_ids:
        previous = previous_snapshots[artifact_id]
        diff = diff_removed_artifact(previous)
        policy_action = decide_action(
            configured_action=store.resolve_policy(detection.harness, artifact_id, workspace),
            default_action=default_action,
            config=config,
            changed=True,
        )
        if _is_blocking_action(policy_action):
            blocked = True
        previous_hash = diff["previous_hash"] if isinstance(diff["previous_hash"], str) else "removed"
        artifact_name = previous.get("name")
        source_scope = previous.get("source_scope")
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
            }
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
) -> dict[str, object]:
    """Persist an allow or deny action."""

    decision = PolicyDecision(
        harness=harness,
        scope=scope,  # type: ignore[arg-type]
        action=action,  # type: ignore[arg-type]
        artifact_id=artifact_id,
        workspace=workspace,
        publisher=publisher,
        reason=reason,
    )
    store.upsert_policy(decision, _now())
    return decision.to_dict()


def run_consumer_scan(target: Path) -> dict[str, object]:
    """Expose the consumer-mode scan contract."""

    return build_consumer_mode_contract(target)
