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
    for artifact in detection.artifacts:
        previous = store.get_snapshot(detection.harness, artifact.artifact_id)
        diff = diff_artifact(previous, artifact)
        policy_action = decide_action(
            configured_action=store.resolve_policy(detection.harness, artifact.artifact_id, workspace),
            default_action=default_action,
            config=config,
            changed=bool(diff["changed"]),
        )
        if policy_action == "block":
            blocked = True
        receipt = build_receipt(
            harness=detection.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=str(diff["current_hash"]),
            policy_decision=policy_action,
            changed_capabilities=list(diff["changed_fields"]),
            provenance_summary=f"{artifact.source_scope} artifact defined at {artifact.config_path}",
            artifact_name=artifact.name,
            source_scope=artifact.source_scope,
        )
        if persist:
            store.save_snapshot(
                detection.harness,
                artifact.artifact_id,
                {**diff["current_snapshot"], "artifact_hash": diff["current_hash"]},
                str(diff["current_hash"]),
                now,
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
    reason: str | None = None,
) -> dict[str, object]:
    """Persist an allow or deny action."""

    decision = PolicyDecision(
        harness=harness,
        scope=scope,  # type: ignore[arg-type]
        action=action,  # type: ignore[arg-type]
        artifact_id=artifact_id,
        workspace=workspace,
        reason=reason,
    )
    store.upsert_policy(decision, _now())
    return decision.to_dict()


def run_consumer_scan(target: Path) -> dict[str, object]:
    """Expose the consumer-mode scan contract."""

    return build_consumer_mode_contract(target)
