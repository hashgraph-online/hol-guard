"""Guard orchestration helpers."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

__all__ = ["artifact_hash", "detect_all", "detect_harness", "evaluate_detection", "record_policy", "run_consumer_scan"]


def _service_module():
    return importlib.import_module(".service", __package__)


def artifact_hash(artifact: Any):
    return _service_module().artifact_hash(artifact)


def detect_all(context: Any):
    return _service_module().detect_all(context)


def detect_harness(harness: str, context: Any):
    return _service_module().detect_harness(harness, context)


def evaluate_detection(
    detection: Any,
    store: Any,
    config: Any,
    default_action: str | None = None,
    persist: bool = True,
    trusted_request_overrides: Any = None,
    trusted_request_override_labels: Any = None,
    pending_approval_claims: Any = None,
    claimed_saved_approval_overrides: Any = None,
    retained_saved_approval_overrides: Any = None,
    runtime_detector_context: Any = None,
):
    return _service_module().evaluate_detection(
        detection,
        store,
        config,
        default_action=default_action,
        persist=persist,
        trusted_request_overrides=trusted_request_overrides,
        trusted_request_override_labels=trusted_request_override_labels,
        pending_approval_claims=pending_approval_claims,
        claimed_saved_approval_overrides=claimed_saved_approval_overrides,
        retained_saved_approval_overrides=retained_saved_approval_overrides,
        runtime_detector_context=runtime_detector_context,
    )


def record_policy(
    store: Any,
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
    approval_gate_grant=None,
):
    return _service_module().record_policy(
        store,
        harness,
        action,
        scope,
        artifact_id,
        workspace,
        publisher=publisher,
        reason=reason,
        owner=owner,
        source=source,
        expires_at=expires_at,
        approval_gate_grant=approval_gate_grant,
    )


def run_consumer_scan(target: Path, intended_harness: str | None = None, options: Any = None):
    return _service_module().run_consumer_scan(target, intended_harness=intended_harness, options=options)
