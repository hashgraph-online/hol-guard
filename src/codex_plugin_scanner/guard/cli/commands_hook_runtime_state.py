"""Guard CLI runtime artifact hook state."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ._commands_shared import *

from dataclasses import dataclass


@dataclass
class RuntimeArtifactHookState:
    action_envelope: GuardActionEnvelope | None
    artifact_id: str
    artifact_name: str
    browser_approval_daemon_client: object | None
    changed_capabilities: list[str]
    decision_v2_payload: dict[str, object]
    event_name: str
    package_evaluation: object | None
    policy_action: str
    requested_policy_action: str | None
    response_payload: dict[str, object]
    risk_summary: str
    runtime_artifact: GuardArtifact
    runtime_artifact_hash: str
    scanner_evidence_payload: list[dict[str, object]]
    stored_policy_action: str | None

__all__ = [
    "RuntimeArtifactHookState",
]
