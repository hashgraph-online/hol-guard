"""Non-blocking Inbox persistence for watch-only hook decisions."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import replace

from ..approvals import queue_blocked_approvals
from ..daemon.manager import guard_daemon_url_for_home
from ..models import GuardAction, GuardArtifact, HarnessDetection
from ..runtime.actions import GuardActionEnvelope
from ..store import GuardStore


def queue_observe_mode_request(
    *,
    action_envelope: GuardActionEnvelope | None,
    artifact: GuardArtifact,
    artifact_hash: str,
    changed_fields: Sequence[str],
    executable_action: GuardAction,
    observed_policy_action: GuardAction,
    redaction_level: str,
    risk_summary: str | None,
    scanner_evidence: Sequence[Mapping[str, object]],
    store: GuardStore,
) -> list[dict[str, object]]:
    """Queue retrospective review without changing the executable decision."""

    if observed_policy_action not in {"review", "require-reapproval", "sandbox-required", "block"}:
        return []
    review_action: GuardAction = (
        observed_policy_action if observed_policy_action in {"review", "require-reapproval"} else "require-reapproval"
    )
    queue_envelope = action_envelope.with_pre_execution_result(None) if action_envelope is not None else None
    evidence = [dict(item) for item in scanner_evidence]
    evidence.append(
        {
            "source": "observe_mode_inbox",
            "observed_policy_action": observed_policy_action,
            "queued_policy_action": review_action,
            "authoritative_action": executable_action,
        }
    )
    observed_artifact = replace(
        artifact,
        metadata={
            **artifact.metadata,
            "watch_only_observation": True,
            "watch_only_authoritative_action": executable_action,
        },
    )
    try:
        approval_center_url = guard_daemon_url_for_home(store.guard_home)
        return queue_blocked_approvals(
            detection=HarnessDetection(
                harness=observed_artifact.harness,
                installed=True,
                command_available=True,
                config_paths=(observed_artifact.config_path,),
                artifacts=(observed_artifact,),
            ),
            evaluation={
                "artifacts": [
                    {
                        "artifact_id": artifact.artifact_id,
                        "artifact_name": artifact.name,
                        "artifact_hash": artifact_hash,
                        "artifact_type": artifact.artifact_type,
                        "source_scope": artifact.source_scope,
                        "config_path": artifact.config_path,
                        "policy_action": review_action,
                        "changed_fields": list(changed_fields),
                        "launch_target": artifact.command,
                        "risk_summary": risk_summary,
                        "action_envelope_json": queue_envelope.to_dict() if queue_envelope is not None else None,
                        "scanner_evidence": evidence,
                    }
                ]
            },
            store=store,
            approval_center_url=approval_center_url,
            notify=False,
            redaction_level=redaction_level,
        )
    except (KeyError, OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        # Watch-only telemetry must never alter the executable hook decision.
        return []


__all__ = ["queue_observe_mode_request"]
