"""Queue a Claude native approval behind the approval gate the way the retired fallback did."""

from __future__ import annotations

from typing import TYPE_CHECKING

from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.cli._commands_shared import _now
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _action_envelope_json
from codex_plugin_scanner.guard.models import HarnessDetection

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.models import GuardArtifact
    from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
    from codex_plugin_scanner.guard.store import GuardStore


def queue_claude_native_approval_gate_fallback(
    *,
    store: GuardStore,
    harness: str,
    artifact: GuardArtifact,
    artifact_digest: str,
    approval_center_url: str,
    action_envelope: GuardActionEnvelope | None = None,
    redaction_level: str = "full",
) -> list[dict[str, object]]:
    now = _now()
    queued = queue_blocked_approvals(
        detection=HarnessDetection(
            harness=harness,
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        ),
        evaluation={
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": artifact_digest,
                    "artifact_type": artifact.artifact_type,
                    "policy_action": "require-reapproval",
                    "changed_fields": [artifact.artifact_type, "claude-native-approval-gate"],
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "risk_summary": "Native Claude approval requires the HOL Guard approval password.",
                    "risk_signals": ["approval_gate_required", "claude_native_approval"],
                    "action_envelope_json": _action_envelope_json(action_envelope),
                }
            ]
        },
        store=store,
        approval_center_url=approval_center_url,
        now=now,
        redaction_level=redaction_level,
    )
    store.add_event(
        "approval_gate/native_fallback_queued",
        {
            "harness": harness,
            "artifact_id": artifact.artifact_id,
            "queued_count": len(queued),
        },
        now,
    )
    return queued
