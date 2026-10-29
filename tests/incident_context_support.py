"""Ask the resident for one artifact decision's incident copy.

Production composes incident copy inside the resident runtime. These tests
keep pinning that copy through the same ``consumer_artifact_project`` query.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.consumer.projection import wire_artifact
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact
from codex_plugin_scanner.guard.native_consumer_artifact_project import native_consumer_project


def build_incident_context(
    *,
    harness: str,
    artifact: GuardArtifact | None,
    artifact_id: str,
    artifact_name: str,
    artifact_type: str | None,
    source_scope: str | None,
    config_path: str | None,
    changed_fields: list[str],
    policy_action: GuardAction,
    launch_target: str | None,
    risk_summary: str | None,
    guard_home: Path | None = None,
) -> dict[str, str]:
    answer = native_consumer_project(
        "incident_context",
        {
            "harness": harness,
            "artifact": wire_artifact(artifact) if artifact is not None else None,
            "changed_fields": list(changed_fields),
            "artifact_id": artifact_id,
            "artifact_name": artifact_name,
            "artifact_type": artifact_type,
            "source_scope": source_scope,
            "config_path": config_path,
            "policy_action": policy_action,
            "launch_target": launch_target,
            "risk_summary": risk_summary,
        },
        guard_home=guard_home,
    )
    return {key: str(value) for key, value in answer.items()}
