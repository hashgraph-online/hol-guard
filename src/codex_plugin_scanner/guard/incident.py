"""User-facing incident summaries for blocked Guard artifacts.

The copy is composed by the resident runtime (``consumer_artifact_project``);
this wrapper only forwards the artifact facts and fails closed when the
resident cannot answer.
"""

from __future__ import annotations

from pathlib import Path

from .consumer import projection
from .models import GuardAction, GuardArtifact


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
    return projection.incident_context(
        harness=harness,
        artifact=artifact,
        changed_fields=changed_fields,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        artifact_type=artifact_type,
        source_scope=source_scope,
        config_path=config_path,
        policy_action=policy_action,
        launch_target=launch_target,
        risk_summary=risk_summary,
        guard_home=guard_home,
    )
