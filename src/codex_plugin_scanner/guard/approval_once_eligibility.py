"""Identify approved actions that need exact one-shot continuation authority."""

from __future__ import annotations

from collections.abc import Mapping

from .continuation_snapshot import validated_continuation_snapshot
from .runtime.github_workflow_runtime import github_workflow_requires_local_once


def requires_local_once_approval(request: Mapping[str, object]) -> bool:
    if request.get("artifact_type") == "package_request":
        return False
    artifact_id = request.get("artifact_id")
    if isinstance(artifact_id, str) and ":package-request:" in artifact_id:
        return False
    snapshot = validated_continuation_snapshot(request.get("continuation_snapshot"))
    if request.get("harness") == "codex" and snapshot is not None and snapshot["capability"] == "suspended-response":
        return True
    if github_workflow_requires_local_once(request):
        return True
    launch_target = request.get("launch_target")
    return isinstance(launch_target, str) and launch_target.startswith(("npm ", "npx ", "pnpm ", "yarn ", "bun "))
