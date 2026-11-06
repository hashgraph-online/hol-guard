"""Shared helpers for OpenClaw adapter tests."""

from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def mcp_artifact(detection: HarnessDetection, name: str) -> GuardArtifact:
    """Return the unique emitted MCP artifact with the requested server name."""

    return next(
        artifact for artifact in detection.artifacts if artifact.artifact_type == "mcp_server" and artifact.name == name
    )


__all__ = ["mcp_artifact"]
