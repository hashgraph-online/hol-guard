"""Test helpers that ask the resident for a sensitive read's action and approval token."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_mcp_sensitive_read import sensitive_read_context


def sensitive_read_current_action(config: object, *, artifact: GuardArtifact, harness: str) -> str:
    return sensitive_read_context(artifact, config=config, cwd=None, harness=harness)[0]


def sensitive_read_token(
    artifact: GuardArtifact,
    *,
    config: object,
    cwd: Path | None,
    current_action: str | None = None,
    server_launch_identity: Mapping[str, object] | None = None,
    configured_env_values_hash: str | None = None,
    harness: str = "codex",
) -> str:
    action, token = sensitive_read_context(
        artifact,
        config=config,
        cwd=cwd,
        harness=harness,
        server_launch_identity=server_launch_identity,
        configured_env_values_hash=configured_env_values_hash,
    )
    if current_action is not None:
        assert action == current_action, f"resident action {action!r} differs from the expected {current_action!r}"
    return token
