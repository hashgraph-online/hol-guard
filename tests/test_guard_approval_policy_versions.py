"""Approval tokens bind evaluator revisions without binding product UX versions."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner import version as product_version_module
from codex_plugin_scanner.guard import mcp_tool_calls as mcp_tool_calls_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact
from tests.guard_sensitive_read_support import sensitive_read_token


def _config(tmp_path: Path) -> GuardConfig:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
        security_level="custom",
        risk_actions={
            "local_secret_read": "review",
            "mcp_dangerous_tool": "review",
        },
    )


def _ux_only_config_change(config: GuardConfig) -> GuardConfig:
    return replace(
        config,
        approval_browser_delay_seconds=config.approval_browser_delay_seconds + 17,
        approval_surface_policy="never-auto-open",
        desktop_notifications=not config.desktop_notifications,
        telemetry=not config.telemetry,
    )


def _workspace(config: GuardConfig) -> Path:
    assert config.workspace is not None
    return config.workspace


def _tool_call_token(*, artifact: GuardArtifact, config: GuardConfig) -> str:
    assert config.workspace is not None
    return mcp_tool_calls_module.build_tool_call_hash(
        artifact,
        {"command": "rm unchanged-target"},
        workspace=config.workspace,
        config=config,
    )


def test_mcp_tool_call_approval_ignores_presentation_only_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_context_digest: Path,
) -> None:
    config = _config(tmp_path)
    artifact = mcp_tool_calls_module.build_tool_call_artifact(
        harness="codex",
        server_name="policy-version-server",
        tool_name="shell_exec",
        source_scope="project",
        config_path=str(_workspace(config) / ".mcp.json"),
        transport="stdio",
        tool_schema={"type": "object", "properties": {"command": {"type": "string"}}},
    )
    saved_token = _tool_call_token(artifact=artifact, config=config)

    monkeypatch.setattr(product_version_module, "__version__", "999.0.0-ux-only")
    assert (
        _tool_call_token(
            artifact=replace(artifact, metadata={**artifact.metadata, "ui_contract_version": "v2"}),
            config=_ux_only_config_change(config),
        )
        == saved_token
    )


def _sensitive_read_token(*, artifact: GuardArtifact, config: GuardConfig) -> str:
    return sensitive_read_token(artifact, config=config, cwd=config.workspace)


def test_stdio_sensitive_read_token_ignores_presentation_only_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_context_digest: Path,
) -> None:
    config = _config(tmp_path)
    artifact = GuardArtifact(
        artifact_id="codex:project:file-read:policy-version",
        name="Read .env",
        harness="codex",
        artifact_type="file_read_request",
        source_scope="project",
        config_path=str(_workspace(config) / ".mcp.json"),
        metadata={
            "normalized_path": str(_workspace(config) / ".env"),
            "path_class": "dotenv",
            "tool_name": "read_file",
        },
    )
    saved_token = _sensitive_read_token(artifact=artifact, config=config)

    monkeypatch.setattr(product_version_module, "__version__", "999.0.0-ux-only")
    assert (
        _sensitive_read_token(
            artifact=artifact,
            config=_ux_only_config_change(config),
        )
        == saved_token
    )
