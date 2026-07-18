"""Approval tokens bind evaluator revisions without binding product UX versions."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner import version as product_version_module
from codex_plugin_scanner.guard import mcp_tool_calls as mcp_tool_calls_module
from codex_plugin_scanner.guard.cli import commands_hook_generic as generic_hook_module
from codex_plugin_scanner.guard.cli import commands_support_runtime_policy as runtime_policy_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.proxy import stdio as stdio_module
from codex_plugin_scanner.guard.runtime.approval_context import (
    approval_context_tokens_validation_reason,
    parse_approval_context_token,
)


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


def _assert_only_policy_component_changed(saved_token: str, current_token: str) -> None:
    saved = parse_approval_context_token(saved_token)
    current = parse_approval_context_token(current_token)

    assert saved is not None
    assert current is not None
    assert saved.identity_hash == current.identity_hash
    assert saved.content_hash == current.content_hash
    assert saved.capabilities_hash == current.capabilities_hash
    assert saved.policy_hash != current.policy_hash
    assert saved.sandbox_hash == current.sandbox_hash
    assert approval_context_tokens_validation_reason(saved_token, current_token) == "approval_reuse_policy_changed"


def _runtime_hook_token(*, artifact: GuardArtifact, config: GuardConfig) -> str:
    return runtime_policy_module._runtime_hook_approval_context_token(
        artifact=artifact,
        content_hash="unchanged-runtime-content",
        runtime_workspace=config.workspace,
        action_envelope=None,
        config=config,
        current_config_action="review",
        trusted_cli_action=None,
        untrusted_payload_action=None,
        package_action=None,
        data_flow_action=None,
        scanner_action=None,
        current_action="review",
        data_flow_signals=(),
        scanner_evidence=(),
    )


def test_runtime_hook_evaluator_policy_version_is_the_only_changed_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    artifact = GuardArtifact(
        artifact_id="codex:project:runtime-policy-version",
        name="runtime policy version fixture",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(_workspace(config) / ".codex" / "config.toml"),
        metadata={"runtime_request_summary": "display copy v1"},
    )
    saved_token = _runtime_hook_token(artifact=artifact, config=config)

    monkeypatch.setattr(product_version_module, "__version__", "999.0.0-ux-only")
    assert (
        _runtime_hook_token(
            artifact=replace(artifact, metadata={"runtime_request_summary": "display copy v2"}),
            config=_ux_only_config_change(config),
        )
        == saved_token
    )

    monkeypatch.setattr(
        runtime_policy_module,
        "_RUNTIME_HOOK_EVALUATOR_POLICY_VERSION",
        "runtime-hook-evaluation-v2-test",
    )
    _assert_only_policy_component_changed(
        saved_token,
        _runtime_hook_token(artifact=artifact, config=config),
    )


def _generic_hook_token(*, config: GuardConfig, payload: dict[str, object]) -> str:
    return generic_hook_module._generic_hook_approval_context_token(
        action_envelope=None,
        artifact_id="generic:project:policy-version",
        artifact_name="generic policy version fixture",
        config=config,
        current_action="review",
        current_config_action="review",
        daemon_hint_disposition=None,
        daemon_hint_reason_code=None,
        daemon_status=None,
        fail_mode=None,
        harness="generic-test",
        payload=payload,
        publisher=None,
        runtime_workspace=config.workspace,
        trusted_cli_action=None,
        untrusted_payload_action=None,
        untrusted_payload_action_disposition=None,
        untrusted_payload_action_reason=None,
    )


def test_generic_hook_evaluator_policy_version_is_the_only_changed_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    payload: dict[str, object] = {
        "hook_event_name": "OpaqueHookEvent",
        "tool_name": "opaque_tool",
        "tool_input": {"target": "unchanged"},
        "approval_delivery": {"ui_contract_version": "v1"},
    }
    saved_token = _generic_hook_token(config=config, payload=payload)

    monkeypatch.setattr(product_version_module, "__version__", "999.0.0-ux-only")
    assert (
        _generic_hook_token(
            config=_ux_only_config_change(config),
            payload={**payload, "approval_delivery": {"ui_contract_version": "v2"}},
        )
        == saved_token
    )

    monkeypatch.setattr(
        generic_hook_module,
        "_GENERIC_HOOK_EVALUATOR_POLICY_VERSION",
        "generic-hook-evaluation-v2-test",
    )
    _assert_only_policy_component_changed(
        saved_token,
        _generic_hook_token(config=config, payload=payload),
    )


def _tool_call_token(*, artifact: GuardArtifact, config: GuardConfig) -> str:
    assert config.workspace is not None
    return mcp_tool_calls_module.build_tool_call_hash(
        artifact,
        {"command": "rm unchanged-target"},
        workspace=config.workspace,
        config=config,
    )


def test_mcp_tool_call_evaluator_policy_version_is_the_only_changed_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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

    monkeypatch.setattr(
        mcp_tool_calls_module,
        "_MCP_TOOL_CALL_EVALUATOR_POLICY_VERSION",
        "mcp-tool-call-evaluation-v2-test",
    )
    _assert_only_policy_component_changed(
        saved_token,
        _tool_call_token(artifact=artifact, config=config),
    )


def _sensitive_read_token(*, artifact: GuardArtifact, config: GuardConfig) -> str:
    return stdio_module.build_sensitive_read_approval_hash(
        artifact,
        config=config,
        cwd=config.workspace,
        current_action="review",
    )


def test_stdio_sensitive_read_evaluator_policy_version_is_the_only_changed_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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

    monkeypatch.setattr(
        stdio_module,
        "_STDIO_SENSITIVE_READ_EVALUATOR_POLICY_VERSION",
        "stdio-sensitive-read-evaluation-v2-test",
    )
    _assert_only_policy_component_changed(
        saved_token,
        _sensitive_read_token(artifact=artifact, config=config),
    )
