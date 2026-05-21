"""Phase 14 runtime action contract regressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.actions import (
    GuardActionEnvelope,
    normalize_codex_hook_payload,
    normalize_harness_payload,
    stable_action_hash,
)


def _package_payload(command: str) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


def test_phase14_action_contract_round_trips_package_intent_fields() -> None:
    envelope = GuardActionEnvelope(
        schema_version=1,
        action_id="action-123",
        harness="codex",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace="/workspace/demo",
        workspace_hash="workspace-hash",
        tool_name="Bash",
        command="npm install minimist@1.2.8",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=("package.json",),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager="npm",
        package_name="minimist",
        package_intent_kind="install",
        package_targets=("minimist@1.2.8",),
        pre_execution_result="require-reapproval",
        script_name=None,
        raw_payload_redacted={"tool_name": "Bash"},
    )

    payload = envelope.to_dict()
    restored = GuardActionEnvelope.from_dict(payload)

    assert payload["package_intent_kind"] == "install"
    assert payload["package_targets"] == ["minimist@1.2.8"]
    assert payload["pre_execution_result"] == "require-reapproval"
    assert restored == envelope


def test_normalize_codex_package_command_extracts_package_metadata(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"

    envelope = normalize_codex_hook_payload(
        _package_payload("npm install minimist@1.2.8"),
        workspace=workspace,
        home_dir=home_dir,
    )

    assert envelope.package_manager == "npm"
    assert envelope.package_name == "minimist"
    assert envelope.package_intent_kind == "install"
    assert envelope.package_targets == ("minimist@1.2.8",)
    assert envelope.pre_execution_result is None


def test_phase14_stable_action_hash_ignores_package_contract_enrichment() -> None:
    base = GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness="codex",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace=None,
        workspace_hash=None,
        tool_name="Bash",
        command="npm install minimist@1.2.8",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        package_intent_kind=None,
        package_targets=(),
        pre_execution_result=None,
        script_name=None,
        raw_payload_redacted={},
    )
    enriched = GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness="codex",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace=None,
        workspace_hash=None,
        tool_name="Bash",
        command="npm install minimist@1.2.8",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager="npm",
        package_name="minimist",
        package_intent_kind="install",
        package_targets=("minimist@1.2.8",),
        pre_execution_result="block",
        script_name=None,
        raw_payload_redacted={},
    )

    assert stable_action_hash(base) == stable_action_hash(enriched)


@pytest.mark.parametrize("harness", ["hermes", "openclaw"])
def test_phase14_normalize_managed_harness_package_hooks(tmp_path: Path, harness: str) -> None:
    envelope = normalize_harness_payload(
        harness,
        "PreToolUse",
        _package_payload("npm install minimist@1.2.8"),
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )

    assert envelope.harness == harness
    assert envelope.package_manager == "npm"
    assert envelope.package_name == "minimist"
