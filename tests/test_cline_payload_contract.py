from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.cline import ClineHarnessAdapter
from codex_plugin_scanner.guard.adapters.cline_bridge import (
    cline_control_from_guard_output,
    plugin_after_tool_replacement,
)
from codex_plugin_scanner.guard.adapters.cline_hook_payload import ClinePayloadError, normalize_cline_payload
from codex_plugin_scanner.guard.runtime.actions import action_envelope_harnesses


def test_cline_adapter_registry_aliases_and_contract() -> None:
    adapter = get_adapter("cline")
    assert isinstance(adapter, ClineHarnessAdapter)
    assert get_adapter("cline-cli") is adapter
    assert get_adapter("cline-vscode") is adapter
    assert "cline" in {item.harness for item in list_adapters()}
    assert "cline" in action_envelope_harnesses()
    contract = adapter.setup_contract()
    assert contract.display_name == "Cline"
    assert contract.surface_capabilities == ("auto", "hooks", "plugin", "cli", "all")
    assert contract.docs_path == "docs/guard/cline-local-protection-contract.md"


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "expected_type"),
    [
        ("run_commands", {"commands": ["echo ok"]}, "shell_command"),
        ("read_files", {"files": [{"path": ".env"}]}, "file_read"),
        ("editor", {"path": "src/app.py", "content": "x"}, "file_write"),
        ("apply_patch", {"patch": "*** Update File: src/app.py"}, "file_write"),
        ("use_mcp_tool", {"server_name": "demo", "tool_name": "write"}, "mcp_tool"),
        ("fetch_web_content", {"url": "https://example.invalid/data"}, "network_request"),
    ],
)
def test_cline_typed_tool_payloads_normalize(tool_name: str, tool_input: dict[str, object], expected_type: str) -> None:
    envelope = normalize_cline_payload(
        {"hookName": "PreToolUse", "tool_call": {"id": "call-1", "name": tool_name, "input": tool_input}},
        workspace="/workspace",
        home_dir="/home/test",
    )
    assert envelope.harness == "cline"
    assert envelope.event_name == "PreToolUse"
    assert envelope.action_type == expected_type


def test_cline_parallel_commands_preserve_concurrent_semantics() -> None:
    envelope = normalize_cline_payload(
        {
            "hookName": "PreToolUse",
            "tool_call": {"id": "call-1", "name": "run_commands", "input": {"commands": ["echo one", "echo two"]}},
        }
    )
    assert envelope.command == 'cline-parallel:["echo one","echo two"]'
    assert ";" not in envelope.command


def test_cline_current_and_legacy_payload_conflict_is_rejected() -> None:
    with pytest.raises(ClinePayloadError):
        normalize_cline_payload(
            {
                "hookName": "PreToolUse",
                "tool_call": {"name": "run_commands", "input": {"commands": ["echo current"]}},
                "preToolUse": {
                    "toolName": "run_commands",
                    "parameters": {"commands": json.dumps(["echo legacy"])},
                },
            }
        )


def test_cline_unknown_action_bearing_tool_fails_closed() -> None:
    with pytest.raises(ClinePayloadError):
        normalize_cline_payload(
            {
                "hookName": "PreToolUse",
                "tool_call": {"name": "future_dangerous_tool", "input": {"command": "echo hi"}},
            }
        )


def test_cline_legacy_parameter_map_decodes_json_values() -> None:
    envelope = normalize_cline_payload(
        {
            "hookName": "PreToolUse",
            "preToolUse": {
                "toolName": "read_files",
                "parameters": {"files": json.dumps([{"path": ".env"}, {"path": "README.md"}])},
            },
        }
    )
    assert ".env" in envelope.target_paths
    assert "README.md" in envelope.target_paths


def test_cline_precompact_paths_are_evidence_only(tmp_path) -> None:
    marker = tmp_path / "context.json"
    marker.write_text("secret", encoding="utf-8")
    envelope = normalize_cline_payload(
        {"hookName": "PreCompact", "preCompact": {"contextJsonPath": str(marker), "contextRawPath": str(marker)}}
    )
    assert envelope.event_name == "PreCompact"
    assert envelope.target_paths == ()


def test_native_and_plugin_bridges_fail_closed_on_unparseable_decisions() -> None:
    assert cline_control_from_guard_output("", event_name="PreToolUse")["cancel"] is True
    assert cline_control_from_guard_output("not json", event_name="PreToolUse")["cancel"] is True
    assert cline_control_from_guard_output('{"decision":"allow"}', event_name="PreToolUse")["cancel"] is False
    replacement = plugin_after_tool_replacement("not json")
    assert replacement is None
