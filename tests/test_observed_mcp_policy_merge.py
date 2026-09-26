from pathlib import Path
from threading import Condition
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_publisher_inputs as inputs_module
from codex_plugin_scanner.guard.native_policy_snapshot_constants import POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS
from codex_plugin_scanner.guard.runtime import observed_mcp_tools


@pytest.mark.parametrize("configured", [
    {"codex:mcp__server__read": "block", "codex:mcp__other__write": "block"},
    {"codex:mcp__server__*": "block"},
])
def test_observed_choices_preserve_configured_restrictions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, configured: dict[str, str],
) -> None:
    inputs = inputs_module.NativePolicySnapshotPublisherInputs()
    inputs.guard_home = tmp_path
    inputs._condition = Condition()
    inputs._workspace_paths = set()
    inputs.store = SimpleNamespace()
    from codex_plugin_scanner.guard import config

    monkeypatch.setattr(config, "load_guard_config", lambda *args, **kwargs: SimpleNamespace(mode="enforce"))
    monkeypatch.setattr(inputs_module, "effective_native_policy_v3", lambda config: {})
    monkeypatch.setattr(
        inputs_module, "_merge_effective_native_policies", lambda policies: {"mcp_tool_actions": configured},
    )
    monkeypatch.setattr(observed_mcp_tools, "native_observed_mcp_tool_actions", lambda store: {
        "codex:mcp__server__read": "allow", "codex:mcp__unrelated__search": "allow",
    })
    result = inputs._compiled_effective_policy()["mcp_tool_actions"]
    assert all(result[key] == action for key, action in configured.items())
    assert result["codex:mcp__unrelated__search"] == "allow"
    assert result.get("codex:mcp__server__read") != "allow"
    assert all(action == "block" for action in configured.values())


def test_combined_action_capacity_is_deterministic_and_keeps_configured_blocks() -> None:
    configured = "codex:mcp__zz_configured__blocked"
    namespace = "codex:mcp__zz_namespace__*"
    actions = {f"codex:mcp__server__tool_{index}": "block" for index in range(1100)}
    actions[configured] = "block"
    actions[namespace] = "block"
    actions["codex:mcp__server__allowed"] = "allow"
    result = observed_mcp_tools.bound_native_mcp_tool_actions(actions, required_blocks=frozenset({configured}))
    reversed_result = observed_mcp_tools.bound_native_mcp_tool_actions(
        dict(reversed(list(actions.items()))), required_blocks=frozenset({configured}),
    )
    assert result == reversed_result
    assert len(result) == POLICY_SNAPSHOT_MAX_MCP_TOOL_ACTIONS
    assert result[configured] == result[namespace] == "block"
    assert "codex:mcp__server__allowed" not in result
