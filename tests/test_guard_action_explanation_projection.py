from __future__ import annotations

from codex_plugin_scanner.guard.runtime.action_explanation_projection import project_action_explanation


def test_typed_file_projection_uses_safe_basename_and_never_prompt_text() -> None:
    explanation = project_action_explanation(
        {
            "schema_version": 1,
            "action_id": "action:file",
            "action_type": "file_read",
            "target_paths": ["/Users/alice/project/.env"],
            "prompt_text": "secret prompt should never be rendered",
            "command": None,
        },
        action_identity="action:file",
        actor_label="Cursor",
    )
    assert explanation is not None
    assert explanation.kind == "file_read"
    assert ".env" in explanation.everyday.summary
    assert "/Users/alice" not in explanation.everyday.summary
    assert "secret prompt" not in str(explanation.to_dict())
    assert explanation.technical.available is False
    assert explanation.technical.unavailable_reason


def test_command_projection_requires_deliberate_local_exact_disclosure() -> None:
    envelope = {
        "schema_version": 1,
        "action_id": "action:command",
        "action_type": "shell_command",
        "command": "echo sk-secret-token-value",
        "target_paths": [],
    }
    hidden = project_action_explanation(
        envelope,
        action_identity="action:command",
        actor_label="Codex",
        exact_details_authorized=False,
    )
    visible = project_action_explanation(
        envelope,
        action_identity="action:command",
        actor_label="Codex",
        exact_details_authorized=True,
    )
    assert hidden is not None and visible is not None
    assert hidden.kind == "unknown_action"
    assert hidden.confidence == "limited"
    assert hidden.technical.command_display is None
    assert hidden.technical.unavailable_reason
    assert visible.technical.available is True
    assert visible.technical.command_display is not None
    assert "sk-secret-token-value" not in visible.technical.command_display
    assert visible.redaction.secret_like_values_removed is True


def test_network_and_mcp_projections_use_typed_targets_only() -> None:
    network_input = {
        "action_id": "network:1",
        "action_type": "network_request",
        "network_hosts": ["api.example.com"],
    }
    network = project_action_explanation(
        network_input,
        action_identity="network:1",
        actor_label="Claude Code",
    )
    mcp = project_action_explanation(
        {"action_id": "mcp:1", "action_type": "mcp_tool", "mcp_server": "github", "mcp_tool": "create_issue"},
        action_identity="mcp:1",
        actor_label="Codex",
    )
    assert network is not None and network.kind == "unknown_action"
    assert network.confidence == "limited"
    assert network.uncertainty_reasons == ("network_direction_unavailable",)
    assert network.everyday.targets[0].label == f"the service {network_input['network_hosts'][0]}"
    assert mcp is not None and mcp.kind == "mcp_tool"
    assert "github / create_issue" in mcp.everyday.summary


def test_long_command_projection_truncates_within_schema_limits() -> None:
    envelope = {
        "action_id": "action:long-command",
        "action_type": "shell_command",
        "command": "echo " + ("a" * 5000),
        "target_paths": [],
    }
    explanation = project_action_explanation(
        envelope,
        action_identity="action:long-command",
        actor_label="Codex",
        exact_details_authorized=True,
    )
    assert explanation is not None
    assert explanation.technical.command_display is not None
    assert len(explanation.technical.command_display) <= 4096
    assert "technical.command_display" in explanation.redaction.truncated_fields


def test_maximum_length_network_host_stays_within_target_label_limit() -> None:
    envelope = {
        "action_id": "network:max-host",
        "action_type": "network_request",
        "network_hosts": ["h" * 253],
    }
    explanation = project_action_explanation(
        envelope,
        action_identity="network:max-host",
        actor_label="Claude Code",
    )
    assert explanation is not None
    assert len(explanation.everyday.targets[0].label) <= 240
    assert "everyday.targets.label" in explanation.redaction.truncated_fields


def test_long_mcp_names_stay_within_target_label_limit() -> None:
    envelope = {
        "action_id": "mcp:long-names",
        "action_type": "mcp_tool",
        "mcp_server": "s" * 120,
        "mcp_tool": "t" * 120,
    }
    explanation = project_action_explanation(
        envelope,
        action_identity="mcp:long-names",
        actor_label="Codex",
    )
    assert explanation is not None
    assert len(explanation.everyday.targets[0].label) <= 240
    assert "everyday.targets.label" in explanation.redaction.truncated_fields
