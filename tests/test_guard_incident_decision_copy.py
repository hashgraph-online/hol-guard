"""Decision-aware regression tests for Guard incident copy."""

from __future__ import annotations

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.incident import build_incident_context
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)


@pytest.mark.parametrize(
    ("artifact_type", "changed_fields"),
    [
        ("mcp_server", ["first_seen"]),
        ("mcp_server", ["removed"]),
        ("prompt_request", ["prompt_request"]),
        ("file_read_request", ["file_read_request"]),
        ("tool_action_request", ["tool_action_request"]),
        ("package_request", ["package_request"]),
    ],
)
@pytest.mark.parametrize(("policy_action", "trigger_verb"), [("allow", "reviewed"), ("warn", "flagged")])
def test_nonblocking_incident_copy_never_claims_execution_was_stopped(
    artifact_type: str,
    changed_fields: list[str],
    policy_action: GuardAction,
    trigger_verb: str,
) -> None:
    incident = build_incident_context(
        harness="codex",
        artifact=None,
        artifact_id=f"codex:project:{artifact_type}",
        artifact_name="example",
        artifact_type=artifact_type,
        source_scope="project",
        config_path="/workspace/.codex/config.toml",
        changed_fields=changed_fields,
        policy_action=policy_action,
        launch_target="example --run",
        risk_summary="Guard reviewed the request.",
    )

    combined_copy = f"{incident['trigger_summary']} {incident['why_now']}".lower()
    assert f"hol guard {trigger_verb}" in incident["trigger_summary"].lower()
    assert "continue" in incident["why_now"].lower()
    assert all(term not in combined_copy for term in ("paused", "stopped", "blocked"))
    if policy_action == "warn":
        assert "warning" in incident["why_now"].lower()


def test_allowed_removal_is_recorded_instead_of_presented_as_a_pause() -> None:
    incident = build_incident_context(
        harness="codex",
        artifact=None,
        artifact_id="codex:project:removed-server",
        artifact_name="removed-server",
        artifact_type="mcp_server",
        source_scope="project",
        config_path="/workspace/.codex/config.toml",
        changed_fields=["removed"],
        policy_action="allow",
        launch_target=None,
        risk_summary=None,
    )

    assert incident["trigger_summary"].startswith("HOL Guard reviewed")
    assert incident["why_now"].startswith("HOL Guard recorded")
    assert "allows the action to continue" in incident["why_now"]


def test_non_launch_skill_summary_identifies_the_reviewed_definition() -> None:
    artifact = GuardArtifact(
        artifact_id="omp:project:skill:memory-interaction",
        name="memory-interaction",
        harness="omp",
        source_scope="project",
        artifact_type="skill",
        config_path="/workspace/.omp/skills/memory-interaction/SKILL.md",
    )

    incident = build_incident_context(
        harness="omp",
        artifact=artifact,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        artifact_type=artifact.artifact_type,
        source_scope=artifact.source_scope,
        config_path=artifact.config_path,
        changed_fields=["first_seen"],
        policy_action="review",
        launch_target=None,
        risk_summary=None,
    )

    assert incident["artifact_label"] == "Skill"
    assert "memory-interaction/SKILL.md" in incident["launch_summary"]
    assert "No separate shell launch command" in incident["launch_summary"]
    assert "details were not available" not in incident["launch_summary"].lower()


def test_direct_tool_interaction_explains_why_no_launch_command_exists() -> None:
    incident = build_incident_context(
        harness="omp",
        artifact=None,
        artifact_id="omp:project:memory-interaction",
        artifact_name="memory-interaction",
        artifact_type="tool_call",
        source_scope="project",
        config_path=None,
        changed_fields=["first_seen"],
        policy_action="review",
        launch_target=None,
        risk_summary=None,
    )

    assert incident["launch_summary"] == (
        "Guard reviewed this interaction directly. No shell launch command was recorded."
    )


def test_populated_mcp_tool_call_does_not_turn_tool_name_into_shell_launch() -> None:
    artifact = build_tool_call_artifact(
        harness="omp",
        server_name="filesystem",
        tool_name="read_file",
        source_scope="project",
        config_path="/workspace/.mcp.json",
        transport="stdio",
    )

    incident = build_incident_context(
        harness="omp",
        artifact=artifact,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        artifact_type=artifact.artifact_type,
        source_scope=artifact.source_scope,
        config_path=artifact.config_path,
        changed_fields=["runtime_tool_call"],
        policy_action="review",
        launch_target=(
            'read_file {"path":"/workspace/project/README.md"} '
            "[arguments-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef]"
        ),
        risk_summary=None,
    )

    assert incident["launch_summary"] == (
        "Guard reviewed this interaction directly. No shell launch command was recorded."
    )


def test_command_bearing_native_request_keeps_command_over_generic_summary() -> None:
    request = extract_sensitive_tool_action_request(
        "bash",
        {"command": "rm -f /workspace/project/output.txt"},
    )
    assert request is not None
    artifact = build_tool_action_request_artifact(
        "copilot",
        request,
        config_path="/workspace/.github/hooks/guard.json",
        source_scope="project",
    )
    runtime_launch_target = str(artifact.metadata["request_summary"])
    artifact = replace(
        artifact,
        metadata={
            **artifact.metadata,
            "request_summary": "Guard requires approval because no command rule matched this tool action.",
        },
    )

    incident = build_incident_context(
        harness="copilot",
        artifact=artifact,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        artifact_type=artifact.artifact_type,
        source_scope=artifact.source_scope,
        config_path=artifact.config_path,
        changed_fields=["tool_action_request"],
        policy_action="require-reapproval",
        launch_target=runtime_launch_target,
        risk_summary=None,
    )

    assert incident["launch_summary"] == "Launches with `rm -f /workspace/project/output.txt`."


def test_native_raw_command_credentials_are_redacted_in_incident_copy() -> None:
    retained_tail = "retained-command-tail-" + ("x" * 180)
    raw_command = (
        f"bash -lc 'rm -f /workspace/project/output.txt --token=sk-testcredential123 --marker={retained_tail}'"
    )
    request = extract_sensitive_tool_action_request("bash", {"command": raw_command})
    assert request is not None
    assert request.raw_command_text == raw_command
    artifact = build_tool_action_request_artifact(
        "copilot",
        request,
        config_path="/workspace/.github/hooks/guard.json",
        source_scope="project",
    )

    incident = build_incident_context(
        harness="copilot",
        artifact=artifact,
        artifact_id=artifact.artifact_id,
        artifact_name=artifact.name,
        artifact_type=artifact.artifact_type,
        source_scope=artifact.source_scope,
        config_path=artifact.config_path,
        changed_fields=["tool_action_request"],
        policy_action="require-reapproval",
        launch_target=str(artifact.metadata["request_summary"]),
        risk_summary=None,
    )

    assert "sk-testcredential123" not in incident["launch_summary"]
    assert "--token=sk-*****" in incident["launch_summary"]
    assert retained_tail in incident["launch_summary"]


def test_native_raw_launch_target_is_redacted_without_truncating_command_tail() -> None:
    retained_tail = "raw-target-tail-" + ("y" * 180)
    raw_target = f"rm -f /workspace/project/output.txt --token=sk-testcredential123 --marker={retained_tail}"

    incident = build_incident_context(
        harness="copilot",
        artifact=None,
        artifact_id="copilot:project:tool-action",
        artifact_name="bash destructive shell command",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="/workspace/.github/hooks/guard.json",
        changed_fields=["tool_action_request"],
        policy_action="require-reapproval",
        launch_target=raw_target,
        risk_summary=None,
    )

    assert "sk-testcredential123" not in incident["launch_summary"]
    assert "--token=sk-*****" in incident["launch_summary"]
    assert retained_tail in incident["launch_summary"]


@pytest.mark.parametrize(
    ("policy_action", "expected_trigger", "headline_fragment"),
    [
        ("review", "HOL Guard paused", "requires review"),
        ("require-reapproval", "HOL Guard paused", "requires fresh approval"),
        ("sandbox-required", "HOL Guard paused", "approved sandbox"),
        ("block", "HOL Guard blocked", "blocks this action"),
    ],
)
def test_blocking_incident_copy_retains_enforcement_wording(
    policy_action: GuardAction,
    expected_trigger: str,
    headline_fragment: str,
) -> None:
    incident = build_incident_context(
        harness="codex",
        artifact=None,
        artifact_id="codex:project:prompt",
        artifact_name="prompt",
        artifact_type="prompt_request",
        source_scope="project",
        config_path="/workspace/.codex/config.toml",
        changed_fields=["prompt_request"],
        policy_action=policy_action,
        launch_target="read .env",
        risk_summary=None,
    )

    assert incident["trigger_summary"].startswith(expected_trigger)
    if policy_action == "block":
        assert "blocked" in incident["why_now"].lower()
        assert "paused" not in incident["why_now"].lower()
        assert "approve" not in incident["why_now"].lower()
    elif policy_action == "sandbox-required":
        assert "sandbox" in incident["why_now"].lower()
        assert "approve it" not in incident["why_now"].lower()
        assert "confirm" not in incident["why_now"].lower()
    else:
        assert "paused" in incident["why_now"].lower()
    assert headline_fragment in incident["risk_headline"].lower()


@pytest.mark.parametrize(
    ("policy_action", "artifact_type", "changed_field", "required_word"),
    [
        ("block", "file_read_request", "file_read_request", "blocked"),
        ("block", "tool_action_request", "tool_action_request", "blocked"),
        ("sandbox-required", "package_request", "package_request", "sandbox"),
        ("sandbox-required", "mcp_server", "first_seen", "sandbox"),
    ],
)
def test_terminal_action_semantics_override_special_incident_branches(
    policy_action: GuardAction,
    artifact_type: str,
    changed_field: str,
    required_word: str,
) -> None:
    incident = build_incident_context(
        harness="codex",
        artifact=None,
        artifact_id=f"codex:project:{artifact_type}",
        artifact_name="example",
        artifact_type=artifact_type,
        source_scope="project",
        config_path="/workspace/.codex/config.toml",
        changed_fields=[changed_field],
        policy_action=policy_action,
        launch_target="example --run",
        risk_summary=None,
    )

    why_now = incident["why_now"].lower()
    assert required_word in why_now
    assert "until you approve" not in why_now
    assert "until you confirm" not in why_now
