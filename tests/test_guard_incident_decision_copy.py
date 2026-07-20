"""Decision-aware regression tests for Guard incident copy."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.incident import build_incident_context
from codex_plugin_scanner.guard.models import GuardAction


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
