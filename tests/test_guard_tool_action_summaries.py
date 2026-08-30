"""Focused coverage for native tool-action review explanations."""

from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)


def test_destructive_tool_action_summary_explains_user_impact():
    request = extract_sensitive_tool_action_request(
        "bash",
        {"command": "rm -rf dangerous-marker.json"},
    )

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "opencode",
        request,
        config_path="opencode.json",
        source_scope="project",
    )

    expected_summary = (
        "This destructive shell command can delete or overwrite local files, discard work, or alter "
        "repository or system state. "
        "Recovery may require version control or a backup."
    )
    assert artifact.metadata["runtime_request_summary"] == expected_summary
    assert artifact.metadata["runtime_request_signals"] == [expected_summary]


def test_non_destructive_tool_action_summary_preserves_specific_classifier_reason():
    request = extract_sensitive_tool_action_request(
        "bash",
        {"command": "kubectl get secret app-credentials -o yaml"},
    )

    assert request is not None
    artifact = build_tool_action_request_artifact(
        "opencode",
        request,
        config_path="opencode.json",
        source_scope="project",
    )

    summary = str(artifact.metadata["runtime_request_summary"])
    assert "expose cluster credentials or application secrets" in summary
    assert "Sensitive native tool action (Kubernetes secret read command)" in summary
    assert artifact.metadata["runtime_request_signals"] == [summary]
