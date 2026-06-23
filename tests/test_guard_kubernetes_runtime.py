"""Kubernetes runtime secret-read coverage for Guard hooks."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _codex_post_tool_output_artifact
from codex_plugin_scanner.guard.runtime.kubernetes_commands import kubernetes_secret_read_source
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_kubectl_exec_sensitive_printenv_is_pre_execution_secret_read(tmp_path: Path) -> None:
    command = (
        "kubectl exec -n registry-broker registry-frontend-7fb9bf6b46-2fcj8 -- printenv GUARD_GITHUB_APP_PRIVATE_KEY"
    )

    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert request is not None
    assert request.action_class == "Kubernetes secret read command"
    assert kubernetes_secret_read_source(command) == "Kubernetes pod environment"
    assert (
        kubernetes_secret_read_source(
            "kubectl exec -n registry-broker registry-frontend-7fb9bf6b46-2fcj8 printenv GUARD_GITHUB_APP_PRIVATE_KEY"
        )
        == "Kubernetes pod environment"
    )
    assert kubernetes_secret_read_source("kubectl exec pod -- printenv PATH") is None


def test_kubectl_secret_reads_are_detected_in_command_substitutions(tmp_path: Path) -> None:
    command = "PK=$(kubectl exec -n registry-broker registry-frontend -- printenv GUARD_GITHUB_APP_PRIVATE_KEY)"

    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert request is not None
    assert request.action_class == "Kubernetes secret read command"
    assert kubernetes_secret_read_source("kubectl get secret registry-frontend -o yaml") == "Kubernetes Secret resource"
    assert kubernetes_secret_read_source("kubectl get po,secret -A -o yaml") == "Kubernetes Secret resource"
    assert kubernetes_secret_read_source("kubectl get secrets.v1 -A -o yaml") == "Kubernetes Secret resource"
    assert (
        kubernetes_secret_read_source("kubectl get --raw /api/v1/namespaces/default/secrets/registry-frontend")
        == "Kubernetes Secret resource"
    )
    assert kubernetes_secret_read_source("kubectl get pods -n registry-broker") is None


def test_kubectl_exec_shell_expansion_secret_reads_are_detected(tmp_path: Path) -> None:
    command = "kubectl exec registry-frontend -- sh -c 'echo \"$GUARD_GITHUB_APP_PRIVATE_KEY\"'"

    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert request is not None
    assert request.action_class == "Kubernetes secret read command"
    assert kubernetes_secret_read_source(command) == "Kubernetes pod environment"
    assert kubernetes_secret_read_source("oc rsh registry-frontend printenv GUARD_GITHUB_APP_PRIVATE_KEY") == (
        "Kubernetes pod environment"
    )
    python_env_command = (
        "kubectl exec registry-frontend -- python -c 'import os; print(os.environ[\"GUARD_GITHUB_APP_PRIVATE_KEY\"])'"
    )
    assert kubernetes_secret_read_source(python_env_command) == "Kubernetes pod environment"


def test_kubectl_exec_secret_volume_readers_are_detected() -> None:
    commands = (
        "kubectl exec registry-frontend -- grep . /etc/secrets/api-key",
        "kubectl exec registry-frontend -- awk '{print}' /etc/secrets/token",
        "kubectl exec registry-frontend -- base64 /etc/secrets/token",
        "kubectl exec registry-frontend -- tar cf - /etc/secrets",
    )

    for command in commands:
        assert kubernetes_secret_read_source(command) == "Kubernetes secret volume"
    assert kubernetes_secret_read_source('kubectl exec registry-frontend -- sh -c "cat /etc/secrets/token"') == (
        "Kubernetes secret volume"
    )


def test_kubectl_cp_only_flags_remote_secret_volume_sources() -> None:
    assert kubernetes_secret_read_source("kubectl cp registry-frontend:/etc/secrets/token ./token") == (
        "Kubernetes secret volume"
    )
    assert kubernetes_secret_read_source("kubectl cp ./token registry-frontend:/etc/secrets/token") is None


def test_pi_pre_tool_use_blocks_kubectl_secret_printenv(tmp_path: Path, monkeypatch, capsys) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": (
                "kubectl exec -n registry-broker registry-frontend-7fb9bf6b46-2fcj8 "
                "-- printenv GUARD_GITHUB_APP_PRIVATE_KEY"
            )
        },
        "source_scope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "pi",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert output["decision"] == "deny"
    assert "kubernetes secret read command" in output["reason"].lower()


def test_pi_post_tool_output_labels_kubernetes_secret_source(tmp_path: Path) -> None:
    command = (
        "kubectl exec -n registry-broker registry-frontend-7fb9bf6b46-2fcj8 -- printenv GUARD_GITHUB_APP_PRIVATE_KEY"
    )
    artifact = _codex_post_tool_output_artifact(
        harness="pi",
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "stdout": "-----BEGIN RSA PRIVATE KEY-----\nMIIE" + ("A" * 64) + "\n-----END RSA PRIVATE KEY-----\n",
        },
        config_path="~/.pi/agent/settings.json",
        source_scope="project",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert artifact is not None
    assert artifact.metadata["action_class"] == "Kubernetes secret read command"
    assert artifact.metadata["guard_default_action"] == "require-reapproval"
    assert artifact.metadata["secret_source_family"] == "Kubernetes pod environment"


def test_pi_post_tool_output_preserves_kubernetes_secret_volume_source(tmp_path: Path) -> None:
    command = 'kubectl exec registry-frontend -- sh -c "cat /etc/secrets/token"'
    artifact = _codex_post_tool_output_artifact(
        harness="pi",
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "stdout": "-----BEGIN RSA PRIVATE KEY-----\nMIIE" + ("A" * 64) + "\n-----END RSA PRIVATE KEY-----\n",
        },
        config_path="~/.pi/agent/settings.json",
        source_scope="project",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert artifact is not None
    assert artifact.metadata["action_class"] == "Kubernetes secret read command"
    assert artifact.metadata["secret_source_family"] == "Kubernetes secret volume"
