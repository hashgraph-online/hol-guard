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
    assert (
        kubernetes_secret_read_source("kubectl get --raw '/api/v1/namespaces/default/secrets?limit=1'")
        == "Kubernetes Secret resource"
    )
    assert kubernetes_secret_read_source("kubectl get --raw /api/v1/namespaces/default/secrets#x") == (
        "Kubernetes Secret resource"
    )
    assert kubernetes_secret_read_source("kubectl get --chunk-size 500 secrets -A -o yaml") == (
        "Kubernetes Secret resource"
    )
    assert kubernetes_secret_read_source("kubectl get --raw /api/v1/namespaces/default/configmaps/secret/foo") is None
    assert kubernetes_secret_read_source("kubectl get pods -n registry-broker") is None
    assert kubernetes_secret_read_source("kubectl create token default") == "Kubernetes service-account token"


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
    assert kubernetes_secret_read_source(
        "kubectl exec --context prod registry-frontend -- printenv GUARD_GITHUB_APP_PRIVATE_KEY"
    ) == ("Kubernetes pod environment")
    assert kubernetes_secret_read_source(
        'kubectl exec registry-frontend -- bash -c "env | grep GUARD_GITHUB_APP_PRIVATE_KEY"'
    ) == ("Kubernetes pod environment")
    python_env_command = (
        "kubectl exec registry-frontend -- python -c 'import os; print(os.environ[\"GUARD_GITHUB_APP_PRIVATE_KEY\"])'"
    )
    assert kubernetes_secret_read_source(python_env_command) == "Kubernetes pod environment"
    python_environ_get_command = (
        "kubectl exec registry-frontend -- python -c "
        "'import os; print(os.environ.get(\"GUARD_GITHUB_APP_PRIVATE_KEY\"))'"
    )
    assert kubernetes_secret_read_source(python_environ_get_command) == "Kubernetes pod environment"
    python_stdin_command = (
        "kubectl exec registry-frontend -- python - <<'PY'\n"
        "import os\n"
        'print(os.environ["GUARD_GITHUB_APP_PRIVATE_KEY"])\n'
        "PY"
    )
    assert kubernetes_secret_read_source(python_stdin_command) == "Kubernetes pod environment"


def test_kubectl_exec_secret_volume_readers_are_detected() -> None:
    commands = (
        "kubectl exec registry-frontend -- grep . /etc/secrets/api-key",
        "kubectl exec registry-frontend -- awk '{print}' /etc/secrets/token",
        "kubectl exec registry-frontend -- base64 /etc/secrets/token",
        "kubectl exec registry-frontend -- tar cf - /etc/secrets",
        "kubectl exec registry-frontend -- dd if=/etc/secrets/token of=/tmp/x",
        "kubectl exec registry-frontend -- cp --target-directory /tmp /etc/secrets/token",
        "kubectl exec registry-frontend -- grep --file=/etc/secrets/token /tmp/file",
        "kubectl exec registry-frontend -- cat /mnt/secrets-store/token",
    )

    for command in commands:
        assert kubernetes_secret_read_source(command) == "Kubernetes secret volume"
    assert kubernetes_secret_read_source('kubectl exec registry-frontend -- sh -c "cat /etc/secrets/token"') == (
        "Kubernetes secret volume"
    )
    shell_stdin_command = "kubectl exec registry-frontend -- sh <<'SH'\necho \"$GUARD_GITHUB_APP_PRIVATE_KEY\"\nSH"
    assert kubernetes_secret_read_source(shell_stdin_command) == "Kubernetes pod environment"
    assert kubernetes_secret_read_source("kubectl exec registry-frontend -- cat /etc/secrets-backup/token") is None


def test_kubectl_cp_only_flags_remote_secret_volume_sources() -> None:
    assert kubernetes_secret_read_source("kubectl cp registry-frontend:/etc/secrets/token ./token") == (
        "Kubernetes secret volume"
    )
    assert kubernetes_secret_read_source("kubectl cp --context prod registry-frontend:/etc/secrets/token ./token") == (
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


def test_local_interpreter_heredoc_after_kubectl_exec_is_not_mislabeled() -> None:
    command = (
        "kubectl exec registry-frontend -- true\n"
        "python - <<'PY'\n"
        "import os\n"
        'print(os.environ["GUARD_GITHUB_APP_PRIVATE_KEY"])\n'
        "PY"
    )

    assert kubernetes_secret_read_source(command) is None


def test_non_interpreter_kubectl_heredoc_is_not_mislabeled() -> None:
    command = (
        "kubectl exec registry-frontend -- true python - <<'PY'\n"
        "import os\n"
        'print(os.environ["GUARD_GITHUB_APP_PRIVATE_KEY"])\n'
        "PY"
    )

    assert kubernetes_secret_read_source(command) is None


def test_only_later_kubernetes_heredoc_secret_is_detected() -> None:
    command = (
        "kubectl exec registry-frontend -- python - <<'PY1'\n"
        "print('safe')\n"
        "PY1\n"
        "kubectl exec registry-frontend -- python - <<'PY2'\n"
        "import os\n"
        'print(os.environ["GUARD_GITHUB_APP_PRIVATE_KEY"])\n'
        "PY2"
    )

    assert kubernetes_secret_read_source(command) == "Kubernetes pod environment"
