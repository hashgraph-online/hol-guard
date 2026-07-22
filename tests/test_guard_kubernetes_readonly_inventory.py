from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.kubernetes_commands import kubernetes_read_only_inventory_args
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def test_basic_pod_name_inventory_is_explicitly_benign(tmp_path: Path) -> None:
    workspace = tmp_path / "app"
    workspace.mkdir()
    command = f"cd {workspace} && kubectl get pods -n team-a -l app=web -o jsonpath='{{.items[0].metadata.name}}' 2>&1"
    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )


@pytest.mark.parametrize(
    "args",
    (
        ["get", "pods", "-n", "team-a"],
        ["--context", "staging", "get", "deployments", "-o", "wide"],
        ["get", "services", "--all-namespaces", "-o", "name"],
        ["get", "pods", "-ojsonpath={.items[*].metadata.namespace}"],
        ["get", "nodes", "-o", "jsonpath-as-json={.items[*].status.phase}"],
    ),
)
def test_bounded_inventory_variants_are_safe(args: list[str]) -> None:
    assert kubernetes_read_only_inventory_args("kubectl", args)


@pytest.mark.parametrize(
    "command",
    (
        "kubectl get secrets -n team-a",
        "kubectl get pods -o json",
        "kubectl get configmaps -o name",
        "kubectl get pods -o jsonpath='{.items[0].spec.containers[0].env}'",
        "kubectl get pods --raw /api/v1/namespaces/team-a/secrets",
        "kubectl exec web-0 -- printenv",
        "kubectl create token default",
        "kubectl delete pod web-0",
        "kubectl apply -f deployment.yaml",
        "kubectl get pods && kubectl delete pod web-0",
        "kubectl get pods > inventory.txt",
        "PATH=/tmp/untrusted:$PATH kubectl get pods",
        "kubectl get pods $(touch marker)",
    ),
)
def test_sensitive_or_effectful_variants_are_not_benign(command: str) -> None:
    assert not is_explicitly_benign_tool_action_request("bash", {"command": command})


@pytest.mark.parametrize(
    "command",
    (
        "kubectl get secrets -n team-a",
        "kubectl exec web-0 -- printenv",
        "kubectl create token default",
        "kubectl delete pod web-0",
    ),
)
def test_risky_variants_keep_sensitive_runtime_classification(command: str) -> None:
    assert extract_sensitive_tool_action_request("bash", {"command": command}) is not None
