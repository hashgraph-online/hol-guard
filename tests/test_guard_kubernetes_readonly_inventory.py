from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.kubernetes_commands import kubernetes_read_only_inventory_args
from tests.native_command_test_support import extract_sensitive_tool_action_request_native_test


@pytest.mark.parametrize(
    "args",
    (
        ["get", "pods", "-n", "team-a"],
        ["--context", "staging", "get", "deployments", "-o", "wide"],
        ["get", "services", "--all-namespaces", "-o", "name"],
        ["get", "pod/worker-0", "pod/worker-1", "-o", "name"],
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
        "kubectl exec web-0 -- printenv",
        "kubectl create token default",
        "kubectl delete pod web-0",
    ),
)
def test_risky_variants_keep_sensitive_runtime_classification(command: str) -> None:
    assert extract_sensitive_tool_action_request_native_test("bash", {"command": command}) is not None
