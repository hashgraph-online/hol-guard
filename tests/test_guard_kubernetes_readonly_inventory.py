from __future__ import annotations

import pytest

from tests.native_command_test_support import extract_sensitive_tool_action_request_native_test


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
