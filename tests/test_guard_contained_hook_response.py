"""A required execution profile never becomes direct execution permission."""

from __future__ import annotations

from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker_responses import harness_json_from_native_pre_tool


def result() -> dict[str, object]:
    return {
        "schema": "guard-pre-tool-result.v1",
        "authority": "rust",
        "minimum_action": "sandbox-required",
        "policy_action": "sandbox-required",
        "decision": "deny",
        "reason_code": "native_pytest_readonly_containment_required",
        "command_extensions": {
            "binding": {"uncertainty_count": 0},
            "evaluation_error": None,
            "observations": [],
            "permission_observations": [],
        },
    }


def test_profile_requirement_remains_denied_for_original_input() -> None:
    response = harness_json_from_native_pre_tool("omp", result())
    assert response["decision"] == "deny"
    assert response["policy_action"] == "sandbox-required"
    assert response["required_execution_profile"] == "pytest-readonly-v2"
    assert "approval_request_id" not in response


def test_node_profile_requirement_is_distinct_and_still_denied() -> None:
    native = result()
    native["reason_code"] = "native_node_test_readonly_containment_required"
    response = harness_json_from_native_pre_tool("omp", native)
    assert response["decision"] == "deny"
    assert response["required_execution_profile"] == "node-test-readonly-v1"
    assert "approval_request_id" not in response


def test_package_test_routing_is_not_unprotected_execution_permission() -> None:
    native = result()
    native["reason_code"] = "native_package_test_readonly_containment_required"
    response = harness_json_from_native_pre_tool("omp", native)
    assert response["decision"] == "deny"
    assert response["required_execution_profile"] == "package-test-readonly-v1"
    assert "approval_request_id" not in response


@pytest.mark.parametrize("runtime", ["python", "node"])
def test_inline_eval_requires_its_own_enforced_profile(runtime) -> None:
    native = result()
    native["reason_code"] = f"native_{runtime}_eval_readonly_containment_required"
    response = harness_json_from_native_pre_tool("omp", native)
    assert response["decision"] == "deny"
    assert response["required_execution_profile"] == f"{runtime}-eval-readonly-v1"
    assert "approval_request_id" not in response


@pytest.mark.parametrize("permission", ["package-protection", "other"])
def test_vitest_profile_accepts_only_known_package_control_evidence(permission: str) -> None:
    native = result()
    native["reason_code"] = "native_vitest_readonly_containment_required"
    native["command_extensions"]["permission_observations"] = [
        {
            "extension_id": "command.package.node",
            "permission_id": f"command.package.node.permission.{permission}",
            "uncertainty_reasons": [],
        }
    ]
    response = harness_json_from_native_pre_tool("omp", native)
    if permission == "package-protection":
        assert response["required_execution_profile"] == "vitest-readonly-v1"
    else:
        assert "required_execution_profile" not in response


@pytest.mark.parametrize("action", ("block", "review", "require-reapproval", "allow", "warn"))
def test_other_policy_actions_cannot_delegate_to_test_runner(action: str) -> None:
    native = result()
    native["minimum_action"] = action
    native["policy_action"] = action
    native["decision"] = "allow" if action in {"allow", "warn"} else "deny"
    assert "required_execution_profile" not in harness_json_from_native_pre_tool("omp", native)


@pytest.mark.parametrize("broken", ("missing", "uncertain", "error", "rule", "permission"))
def test_missing_or_independent_extension_control_decisions_cannot_delegate(broken: str) -> None:
    native = deepcopy(result())
    extensions = native["command_extensions"]
    assert isinstance(extensions, dict)
    if broken == "missing":
        del native["command_extensions"]
    elif broken == "uncertain":
        extensions["binding"] = {"uncertainty_count": 1}
    elif broken == "error":
        extensions["evaluation_error"] = "failed"
    elif broken == "rule":
        extensions["observations"] = [{"minimum_action": "review"}]
    else:
        extensions["permission_observations"] = [{"minimum_action": "review"}]
    response = harness_json_from_native_pre_tool("omp", native)
    assert response["decision"] == "deny"
    assert "required_execution_profile" not in response


def test_unsupported_harness_never_receives_a_delegation_hint() -> None:
    for harness in ("pi", "claude-code"):
        assert "required_execution_profile" not in harness_json_from_native_pre_tool(harness, result())


def test_zcode_receipt_stays_denied_until_bridge_rewrites_input() -> None:
    response = harness_json_from_native_pre_tool("zcode", result())
    assert response["decision"] == "deny"
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert response["required_execution_profile"] == "pytest-readonly-v2"
