import pytest

from ci.native_runtime.probe_workflow_matrix import assert_admission, assert_execution, decode_events
from ci.native_runtime.workflow_matrix_cases import WorkflowCase


def test_a_blocked_positive_or_allowed_negative_cannot_be_skipped():
    cases = [WorkflowCase("read", "cat ordinary.ts"), WorkflowCase("secret", "cat .env", False)]
    with pytest.raises(AssertionError, match="skipped"):
        assert_admission(cases, [])
    with pytest.raises(AssertionError, match="read"):
        assert_admission(cases, [{"decision": "deny"}, {"decision": "deny"}])
    with pytest.raises(AssertionError, match="secret"):
        assert_admission(cases, [{"decision": "allow", "policy_action": "allow"}] * 2)
    assert_admission(cases, [{"decision": "allow", "policy_action": "warn"}, {"decision": "deny"}])


def test_live_execution_requires_every_exact_command_and_success():
    case = WorkflowCase("read", "cat ordinary.ts")
    with pytest.raises(AssertionError, match="omitted"):
        assert_execution([case], [])
    events = [
        {"type": "tool_execution_start", "args": {"command": case.command}},
        {"type": "tool_execution_end", "isError": True},
    ]
    with pytest.raises(AssertionError, match="failed"):
        assert_execution([case], events)
    events[1]["isError"] = False
    assert_execution([case], events)


@pytest.mark.parametrize("value", [None, [], "invalid"])
def test_malformed_tool_arguments_fail_as_assertions(value):
    events = [
        {"type": "tool_execution_start", "args": value},
        {"type": "tool_execution_end", "isError": False},
    ]
    with pytest.raises(AssertionError, match="malformed"):
        assert_execution([WorkflowCase("read", "cat ordinary.ts")], events)


def test_malformed_json_fails_as_an_assertion():
    with pytest.raises(AssertionError, match="malformed Pi event JSON"):
        decode_events('{"type":')


def test_protected_admission_requires_the_exact_containment_route():
    reason = "native_vitest_readonly_containment_required"
    case = WorkflowCase("vitest", "bunx vitest run", protected_reason=reason)
    result = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": reason,
        "required_execution_profile": "vitest-readonly-v1",
    }
    assert_admission([case], [result])
    for field, value in [("decision", "allow"), ("required_execution_profile", "wrong-profile")]:
        with pytest.raises(AssertionError, match="vitest"):
            assert_admission([case], [{**result, field: value}])


def test_workflow_fixture_removes_only_successful_runs(tmp_path, monkeypatch):
    from ci.native_runtime.probe_workflow_matrix import workflow_fixture

    monkeypatch.chdir(tmp_path)
    with workflow_fixture() as successful:
        assert successful.is_dir()
    assert not successful.exists()
    with pytest.raises(RuntimeError, match="cleanup uncertain"), workflow_fixture() as retained:
        raise RuntimeError("cleanup uncertain")
    assert retained.is_dir()
