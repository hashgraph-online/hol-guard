"""Keep native generic vectors tied to the actual Python outer consumer."""

from pathlib import Path

from tests.native_generic_policy_vectors import generate_vectors


def test_generic_vector_scope_retains_reciprocal_origins_and_tool_contracts(tmp_path: Path) -> None:
    cases = generate_vectors(tmp_path)["cases"]
    assert isinstance(cases, list)
    assert len(cases) == 260
    assert len({case["name"] for case in cases}) == len(cases)
    assert {case["payload"]["tool_name"] for case in cases} == {"Shell", "Bash", "shell", "exec_command"}
    assert {case["mode"] for case in cases} == {"enforce", "observe"}
    for case in cases:
        assert case["artifactId"] == f"codex:project:{case['payload']['tool_name']}"
        origin = case["managedConfiguration"]
        if origin is not None:
            assert origin["default_action_present"] is ("default_action" in case["configInputs"]["managed"]["settings"])
        expected = case["expected"]
        if case["mode"] == "observe" and expected["currentConfigAction"] not in {"allow", "warn"}:
            assert expected["finalPolicyAction"] == "allow"
            assert expected["observedPolicyAction"] == expected["currentConfigAction"]
