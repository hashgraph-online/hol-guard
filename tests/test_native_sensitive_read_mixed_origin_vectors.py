"""Mixed policy origins must retain their independent restrictions."""

from pathlib import Path

from tests.native_sensitive_read_mixed_origin_vectors import generate_vectors


def test_reciprocal_origin_floors_and_stage_boundaries_are_retained(tmp_path: Path) -> None:
    cases = generate_vectors(tmp_path)["cases"]
    assert isinstance(cases, list)
    assert len(cases) == 188
    indexed = {case["name"]: case for case in cases}
    assert len(indexed) == len(cases)
    assert {case["harness"] for case in cases} == {"codex", "claude-code", "cline", "cursor"}
    for suffix in ("local-default-block-managed-harness-allow", "local-risk-block-managed-harness-risk-allow"):
        for mode in ("enforce", "observe"):
            case = indexed[f"codex-{mode}-{suffix}"]
            assert case["expected"]["evaluatedPolicyAction"] == "block"
    for case in cases:
        assert case["localEffectivePolicy"]["unknown_publisher_action"] == "review"
        assert case["managedConfiguration"]["source_digest"]
        settings = case["configInputs"]["managed"]["settings"]
        assert case["managedConfiguration"]["default_action_present"] is ("default_action" in settings)
        expected = case["expected"]
        if case["mode"] == "observe":
            assert "finalPolicyAction" in expected and "renderedDecision" in expected
        else:
            assert "finalPolicyAction" not in expected
    absent = indexed["codex-observe-managed-risk-block-default-absent"]
    explicit = indexed["codex-observe-managed-risk-block-default-explicit-allow"]
    assert absent["expected"]["evaluatedPolicyAction"] == explicit["expected"]["evaluatedPolicyAction"] == "block"
    assert absent["expected"]["finalPolicyAction"] == "allow"
    assert explicit["expected"]["finalPolicyAction"] == "warn"
    assert absent["managedConfiguration"]["effective_policy"] == explicit["managedConfiguration"]["effective_policy"]
    assert absent["managedConfiguration"]["default_action_present"] is False
    assert explicit["managedConfiguration"]["default_action_present"] is True
