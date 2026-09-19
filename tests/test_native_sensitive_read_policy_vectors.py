"""Keep native policy vectors bound to the actual Python consumer behavior."""

from pathlib import Path

from tests.native_sensitive_read_policy_vectors import generate_vectors


def test_sensitive_read_vectors_preserve_unknown_publisher_and_stage_boundaries(tmp_path: Path) -> None:
    fixture = generate_vectors(tmp_path)
    cases = fixture["cases"]
    assert isinstance(cases, list)
    assert len(cases) == 133
    assert len({case["name"] for case in cases}) == len(cases)
    assert {case["harness"] for case in cases} == {"codex", "claude-code", "cline", "cursor"}
    for case in cases:
        assert case["effectivePolicy"]["unknown_publisher_action"] == "review"
        expected = case["expected"]
        if case["mode"] == "observe":
            assert "finalPolicyAction" in expected and "renderedDecision" in expected
        else:
            assert "finalPolicyAction" not in expected
    # These values are deliberately consumer evidence, not a Python-authored
    # native result. Broad default/harness Allow does not erase sensitive risk.
    indexed = {case["name"]: case["expected"] for case in cases}
    assert indexed["codex-enforce-default-allow"]["evaluatedPolicyAction"] == "require-reapproval"
    assert indexed["codex-enforce-risk-allow"]["evaluatedPolicyAction"] == "allow"


def test_explicit_postures_use_loaded_modes_and_all_levels_keep_real_actions(tmp_path: Path) -> None:
    cases = generate_vectors(tmp_path)["cases"]
    assert isinstance(cases, list)
    indexed = {case["name"]: case for case in cases}
    for level in ("gentle", "paranoid", "custom"):
        for mode in ("enforce", "observe"):
            assert f"codex-{mode}-level-{level}" in indexed
    for posture in ("protected", "extra_careful", "watch"):
        mode = "observe" if posture == "watch" else "enforce"
        for risk in ("default", "allow", "block"):
            case = indexed[f"codex-{mode}-posture-{posture}-risk-{risk}"]
            assert case["effectivePolicy"]["protection_posture"] == posture
            if posture == "watch":
                assert "finalPolicyAction" in case["expected"]
