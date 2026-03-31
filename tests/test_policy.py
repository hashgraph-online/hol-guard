"""Policy profile contract tests."""

from codex_plugin_scanner.policy import POLICY_PROFILES, RuleEvaluation, evaluate_policy


def test_builtin_policy_profiles_require_core_rules() -> None:
    assert POLICY_PROFILES["default"].required_executed_rules
    assert POLICY_PROFILES["public-marketplace"].required_pass_rules
    assert POLICY_PROFILES["strict-security"].required_pass_rules


def test_public_marketplace_policy_fails_when_required_rules_do_not_pass() -> None:
    evaluation = evaluate_policy(
        (),
        "public-marketplace",
        rule_inventory={
            "PLUGIN_JSON_MISSING": RuleEvaluation(
                rule_id="PLUGIN_JSON_MISSING",
                executed=True,
                triggered=True,
                passed=False,
            )
        },
    )

    assert evaluation.policy_pass is False
    assert "PLUGIN_JSON_MISSING" in evaluation.failed_required_pass_rules
