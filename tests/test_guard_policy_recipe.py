from __future__ import annotations

import copy

import pytest

from codex_plugin_scanner.guard.policy_recipe import (
    evaluate_policy_recipe_fixture,
    parse_policy_recipe,
    policy_recipe_sha256,
)


def _recipe() -> dict[str, object]:
    return {
        "schemaVersion": "guard-policy-recipe/v1",
        "id": "GPR-001",
        "slug": "review-secret-file-reads",
        "title": "Review secret-file reads",
        "summary": "Require review before supported agents read common local secret files.",
        "action": "review",
        "matcher": {"kind": "path", "value": ".env"},
        "templateId": "require-approval-secret-reads",
        "risk": "critical",
        "threatSlugs": ["secret-exfiltration"],
        "limitations": ["Path matching is surface-specific and does not replace operating-system access controls."],
        "tests": [
            {"label": "matching synthetic case", "matcherKind": "path", "value": ".env", "expected": "review"},
            {
                "label": "different benign synthetic case",
                "matcherKind": "path",
                "value": "benign-.env",
                "expected": "unmatched",
            },
        ],
        "emergencyEligible": True,
        "reviewedAt": "2026-08-09",
    }


def test_policy_recipe_parses_and_safe_fixtures_pass() -> None:
    raw = _recipe()
    recipe = parse_policy_recipe(raw)
    assert recipe.recipe_id == "GPR-001"
    assert [evaluate_policy_recipe_fixture(recipe, fixture) for fixture in recipe.tests] == ["review", "unmatched"]
    assert len(policy_recipe_sha256(raw)) == 64


def test_policy_recipe_rejects_unknown_fields() -> None:
    raw = _recipe()
    raw["rawPrompt"] = "secret"
    with pytest.raises(ValueError, match="unsupported fields"):
        parse_policy_recipe(raw)


@pytest.mark.parametrize(
    "matcher_value",
    ["*", "secret?", "[abc]", "{foo,bar}", "@(safe|unsafe)", "+(safe|unsafe)", "!(unsafe)"],
)
def test_policy_recipe_rejects_wildcard_matchers(matcher_value: str) -> None:
    raw = _recipe()
    raw["matcher"] = {"kind": "path", "value": matcher_value}
    with pytest.raises(ValueError, match="wildcard"):
        parse_policy_recipe(raw)


def test_policy_recipe_rejects_a_fixture_that_does_not_match_expected_behavior() -> None:
    raw = _recipe()
    tests = copy.deepcopy(raw["tests"])
    assert isinstance(tests, list) and isinstance(tests[0], dict)
    tests[0]["expected"] = "allow"
    raw["tests"] = tests
    with pytest.raises(ValueError, match="matching fixture"):
        parse_policy_recipe(raw)


def test_policy_recipe_rejects_an_invalid_calendar_date() -> None:
    raw = _recipe()
    raw["reviewedAt"] = "2026-99-99"
    with pytest.raises(ValueError, match="valid YYYY-MM-DD"):
        parse_policy_recipe(raw)


def test_policy_recipe_requires_positive_and_negative_fixtures() -> None:
    raw = _recipe()
    raw["tests"] = [
        {"label": "first miss", "matcherKind": "path", "value": "one", "expected": "unmatched"},
        {"label": "second miss", "matcherKind": "path", "value": "two", "expected": "unmatched"},
    ]
    with pytest.raises(ValueError, match="matching fixture"):
        parse_policy_recipe(raw)

    raw = _recipe()
    raw["tests"] = [
        {"label": "first match", "matcherKind": "path", "value": ".env", "expected": "review"},
        {"label": "second match", "matcherKind": "path", "value": ".env", "expected": "review"},
    ]
    with pytest.raises(ValueError, match="duplicate"):
        parse_policy_recipe(raw)


def test_policy_recipe_is_inert_and_has_no_apply_or_command_fields() -> None:
    serialized_keys = set(_recipe())
    assert "apply" not in serialized_keys
    assert "command" not in serialized_keys
    assert "workspace" not in serialized_keys
    assert "token" not in serialized_keys
