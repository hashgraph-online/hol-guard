"""Registry validation, indexing, and monotonic command decision tests."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import (
    CommandDecisionFloor,
    evaluate_command,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    CommandExtensionSource,
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_rules import (
    CommandRuleMode,
    CommandRuleSeverity,
    CommandSafetyRule,
    ExecutableMatcher,
)


def _test_rule(
    rule_id: str,
    *,
    executable: str,
    severity: CommandRuleSeverity = "high",
    default_mode: CommandRuleMode = "review",
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title="Test rule",
        description="Test registry behavior.",
        severity=severity,
        risk_classes=("test_risk",),
        action_classes=(),
        safer_alternatives=("Preview the operation.",),
        default_mode=default_mode,
        matcher=ExecutableMatcher(executables=frozenset({executable})),
    )


def _test_extension(
    extension_id: str,
    *,
    rule: CommandSafetyRule,
    required: bool = False,
    source: CommandExtensionSource = "built-in",
    aliases: tuple[str, ...] = (),
    dependencies: tuple[str, ...] = (),
    conflicts: tuple[str, ...] = (),
) -> CommandSafetyExtension:
    return CommandSafetyExtension(
        extension_id=extension_id,
        version="1.0.0",
        name="Test extension",
        description="Test registry behavior.",
        action_classes=(),
        risk_classes=("test_risk",),
        safer_alternatives=("Preview the operation.",),
        rules=(rule,),
        required=required,
        source=source,
        aliases=aliases,
        dependencies=dependencies,
        conflicts=conflicts,
    )


def test_command_extension_registry_validates_relationships_and_aliases() -> None:
    base = _test_extension(
        "command.base",
        rule=_test_rule("command.base.rule", executable="base-tool"),
        aliases=("command.legacy-base",),
    )
    dependent = _test_extension(
        "command.dependent",
        rule=_test_rule("command.dependent.rule", executable="dependent-tool"),
        dependencies=("command.base",),
    )
    registry = CommandSafetyExtensionRegistry((dependent, base))

    assert registry.get("command.legacy-base") is base
    assert [extension.extension_id for extension in registry.extensions] == ["command.base", "command.dependent"]

    unknown_dependency = _test_extension(
        "command.unknown-dependency",
        rule=_test_rule("command.unknown-dependency.rule", executable="unknown-tool"),
        dependencies=("command.missing",),
    )
    with pytest.raises(ValueError, match="unknown dependency"):
        CommandSafetyExtensionRegistry((unknown_dependency,))

    conflict = _test_extension(
        "command.conflict",
        rule=_test_rule("command.conflict.rule", executable="conflict-tool"),
        conflicts=("command.base",),
    )
    with pytest.raises(ValueError, match="conflicts with"):
        CommandSafetyExtensionRegistry((base, conflict))


def test_command_extension_registry_rejects_dependency_cycles_and_untrusted_required_sources() -> None:
    first = _test_extension(
        "command.first",
        rule=_test_rule("command.first.rule", executable="first-tool"),
        dependencies=("command.second",),
    )
    second = _test_extension(
        "command.second",
        rule=_test_rule("command.second.rule", executable="second-tool"),
        dependencies=("command.first",),
    )
    with pytest.raises(ValueError, match="dependency cycle"):
        CommandSafetyExtensionRegistry((first, second))

    untrusted_required = _test_extension(
        "command.external-required",
        rule=_test_rule("command.external-required.rule", executable="external-tool"),
        required=True,
        source="signed-cloud",
    )
    with pytest.raises(ValueError, match="must be built-in"):
        CommandSafetyExtensionRegistry((untrusted_required,))


def test_command_extension_registry_indexes_candidates_without_changing_order() -> None:
    alpha = _test_extension(
        "command.alpha",
        rule=_test_rule("command.alpha.rule", executable="alpha-tool"),
    )
    zeta = _test_extension(
        "command.zeta",
        rule=_test_rule("command.zeta.rule", executable="zeta-tool"),
    )
    registry = CommandSafetyExtensionRegistry((zeta, alpha))

    assert registry.candidate_rule_ids(parse_shell_command("zeta-tool run")) == ("command.zeta.rule",)
    assert registry.candidate_rule_ids(parse_shell_command("alpha-tool run && zeta-tool run")) == (
        "command.alpha.rule",
        "command.zeta.rule",
    )


def test_composite_evaluation_selects_strongest_rule_and_monotonic_floor() -> None:
    review = _test_extension(
        "command.review",
        rule=_test_rule("command.review.rule", executable="danger", severity="low", default_mode="review"),
    )
    enforce = _test_extension(
        "command.enforce",
        rule=_test_rule("command.enforce.rule", executable="danger", severity="high", default_mode="enforce"),
    )
    registry = CommandSafetyExtensionRegistry((review, enforce))

    evaluation = evaluate_command("danger target", registry=registry)

    assert [owned.match.rule.rule_id for owned in evaluation.matches] == [
        "command.enforce.rule",
        "command.review.rule",
    ]
    assert evaluation.controlling_rule_id == "command.enforce.rule"
    assert evaluation.minimum_action == "block"


@pytest.mark.parametrize(
    ("required", "severity", "default_mode", "expected_floor"),
    [
        (False, "low", "disabled", "allow"),
        (False, "low", "monitor", "monitor"),
        (False, "medium", "review", "review"),
        (False, "high", "enforce", "block"),
        (False, "critical", "required", "review"),
        (True, "high", "disabled", "review"),
        (True, "critical", "disabled", "block"),
    ],
)
def test_command_decision_floor_truth_table(
    required: bool,
    severity: CommandRuleSeverity,
    default_mode: CommandRuleMode,
    expected_floor: CommandDecisionFloor,
) -> None:
    extension = _test_extension(
        "command.floor",
        rule=_test_rule(
            "command.floor.rule",
            executable="floor-tool",
            severity=severity,
            default_mode=default_mode,
        ),
        required=required,
    )

    evaluation = evaluate_command(
        "floor-tool target",
        registry=CommandSafetyExtensionRegistry((extension,)),
    )

    assert evaluation.minimum_action == expected_floor


def test_parser_uncertainty_cannot_reduce_sensitive_evidence_below_review() -> None:
    extension = _test_extension(
        "command.uncertain",
        rule=_test_rule(
            "command.uncertain.rule",
            executable="uncertain-tool",
            default_mode="disabled",
        ),
    )

    evaluation = evaluate_command(
        "uncertain-tool '",
        registry=CommandSafetyExtensionRegistry((extension,)),
    )

    assert evaluation.command.confidence == "fallback"
    assert evaluation.minimum_action == "review"
