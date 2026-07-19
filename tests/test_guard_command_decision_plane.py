"""Compatibility and evidence tests for command decision-plane routing."""

from __future__ import annotations

from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.command_decision_adapter import extension_evidence_batch
from codex_plugin_scanner.guard.runtime.command_evaluation import CommandDecisionFloor, evaluate_command
from codex_plugin_scanner.guard.runtime.command_extension_observations import observe_command_extensions
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.command_matcher_contracts import MatcherEvidence
from codex_plugin_scanner.guard.runtime.command_model import CanonicalCommand, parse_shell_command
from codex_plugin_scanner.guard.runtime.command_rules import (
    CommandRuleMode,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
)


class _FailingMatcher:
    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        del command
        raise RuntimeError("private matcher detail")


class _MalformedMatcher:
    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        del command
        return cast(tuple[MatcherEvidence, ...], ("not-evidence",))


class _EmptyMatcher:
    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        del command
        return ()


def _registry(
    mode: CommandRuleMode,
    *,
    required: bool = False,
    severity: CommandRuleSeverity = "high",
) -> CommandSafetyExtensionRegistry:
    rule = CommandSafetyRule(
        rule_id="command.test.rule",
        title="Test rule",
        description="Exercises decision-plane compatibility.",
        severity=severity,
        risk_classes=("destructive_shell",),
        action_classes=(),
        safer_alternatives=("Preview the operation.",),
        default_mode=mode,
        matcher=ExecutableMatcher(executables=frozenset({"test-tool"})),
    )
    extension = CommandSafetyExtension(
        extension_id="command.test",
        version="1.0.0",
        name="Test extension",
        description="Exercises decision-plane compatibility.",
        action_classes=(),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Preview the operation.",),
        rules=(rule,),
        required=required,
    )
    return CommandSafetyExtensionRegistry((extension,))


@pytest.mark.parametrize(
    ("mode", "expected_legacy", "expected_canonical"),
    [
        ("disabled", "allow", "allow"),
        ("monitor", "monitor", "warn"),
        ("review", "review", "review"),
        ("enforce", "block", "block"),
        ("required", "review", "review"),
    ],
)
def test_legacy_mode_truth_table_is_owned_by_canonical_plane(
    mode: CommandRuleMode,
    expected_legacy: CommandDecisionFloor,
    expected_canonical: str,
) -> None:
    evaluation = evaluate_command("test-tool target", registry=_registry(mode))

    assert evaluation.minimum_action == expected_legacy
    assert evaluation.decision_plane.action == expected_canonical
    assert "extension-rule:command.test.rule" in evaluation.decision_plane.controlling_sources


def test_required_extension_floors_remain_monotonic() -> None:
    high = evaluate_command("test-tool target", registry=_registry("disabled", required=True))
    critical = evaluate_command(
        "test-tool target",
        registry=_registry("disabled", required=True, severity="critical"),
    )

    assert (high.minimum_action, high.decision_plane.action) == ("review", "review")
    assert (critical.minimum_action, critical.decision_plane.action) == ("block", "block")


def test_safe_variant_remains_visible_without_suppressing_stronger_sibling() -> None:
    evaluation = evaluate_command("git clean -nfdx && rm -rf ./build")
    force_clean = next(
        item for item in evaluation.extension_observations if item.rule.rule_id == "command.git.force-clean"
    )

    assert force_clean.matcher_evidence
    assert [item.variant_id for item in force_clean.safe_variants] == ["dry-run"]
    assert force_clean.effective_evidence == ()
    assert evaluation.minimum_action == "review"
    assert "extension-rule:command.filesystem.recursive-delete" in evaluation.decision_plane.controlling_sources
    assert evaluation.decision_plane.segment_actions == (("segment:1", "review"),)


def test_owned_safe_variant_is_preserved_in_strict_extension_evidence() -> None:
    command = parse_shell_command("git clean -nfdx")
    observations = observe_command_extensions(
        command,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.candidate_rule_ids(command),
    )
    batch = extension_evidence_batch(command, observations)
    force_clean = next(item for item in batch.evidence if item.identity.rule_id == "command.git.force-clean")

    assert force_clean.safe_variant is not None
    assert force_clean.safe_variant.safe_variant_id == "dry-run"
    assert force_clean.effective_floor is None


@pytest.mark.parametrize(
    "action_class",
    [
        "destructive shell command",
        "GitHub remote mutation command",
        "package installation command",
        "unresolved interpreter command",
    ],
)
def test_parallel_legacy_heuristics_route_through_plane(action_class: str) -> None:
    evaluation = evaluate_command(
        "routine-tool inspect",
        compatibility_action_class=action_class,
        compatibility_reason="Existing heuristic requires review.",
    )

    assert evaluation.minimum_action == "review"
    assert evaluation.decision_plane.action == "review"
    assert any(source.startswith("legacy-heuristic:") for source in evaluation.decision_plane.controlling_sources)


def test_segment_order_cannot_change_the_maximum_floor() -> None:
    first = evaluate_command("git clean -nfdx && rm -rf ./build")
    second = evaluate_command("rm -rf ./build && git clean -nfdx")

    assert first.minimum_action == second.minimum_action == "review"
    assert first.decision_plane.action == second.decision_plane.action == "review"
    assert {item.rule.rule_id for item in first.extension_observations} == {
        item.rule.rule_id for item in second.extension_observations
    }


def test_public_payload_contains_versions_and_no_raw_command() -> None:
    payload = evaluate_command("rm -rf ./private-name").to_dict()
    observations = cast(list[dict[str, object]], payload["extension_observations"])

    assert observations
    assert all(item["extension_version"] and item["rule_version"] for item in observations)
    assert "./private-name" not in repr(payload)
    assert cast(dict[str, object], payload["decision_plane"])["schema_version"] == "1.0.0"


def test_matcher_failure_becomes_typed_blocking_uncertainty() -> None:
    rule = CommandSafetyRule(
        rule_id="command.test.failure",
        title="Failing rule",
        description="Exercises failure-closed matcher handling.",
        severity="low",
        risk_classes=("test_risk",),
        action_classes=(),
        safer_alternatives=("Review the operation.",),
        default_mode="disabled",
        matcher=_FailingMatcher(),
    )
    registry = CommandSafetyExtensionRegistry(
        (
            CommandSafetyExtension(
                extension_id="command.test",
                version="1.0.0",
                name="Test extension",
                description="Exercises matcher failure handling.",
                action_classes=(),
                risk_classes=("test_risk",),
                safer_alternatives=("Review the operation.",),
                rules=(rule,),
            ),
        )
    )

    evaluation = evaluate_command("test-tool target", registry=registry)

    assert evaluation.minimum_action == "block"
    assert evaluation.decision_plane.action == "block"
    assert evaluation.extension_observations[0].to_dict()["uncertainty_reasons"] == ["matcher-failure"]
    assert "private matcher detail" not in repr(evaluation.to_dict())


def test_malformed_matcher_evidence_becomes_typed_uncertainty() -> None:
    rule = CommandSafetyRule(
        rule_id="command.test.malformed",
        title="Malformed rule",
        description="Exercises matcher boundary validation.",
        severity="low",
        risk_classes=("test_risk",),
        action_classes=(),
        safer_alternatives=("Review the operation.",),
        default_mode="disabled",
        matcher=_MalformedMatcher(),
    )
    registry = CommandSafetyExtensionRegistry(
        (
            CommandSafetyExtension(
                extension_id="command.test",
                version="1.0.0",
                name="Test extension",
                description="Exercises malformed matcher handling.",
                action_classes=(),
                risk_classes=("test_risk",),
                safer_alternatives=("Review the operation.",),
                rules=(rule,),
            ),
        )
    )

    evaluation = evaluate_command("test-tool target", registry=registry)

    assert evaluation.minimum_action == "block"
    assert evaluation.extension_observations[0].uncertainty_reasons[0].value == "matcher-failure"


def test_safe_variant_failure_is_scoped_to_an_owning_base_match() -> None:
    safe_variant = CommandSafeVariant("broken-safe", "Broken safe matcher", _FailingMatcher())
    rule = CommandSafetyRule(
        rule_id="command.test.scoped-safe",
        title="Scoped safe rule",
        description="Exercises owned safe-variant failure scoping.",
        severity="high",
        risk_classes=("test_risk",),
        action_classes=(),
        safer_alternatives=("Review the operation.",),
        matcher=_EmptyMatcher(),
        safe_variants=(safe_variant,),
    )
    extension = CommandSafetyExtension(
        extension_id="command.test",
        version="1.0.0",
        name="Test extension",
        description="Exercises owned safe-variant failure scoping.",
        action_classes=(),
        risk_classes=("test_risk",),
        safer_alternatives=("Review the operation.",),
        rules=(rule,),
    )

    evaluation = evaluate_command(
        "unrelated-tool inspect",
        registry=CommandSafetyExtensionRegistry((extension,)),
    )

    assert evaluation.minimum_action == "allow"
    assert evaluation.extension_observations == ()


def test_owned_safe_variant_failure_remains_blocking_uncertainty() -> None:
    rule = CommandSafetyRule(
        rule_id="command.test.owned-safe",
        title="Owned safe rule",
        description="Exercises matched safe-variant failure handling.",
        severity="high",
        risk_classes=("test_risk",),
        action_classes=(),
        safer_alternatives=("Review the operation.",),
        matcher=ExecutableMatcher(executables=frozenset({"test-tool"})),
        safe_variants=(CommandSafeVariant("broken-safe", "Broken safe matcher", _FailingMatcher()),),
    )
    extension = CommandSafetyExtension(
        extension_id="command.test",
        version="1.0.0",
        name="Test extension",
        description="Exercises matched safe-variant failure handling.",
        action_classes=(),
        risk_classes=("test_risk",),
        safer_alternatives=("Review the operation.",),
        rules=(rule,),
    )

    evaluation = evaluate_command("test-tool target", registry=CommandSafetyExtensionRegistry((extension,)))

    assert evaluation.minimum_action == "block"
    assert evaluation.extension_observations[0].uncertainty_reasons[0].value == "matcher-failure"


def test_successful_owned_safe_variant_covers_failed_alternative() -> None:
    executable_matcher = ExecutableMatcher(executables=frozenset({"test-tool"}))
    rule = CommandSafetyRule(
        rule_id="command.test.safe-alternatives",
        title="Safe alternatives rule",
        description="Exercises complete safe-variant coverage.",
        severity="high",
        risk_classes=("test_risk",),
        action_classes=(),
        safer_alternatives=("Review the operation.",),
        matcher=executable_matcher,
        safe_variants=(
            CommandSafeVariant("broken-safe", "Broken safe matcher", _FailingMatcher()),
            CommandSafeVariant("verified-safe", "Verified safe matcher", executable_matcher),
        ),
    )
    extension = CommandSafetyExtension(
        extension_id="command.test",
        version="1.0.0",
        name="Test extension",
        description="Exercises complete safe-variant coverage.",
        action_classes=(),
        risk_classes=("test_risk",),
        safer_alternatives=("Review the operation.",),
        rules=(rule,),
    )

    evaluation = evaluate_command("test-tool target", registry=CommandSafetyExtensionRegistry((extension,)))

    assert evaluation.minimum_action == "allow"
    assert evaluation.extension_observations[0].uncertainty_reasons == ()
    assert evaluation.extension_observations[0].safe_variants[0].variant_id == "verified-safe"


def test_compatibility_fallback_matcher_failure_has_unique_candidates() -> None:
    action_class = "test compatibility failure"
    rule = CommandSafetyRule(
        rule_id="command.test.compatibility-failure",
        title="Compatibility failure rule",
        description="Exercises compatibility fallback matcher failure.",
        severity="high",
        risk_classes=("test_risk",),
        action_classes=(action_class,),
        safer_alternatives=("Review the operation.",),
        matcher=_FailingMatcher(),
        compatibility_fallback=True,
    )
    extension = CommandSafetyExtension(
        extension_id="command.test",
        version="1.0.0",
        name="Test extension",
        description="Exercises compatibility fallback matcher failure.",
        action_classes=(action_class,),
        risk_classes=("test_risk",),
        safer_alternatives=("Review the operation.",),
        rules=(rule,),
    )

    evaluation = evaluate_command(
        "test-tool target",
        compatibility_action_class=action_class,
        registry=CommandSafetyExtensionRegistry((extension,)),
    )

    assert evaluation.minimum_action == "block"
    assert len(evaluation.decision_plane.controlling_sources) == len(set(evaluation.decision_plane.controlling_sources))
