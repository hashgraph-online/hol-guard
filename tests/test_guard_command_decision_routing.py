"""Compatibility and evidence tests for command decision routing."""

from __future__ import annotations

from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime import command_extension_interaction, secret_file_requests
from codex_plugin_scanner.guard.runtime.command_decision_adapter import extension_evidence_batch
from codex_plugin_scanner.guard.runtime.command_evaluation import CommandDecisionFloor, evaluate_command
from codex_plugin_scanner.guard.runtime.command_extension_observations import (
    CommandExtensionObservation,
    observe_command_extensions,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.command_matcher_contracts import MatcherEvidence
from codex_plugin_scanner.guard.runtime.command_model import CanonicalCommand, parse_shell_command
from codex_plugin_scanner.guard.runtime.command_risk_effects import COMMAND_RISK_EFFECTS
from codex_plugin_scanner.guard.runtime.command_rules import (
    CommandRuleMode,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
)
from codex_plugin_scanner.guard.runtime.effect_contract import DecisionBasis, EffectKind, UncertaintyKind
from codex_plugin_scanner.guard.runtime.effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    EffectDecision,
    EffectDecisionRequest,
    evaluate_effect_decision,
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


class _LeakingMatcher:
    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        del command
        return (MatcherEvidence(0, "/private/path/test-tool", "private matcher-provided detail"),)


class _OutOfBoundsMatcher:
    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        del command
        return (MatcherEvidence(99, "test-tool", "invalid index"),)


class _SegmentMatcher:
    def __init__(self, *segment_indexes: int) -> None:
        self._segment_indexes: tuple[int, ...] = segment_indexes

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        del command
        return tuple(MatcherEvidence(index, None, "test evidence") for index in self._segment_indexes)


def _registry(
    mode: CommandRuleMode,
    *,
    action_classes: tuple[str, ...] = (),
    compatibility_fallback: bool = False,
    required: bool = False,
    risk_classes: tuple[str, ...] = ("destructive_shell",),
    severity: CommandRuleSeverity = "high",
    matcher: object | None = None,
    safe_variants: tuple[CommandSafeVariant, ...] = (),
) -> CommandSafetyExtensionRegistry:
    rule = CommandSafetyRule(
        rule_id="command.test.rule",
        title="Test rule",
        description="Exercises decision routing compatibility.",
        severity=severity,
        risk_classes=risk_classes,
        action_classes=action_classes,
        safer_alternatives=("Preview the operation.",),
        default_mode=mode,
        matcher=cast(ExecutableMatcher, matcher)
        if matcher is not None
        else ExecutableMatcher(executables=frozenset({"test-tool"})),
        safe_variants=safe_variants,
        compatibility_fallback=compatibility_fallback,
    )
    extension = CommandSafetyExtension(
        extension_id="command.test",
        version="1.0.0",
        name="Test extension",
        description="Exercises decision routing compatibility.",
        action_classes=action_classes,
        risk_classes=risk_classes,
        safer_alternatives=("Preview the operation.",),
        rules=(rule,),
        required=required,
    )
    return CommandSafetyExtensionRegistry((extension,))


@pytest.mark.parametrize(
    ("mode", "expected_legacy", "expected_plane"),
    [
        ("disabled", "allow", "review"),
        ("monitor", "monitor", "review"),
        ("review", "review", "review"),
        ("enforce", "block", "block"),
        ("required", "review", "review"),
    ],
)
def test_legacy_floor_is_preserved_without_inventing_permissive_proof(
    mode: CommandRuleMode,
    expected_legacy: CommandDecisionFloor,
    expected_plane: str,
) -> None:
    evaluation = evaluate_command("test-tool target", registry=_registry(mode))
    assert evaluation.minimum_action == expected_legacy
    assert evaluation.decision_plane.action == expected_plane


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
    assert evaluation.decision_plane.action == "review"


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
    assert any(reason.reason_code == "compatibility-action" for reason in evaluation.decision_plane.reasons)


@pytest.mark.parametrize(
    ("mode", "required", "severity", "expected"),
    [
        ("disabled", False, "high", "review"),
        ("monitor", False, "high", "review"),
        ("enforce", False, "high", "block"),
        ("disabled", True, "critical", "block"),
    ],
)
def test_compatibility_fallback_preserves_its_block_floor_in_central_decision(
    mode: CommandRuleMode,
    required: bool,
    severity: CommandRuleSeverity,
    expected: CommandDecisionFloor,
) -> None:
    action_class = "compatibility fallback"
    evaluation = evaluate_command(
        "unmatched-tool target",
        compatibility_action_class=action_class,
        registry=_registry(
            mode,
            action_classes=(action_class,),
            compatibility_fallback=True,
            required=required,
            severity=severity,
            matcher=_EmptyMatcher(),
        ),
    )
    assert evaluation.minimum_action == expected
    assert evaluation.decision_plane.action == expected


def test_public_payload_contains_versions_without_raw_command_or_failure_detail() -> None:
    payload = evaluate_command("rm -rf ./private-name").to_dict()
    observations = cast(list[dict[str, object]], payload["extension_observations"])
    assert observations
    assert all(item["extension_version"] and item["rule_version"] for item in observations)
    assert "./private-name" not in repr(payload)
    assert cast(dict[str, object], payload["decision_plane"])["schema_version"] == "1.1.0"


@pytest.mark.parametrize("matcher", [_FailingMatcher(), _MalformedMatcher()])
def test_matcher_failure_becomes_typed_blocking_uncertainty(matcher: object) -> None:
    evaluation = evaluate_command(
        "test-tool target",
        registry=_registry("disabled", matcher=matcher),
    )
    assert evaluation.minimum_action == "block"
    assert evaluation.decision_plane.action == "block"
    payload = evaluation.extension_observations[0].to_dict()
    assert payload["match_class"] == "uncertainty"
    assert payload["match_classes"] == ["uncertainty"]
    assert payload["uncertainty_reasons"] == ["matcher-failure"]
    assert "private matcher detail" not in repr(evaluation.to_dict())


def test_risk_effect_mapping_does_not_use_substring_classification() -> None:
    evaluation = evaluate_command(
        "test-tool target",
        registry=_registry("review", risk_classes=("non-destructive",)),
    )
    batch = extension_evidence_batch(evaluation.command, evaluation.extension_observations)
    effect_claims = frozenset(effect for item in batch.evidence for effect in item.effect_claims)
    assert EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION not in effect_claims
    assert EffectKind.PROCESS_EXECUTION in effect_claims


@pytest.mark.parametrize(("risk_class", "expected"), tuple(COMMAND_RISK_EFFECTS.items()))
def test_extension_evidence_uses_canonical_risk_effect_mapping(
    risk_class: str,
    expected: frozenset[EffectKind],
) -> None:
    evaluation = evaluate_command(
        "test-tool target",
        registry=_registry("review", risk_classes=(risk_class,)),
    )
    batch = extension_evidence_batch(evaluation.command, evaluation.extension_observations)
    assert frozenset(effect for item in batch.evidence for effect in item.effect_claims) == expected


def test_typed_matcher_evidence_is_bounded_and_privacy_normalized() -> None:
    command = parse_shell_command("test-tool target")
    registry = _registry("review", matcher=_LeakingMatcher())
    observations = observe_command_extensions(command, registry.extensions, registry.candidate_rule_ids(command))
    payload = observations[0].to_dict()
    assert payload["matcher_evidence"] == [
        {
            "segment_index": 0,
            "executable": "test-tool",
            "detail": "Matched bounded structured command constraints.",
        }
    ]
    assert "private matcher-provided detail" not in repr(payload)
    assert "/private/path" not in repr(payload)


def test_live_request_classifier_routes_matcher_failure_through_plane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _registry("disabled", matcher=_OutOfBoundsMatcher())
    monkeypatch.setattr(secret_file_requests, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", registry)
    match = secret_file_requests.extract_sensitive_tool_action_request(
        "Shell",
        {"command": "test-tool target"},
    )
    assert match is not None
    assert match.action_class == "command extension matcher failure"
    assert "invalid index" not in match.reason


def test_matcher_failure_projection_requires_a_controlling_uncertainty_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = evaluate_effect_decision(
        EffectDecisionRequest(
            factors=(
                DecisionFactor(
                    source=DecisionFactorSource.POLICY,
                    reason_code="rule-match",
                    basis=DecisionBasis("block", None),
                    producer_ref="test:controlling-rule",
                ),
            )
        )
    )

    def fixed_decision(
        command: CanonicalCommand,
        observations: tuple[CommandExtensionObservation[CommandSafetyExtension], ...],
    ) -> EffectDecision:
        del command, observations
        return decision

    monkeypatch.setattr(command_extension_interaction, "evaluate_extension_interaction", fixed_decision)
    interaction = command_extension_interaction.classify_command_extension_interaction(
        parse_shell_command("test-tool target"),
        _registry("disabled", matcher=_FailingMatcher()),
    )
    assert interaction.priority is None
    assert interaction.fallback is None


def test_legacy_matching_projection_cannot_silence_matcher_failure() -> None:
    registry = _registry("disabled", matcher=_FailingMatcher())
    with pytest.raises(RuntimeError, match="matcher boundary failure") as captured:
        _ = registry.matching_rules(parse_shell_command("test-tool target"))
    assert "private matcher detail" not in str(captured.value)


def test_safe_variant_failure_is_scoped_to_an_owning_base_match() -> None:
    safe_variant = CommandSafeVariant("broken-safe", "Broken safe matcher", _FailingMatcher())
    evaluation = evaluate_command(
        "unrelated-tool inspect",
        registry=_registry("review", matcher=_EmptyMatcher(), safe_variants=(safe_variant,)),
    )
    assert evaluation.minimum_action == "allow"
    assert evaluation.extension_observations == ()


def test_owned_safe_variant_failure_remains_blocking_uncertainty() -> None:
    safe_variant = CommandSafeVariant("broken-safe", "Broken safe matcher", _FailingMatcher())
    evaluation = evaluate_command(
        "test-tool target",
        registry=_registry("review", safe_variants=(safe_variant,)),
    )
    assert evaluation.minimum_action == "block"
    assert evaluation.decision_plane.action == "block"


def test_failed_optional_safe_matcher_does_not_override_complete_safe_evidence() -> None:
    safe_variants = (
        CommandSafeVariant("broken-safe", "Broken safe matcher", _FailingMatcher()),
        CommandSafeVariant("proven-safe", "Proven safe matcher", _SegmentMatcher(0)),
    )
    evaluation = evaluate_command(
        "test-tool target",
        registry=_registry("review", safe_variants=safe_variants),
    )
    assert evaluation.extension_observations[0].uncertainty_reasons == ()
    assert evaluation.extension_observations[0].effective_evidence == ()


def test_failed_safe_matcher_remains_uncertain_when_safe_evidence_is_partial() -> None:
    safe_variants = (
        CommandSafeVariant("broken-safe", "Broken safe matcher", _FailingMatcher()),
        CommandSafeVariant("partially-safe", "Partial safe matcher", _SegmentMatcher(0)),
    )
    evaluation = evaluate_command(
        "test-tool target && other-tool target",
        registry=_registry("review", matcher=_SegmentMatcher(0, 1), safe_variants=safe_variants),
    )
    assert evaluation.extension_observations[0].uncertainty_reasons == (UncertaintyKind.MATCHER_FAILURE,)
    assert evaluation.minimum_action == "block"
    payload = evaluation.extension_observations[0].to_dict()
    assert payload["match_class"] == "uncertainty"
    assert payload["match_classes"] == ["unsafe", "uncertainty"]


def test_rule_versions_are_stable_and_serialized() -> None:
    rule = _registry("review").extensions[0].rules[0]
    assert rule.to_dict()["rule_version"] == "1.0.0"
    with pytest.raises(ValueError, match="invalid rule version"):
        _ = CommandSafetyRule(
            rule_id="command.test.invalid",
            title="Invalid version",
            description="Exercises version validation.",
            severity="high",
            risk_classes=("test_risk",),
            action_classes=(),
            safer_alternatives=("Review the operation.",),
            matcher=_EmptyMatcher(),
            rule_version="01.0.0",
        )
