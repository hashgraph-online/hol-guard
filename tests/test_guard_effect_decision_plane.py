from __future__ import annotations

import itertools
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from typing import cast

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime import effect_decision_plane as effect_decision_plane_module
from codex_plugin_scanner.guard.runtime.effect_contract import (
    ContainmentRequirement,
    EffectAssessment,
    EffectBlastRadius,
    EffectConfidence,
    EffectEvidenceSource,
    EffectKind,
    EffectReversibility,
    EffectTargetScope,
    ProofRequirement,
    ProofRoute,
    UncertaintyKind,
)
from codex_plugin_scanner.guard.runtime.effect_decision_plane import (
    EFFECT_DECISION_PLANE_SCHEMA_VERSION,
    DecisionCandidate,
    DecisionDisposition,
    DecisionSourceKind,
    EffectDecisionRequest,
    EffectObservation,
    EffectProof,
    LaunchComponentKind,
    LaunchIdentityBinding,
    LaunchIdentityComponent,
    evaluate_effect_decision,
)
from codex_plugin_scanner.guard.runtime.extension_evidence import ExtensionEvidenceBatch

_READ_REQUIREMENTS = frozenset({ProofRequirement.OPERATION_AND_TARGETS, ProofRequirement.PARSER_CONFIDENCE})


def _digest(label: str, value: str = "a") -> str:
    return f"{label}-v1:{value * 64}"


def _assessment(
    *,
    kind: EffectKind = EffectKind.WORKSPACE_OR_PUBLIC_READ,
    containment: ContainmentRequirement = ContainmentRequirement.NONE,
    requirements: frozenset[ProofRequirement] = _READ_REQUIREMENTS,
    uncertainty: tuple[UncertaintyKind, ...] = (),
) -> EffectAssessment:
    confidence = EffectConfidence.STRONG if uncertainty else EffectConfidence.EXACT
    return EffectAssessment(
        kind=kind,
        target_scope=EffectTargetScope.WORKSPACE,
        reversibility=EffectReversibility.TRIVIALLY_RECOVERABLE,
        blast_radius=EffectBlastRadius.WORKSPACE,
        evidence_source=EffectEvidenceSource.PARSER,
        confidence=confidence,
        containment=containment,
        proof_requirements=requirements,
        uncertainty_reasons=uncertainty,
    )


def _proof(
    route: ProofRoute = ProofRoute.VERIFIED,
    *,
    requirements: frozenset[ProofRequirement] = _READ_REQUIREMENTS,
    launch_identity: LaunchIdentityBinding | None = None,
) -> EffectProof:
    return EffectProof(
        route=route,
        satisfied_requirements=requirements,
        launch_identity=launch_identity,
        containment_identity=_digest("containment") if route is ProofRoute.CONTAINED else None,
        capability_identity=_digest("capability") if route is ProofRoute.WORKFLOW_AUTHORIZED else None,
    )


def _observation(
    segment: int,
    *,
    policy_floor: GuardAction = "allow",
    assessment: EffectAssessment | None = None,
    proof: EffectProof | None = None,
    workflow_eligible: bool = False,
    expected_launch_identity: LaunchIdentityBinding | None = None,
) -> EffectObservation:
    return EffectObservation(
        segment_ref=f"segment:{segment}",
        effect_ref=f"effect:{segment}",
        assessment=assessment or _assessment(),
        policy_floor=policy_floor,
        proof=proof,
        workflow_authorization_eligible=workflow_eligible,
        expected_launch_identity=expected_launch_identity,
    )


def _request(
    effects: tuple[EffectObservation, ...] = (),
    *,
    candidates: tuple[DecisionCandidate, ...] = (),
    uncertainties: tuple[UncertaintyKind, ...] = (),
) -> EffectDecisionRequest:
    return EffectDecisionRequest(
        effects=effects,
        extension_evidence=ExtensionEvidenceBatch(()),
        candidates=candidates,
        uncertainties=uncertainties,
    )


def _launch_binding() -> LaunchIdentityBinding:
    kinds = tuple(LaunchComponentKind)
    return LaunchIdentityBinding(
        command_security_identity=f"command-security-v2:{'c' * 64}",
        working_directory_identity=_digest("cwd"),
        components=tuple(
            LaunchIdentityComponent(
                kind=kind,
                component_ref=f"component:{index}",
                input_identity=_digest("input", format(index % 16, "x")),
                resolved_identity=_digest("resolved", format((index + 1) % 16, "x")),
            )
            for index, kind in enumerate(kinds)
        ),
    )


def test_empty_or_incomplete_input_fails_closed_to_review() -> None:
    empty = evaluate_effect_decision(_request())
    incomplete = evaluate_effect_decision(_request((_observation(0),)))

    assert empty.action == "review"
    assert empty.disposition is DecisionDisposition.REVIEW
    assert empty.controlling_sources == ("uncertainty:empty",)
    assert incomplete.action == "review"
    assert incomplete.reason_codes == ("reason:effect-proof-incomplete",)


def test_typed_effect_uncertainty_applies_before_incomplete_proof_floor() -> None:
    assessment = _assessment(uncertainty=(UncertaintyKind.MATCHER_FAILURE,))

    decision = evaluate_effect_decision(_request((_observation(0, assessment=assessment),)))

    assert decision.action == "block"
    assert decision.reason_codes == ("reason:effect-proof-incomplete",)


def test_complete_positive_read_proof_is_silent_verified() -> None:
    decision = evaluate_effect_decision(_request((_observation(0, proof=_proof()),)))

    assert decision.action == "allow"
    assert decision.disposition is DecisionDisposition.SILENT_VERIFIED
    assert decision.segment_actions == (("segment:0", "allow"),)
    assert decision.proof_routes == (ProofRoute.VERIFIED,)


def test_required_containment_fails_closed_and_complete_containment_is_silent() -> None:
    requirements = frozenset(
        {
            ProofRequirement.OPERATION_AND_TARGETS,
            ProofRequirement.EXECUTABLE_IDENTITY,
            ProofRequirement.CONTAINMENT_IDENTITY,
        }
    )
    assessment = _assessment(
        kind=EffectKind.PROCESS_EXECUTION,
        containment=ContainmentRequirement.REQUIRED,
        requirements=requirements,
    )
    launch_identity = _launch_binding()
    missing = evaluate_effect_decision(
        _request((_observation(0, assessment=assessment, expected_launch_identity=launch_identity),))
    )
    complete = evaluate_effect_decision(
        _request(
            (
                _observation(
                    0,
                    policy_floor="sandbox-required",
                    assessment=assessment,
                    proof=_proof(ProofRoute.CONTAINED, requirements=requirements, launch_identity=launch_identity),
                    expected_launch_identity=launch_identity,
                ),
            )
        )
    )

    assert missing.action == "sandbox-required"
    assert missing.disposition is DecisionDisposition.REQUIRE_REAPPROVAL
    assert complete.action == "allow"
    assert complete.disposition is DecisionDisposition.SILENT_CONTAINED


def test_launch_identity_drift_invalidates_an_otherwise_complete_proof() -> None:
    requirements = frozenset({ProofRequirement.OPERATION_AND_TARGETS, ProofRequirement.EXECUTABLE_IDENTITY})
    assessment = _assessment(kind=EffectKind.PROCESS_EXECUTION, requirements=requirements)
    expected = _launch_binding()
    drifted = replace(expected, working_directory_identity=_digest("cwd", "e"))

    decision = evaluate_effect_decision(
        _request(
            (
                _observation(
                    0,
                    assessment=assessment,
                    proof=_proof(requirements=requirements, launch_identity=drifted),
                    expected_launch_identity=expected,
                ),
            )
        )
    )

    assert decision.action == "require-reapproval"
    assert "reason:launch-identity-mismatch" in decision.reason_codes


def test_workflow_authorization_requires_explicit_eligibility_and_never_lowers_block() -> None:
    requirements = frozenset({ProofRequirement.OPERATION_AND_TARGETS, ProofRequirement.CAPABILITY_CONSTRAINTS})
    proof = _proof(ProofRoute.WORKFLOW_AUTHORIZED, requirements=requirements)
    assessment = _assessment(kind=EffectKind.REMOTE_STATE_MUTATION, requirements=requirements)

    eligible = evaluate_effect_decision(
        _request(
            (
                _observation(
                    0,
                    policy_floor="review",
                    assessment=assessment,
                    proof=proof,
                    workflow_eligible=True,
                ),
            )
        )
    )
    ineligible = evaluate_effect_decision(
        _request((_observation(0, policy_floor="review", assessment=assessment, proof=proof),))
    )
    blocked = evaluate_effect_decision(
        _request(
            (
                _observation(
                    0,
                    policy_floor="block",
                    assessment=assessment,
                    proof=proof,
                    workflow_eligible=True,
                ),
            )
        )
    )

    assert eligible.disposition is DecisionDisposition.WORKFLOW_AUTHORIZED
    assert eligible.action == "allow"
    assert ineligible.action == "review"
    assert blocked.action == "block"


def test_stronger_sibling_suffix_and_legacy_candidates_always_dominate_safe_proof() -> None:
    safe = _observation(0, proof=_proof())
    destructive = _observation(1, policy_floor="block", proof=_proof())
    legacy = DecisionCandidate(
        source_id="heuristic:github",
        source_kind=DecisionSourceKind.LEGACY_HEURISTIC,
        action_floor="require-reapproval",
        reason_code="reason:remote-mutation",
        segment_ref="segment:2",
    )

    decision = evaluate_effect_decision(_request((safe, destructive), candidates=(legacy,)))

    assert decision.action == "block"
    assert decision.controlling_sources == ("effect:1",)
    assert decision.segment_actions == (
        ("segment:0", "allow"),
        ("segment:1", "block"),
        ("segment:2", "require-reapproval"),
    )


def test_typed_uncertainty_is_monotonic_across_every_candidate_permutation() -> None:
    candidates = (
        DecisionCandidate("policy:workspace", DecisionSourceKind.POLICY, "warn", "reason:policy"),
        DecisionCandidate("heuristic:package", DecisionSourceKind.LEGACY_HEURISTIC, "review", "reason:package"),
        DecisionCandidate("policy:critical", DecisionSourceKind.POLICY, "block", "reason:critical"),
    )
    results = {
        evaluate_effect_decision(
            _request(
                (_observation(0, proof=_proof()),),
                candidates=order,
                uncertainties=(UncertaintyKind.UNRESOLVED_LAUNCH_IDENTITY,),
            )
        ).action
        for order in itertools.permutations(candidates)
    }

    assert results == {"block"}


def test_launch_identity_binds_every_launch_family_and_any_drift_changes_identity() -> None:
    binding = _launch_binding()

    assert {item.kind for item in binding.components} == set(LaunchComponentKind)
    assert LaunchComponentKind.REDIRECTION in {item.kind for item in binding.components}
    assert replace(binding, working_directory_identity=_digest("cwd", "e")) != binding
    assert replace(binding, command_security_identity=f"command-security-v2:{'d' * 64}") != binding
    for component in binding.components:
        input_drifted = replace(component, input_identity=_digest("input", "e"))
        input_components = tuple(item if item != component else input_drifted for item in binding.components)
        assert replace(binding, components=input_components) != binding
        drifted = replace(component, resolved_identity=_digest("resolved", "f"))
        drifted_components = tuple(item if item != component else drifted for item in binding.components)
        assert replace(binding, components=drifted_components) != binding
    with pytest.raises(ValueError, match="executable component"):
        _ = replace(
            binding,
            components=tuple(item for item in binding.components if item.kind is not LaunchComponentKind.EXECUTABLE),
        )
    with pytest.raises(ValueError, match="framed command identity"):
        _ = replace(binding, command_security_identity="command-security-v2:not-a-digest")


def test_contracts_are_immutable_and_reject_untyped_boundaries() -> None:
    decision = evaluate_effect_decision(_request((_observation(0, proof=_proof()),)))

    assert decision.schema_version == EFFECT_DECISION_PLANE_SCHEMA_VERSION
    with pytest.raises(FrozenInstanceError):
        decision.action = "block"  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(ValueError, match="DecisionSourceKind"):
        _ = DecisionCandidate(
            "policy:test",
            "policy",  # pyright: ignore[reportArgumentType]
            "review",
            "reason:test",
        )
    with pytest.raises(ValueError, match="schema version"):
        _ = replace(_request(), schema_version="2.0.0")
    with pytest.raises(ValueError, match="EffectDecisionRequest"):
        _ = evaluate_effect_decision({})  # pyright: ignore[reportArgumentType]


def test_unexpected_future_action_cannot_fall_through_to_silent_verified() -> None:
    disposition = cast(
        Callable[[GuardAction, set[ProofRoute]], DecisionDisposition],
        effect_decision_plane_module.decision_disposition,
    )

    with pytest.raises(ValueError, match="unexpected Guard action"):
        _ = disposition(cast(GuardAction, cast(object, "future-action")), set())
