from __future__ import annotations

import itertools
from dataclasses import FrozenInstanceError, replace

import pytest

from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind, ProofRequirement, UncertaintyKind
from codex_plugin_scanner.guard.runtime.extension_evidence import (
    EXTENSION_EVIDENCE_SCHEMA_VERSION,
    EvidenceSeverity,
    ExtensionEvidence,
    ExtensionEvidenceBatch,
    ExtensionMatchClass,
    ExtensionRuleIdentity,
    OwnedSafeVariant,
    SafeVariantOutcome,
)


def _identity(
    *,
    rule_id: str = "command.git.force-push",
    extension_version: str = "2.2.0",
    rule_version: str = "1.0.0",
) -> ExtensionRuleIdentity:
    return ExtensionRuleIdentity(
        extension_id="command.git",
        extension_version=extension_version,
        rule_id=rule_id,
        rule_version=rule_version,
    )


def _safe(identity: ExtensionRuleIdentity | None = None) -> OwnedSafeVariant:
    return OwnedSafeVariant(
        identity=identity or _identity(),
        safe_variant_id="dry-run",
        outcome=SafeVariantOutcome.OWNED_RULE_NOT_RAISED,
    )


def _evidence(
    *,
    identity: ExtensionRuleIdentity | None = None,
    match_class: ExtensionMatchClass = ExtensionMatchClass.UNSAFE,
    severity: EvidenceSeverity = EvidenceSeverity.HIGH,
    declared_floor: str = "review",
    base_fact: str = "remote-mutation",
    effect_claims: frozenset[EffectKind] | None = None,
    proof_requirements: frozenset[ProofRequirement] | None = None,
    uncertainty_reasons: tuple[UncertaintyKind, ...] = (),
    safe_variant: OwnedSafeVariant | None = None,
    schema_version: str = EXTENSION_EVIDENCE_SCHEMA_VERSION,
) -> ExtensionEvidence:
    return ExtensionEvidence(
        identity=identity or _identity(),
        match_class=match_class,
        severity=severity,
        declared_floor=declared_floor,  # type: ignore[arg-type]
        base_fact=base_fact,
        segment_ref="segment:0",
        operation_ref="operation:git-push",
        effect_claims=(effect_claims if effect_claims is not None else frozenset({EffectKind.REMOTE_STATE_MUTATION})),
        proof_requirements=(
            proof_requirements
            if proof_requirements is not None
            else frozenset({ProofRequirement.OPERATION_AND_TARGETS, ProofRequirement.EXECUTABLE_IDENTITY})
        ),
        uncertainty_reasons=uncertainty_reasons,
        safe_variant=safe_variant,
        schema_version=schema_version,
    )


def test_owned_rule_match_retains_declared_fact_floor_and_effective_floor() -> None:
    evidence = _evidence(declared_floor="require-reapproval")

    assert evidence.base_fact == "remote-mutation"
    assert evidence.declared_floor == "require-reapproval"
    assert evidence.effective_floor == "require-reapproval"
    assert evidence.schema_version == "1.0.0"
    with pytest.raises(FrozenInstanceError):
        evidence.severity = EvidenceSeverity.LOW  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("extension_id", "Command Git"),
        ("extension_version", "2.2"),
        ("rule_id", "command/git"),
        ("rule_version", ""),
    ],
)
def test_identity_requires_stable_semver_and_rule_ownership(field: str, value: str) -> None:
    values = {
        "extension_id": "command.git",
        "extension_version": "2.2.0",
        "rule_id": "command.git.force-push",
        "rule_version": "1.0.0",
    }
    values[field] = value
    with pytest.raises(ValueError, match=field):
        ExtensionRuleIdentity(**values)

    with pytest.raises(ValueError, match="owned by extension_id"):
        _identity(rule_id="command.filesystem.remove")


def test_safe_variant_neutralizes_only_its_exact_owned_observation() -> None:
    safe_match = _evidence(safe_variant=_safe())
    sibling = _evidence(
        identity=_identity(rule_id="command.git.force-delete"),
        declared_floor="block",
        base_fact="remote-delete",
    )

    assert safe_match.declared_floor == "review"
    assert safe_match.effective_floor is None
    assert ExtensionEvidenceBatch((safe_match,)).evidence_floor() is None
    assert ExtensionEvidenceBatch((safe_match, sibling)).evidence_floor() == "block"

    with pytest.raises(ValueError, match="exact matched rule"):
        _evidence(safe_variant=_safe(_identity(rule_id="command.git.other-rule")))


@pytest.mark.parametrize(
    "safe_identity",
    [
        _identity(extension_version="2.2.1"),
        _identity(rule_version="1.0.1"),
    ],
)
def test_safe_variant_requires_the_full_exact_rule_identity(safe_identity: ExtensionRuleIdentity) -> None:
    with pytest.raises(ValueError, match="exact matched rule identity"):
        _evidence(safe_variant=_safe(safe_identity))


def test_safe_variant_rejects_untyped_outcomes() -> None:
    with pytest.raises(ValueError, match="SafeVariantOutcome"):
        replace(_safe(), outcome="owned-rule-not-raised")  # type: ignore[arg-type]


def test_safe_variant_cannot_erase_uncertainty_or_unrelated_floor() -> None:
    safe_match = _evidence(safe_variant=_safe())
    uncertainty = _evidence(
        identity=_identity(rule_id="command.git.parser-health"),
        match_class=ExtensionMatchClass.UNCERTAINTY,
        declared_floor="block",
        base_fact="parser-failure",
        uncertainty_reasons=(UncertaintyKind.PARSER_FAILURE,),
    )

    assert ExtensionEvidenceBatch((safe_match, uncertainty)).evidence_floor() == "block"
    with pytest.raises(ValueError, match="uncertainty evidence cannot declare a safe variant"):
        _evidence(
            match_class=ExtensionMatchClass.UNCERTAINTY,
            declared_floor="block",
            base_fact="parser-failure",
            uncertainty_reasons=(UncertaintyKind.PARSER_FAILURE,),
            safe_variant=_safe(),
        )


def test_unsafe_evidence_requires_a_valid_review_or_stronger_floor() -> None:
    with pytest.raises(ValueError, match="review-or-stronger"):
        _evidence(declared_floor="allow")
    with pytest.raises(ValueError, match="canonical GuardAction"):
        _evidence(declared_floor="invalid-action")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("identity", object(), "identity must be an ExtensionRuleIdentity"),
        ("match_class", "unsafe", "ExtensionMatchClass"),
        ("severity", "high", "EvidenceSeverity"),
        ("effect_claims", frozenset({"remote-state-mutation"}), "effect_claims members"),
        ("proof_requirements", frozenset({"operation-and-targets"}), "proof_requirements members"),
        ("uncertainty_reasons", ("parser-failure",), "uncertainty_reasons members"),
    ],
)
def test_extension_evidence_rejects_untyped_semantic_boundaries(field: str, value: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        replace(_evidence(), **{field: value})


def test_uncertainty_cannot_understate_its_canonical_floor() -> None:
    with pytest.raises(ValueError, match="understate"):
        _evidence(
            match_class=ExtensionMatchClass.UNCERTAINTY,
            declared_floor="review",
            uncertainty_reasons=(UncertaintyKind.UNRESOLVED_LAUNCH_IDENTITY,),
        )
    with pytest.raises(ValueError, match="requires at least one"):
        _evidence(match_class=ExtensionMatchClass.UNCERTAINTY)


def test_semantic_key_is_lossless_for_every_security_relevant_field() -> None:
    base = _evidence()
    variants = (
        replace(base, severity=EvidenceSeverity.CRITICAL),
        replace(base, declared_floor="block"),
        replace(base, base_fact="remote-delete"),
        replace(base, effect_claims=frozenset({EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION})),
        replace(base, proof_requirements=frozenset({ProofRequirement.REMOTE_RESOURCE_IDENTITY})),
        replace(
            base,
            match_class=ExtensionMatchClass.UNCERTAINTY,
            declared_floor="block",
            uncertainty_reasons=(UncertaintyKind.MATCHER_FAILURE,),
        ),
        replace(base, safe_variant=_safe()),
    )

    assert len({base.semantic_key, *(variant.semantic_key for variant in variants)}) == len(variants) + 1


def test_batch_order_and_floor_are_permutation_independent() -> None:
    items = (
        _evidence(safe_variant=_safe()),
        _evidence(
            identity=_identity(rule_id="command.git.force-delete"),
            declared_floor="block",
            base_fact="remote-delete",
        ),
        _evidence(
            identity=_identity(rule_id="command.git.remote-write"),
            declared_floor="require-reapproval",
            base_fact="remote-write",
        ),
    )

    canonical_orders = {
        tuple(item.semantic_key for item in ExtensionEvidenceBatch(order).evidence)
        for order in itertools.permutations(items)
    }
    floors = {ExtensionEvidenceBatch(order).evidence_floor() for order in itertools.permutations(items)}

    assert len(canonical_orders) == 1
    assert floors == {"block"}


def test_mixed_safe_and_unsafe_observations_have_a_canonical_sort_order() -> None:
    unsafe = _evidence()
    safe = _evidence(safe_variant=_safe())

    forward = ExtensionEvidenceBatch((unsafe, safe))
    reverse = ExtensionEvidenceBatch((safe, unsafe))

    assert forward.evidence == reverse.evidence
    assert forward.evidence_floor() == "review"


def test_duplicate_and_malformed_payloads_fail_closed() -> None:
    evidence = _evidence()
    with pytest.raises(ValueError, match="duplicate"):
        ExtensionEvidenceBatch((evidence, evidence))
    with pytest.raises(ValueError, match="schema version"):
        _evidence(schema_version="2.0.0")
    with pytest.raises(ValueError, match="effect_claims"):
        _evidence(effect_claims=frozenset())
    with pytest.raises(ValueError, match="canonical reference"):
        replace(evidence, segment_ref="../../raw/path")
