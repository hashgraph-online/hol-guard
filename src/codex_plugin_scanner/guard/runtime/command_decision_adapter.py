"""Compatibility adapters from command evidence to the central evaluator."""

from __future__ import annotations

import hashlib
from typing import Literal

from codex_plugin_scanner.guard.models import GuardAction

from .command_extension_observations import CommandExtensionObservation
from .command_extensions import CommandSafetyExtension
from .command_model import CanonicalCommand
from .command_rules import CommandRuleMode, CommandSafetyRule
from .effect_contract import (
    UNCERTAINTY_FLOOR,
    DecisionBasis,
    EffectKind,
    ProofRequirement,
    UncertaintyKind,
    maximum_action_floor,
)
from .effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    DecisionReason,
    EffectDecision,
    EffectDecisionRequest,
    evaluate_effect_decision,
    factors_from_extension_evidence,
)
from .extension_evidence import (
    EvidenceSeverity,
    ExtensionEvidence,
    ExtensionEvidenceBatch,
    ExtensionMatchClass,
    ExtensionRuleIdentity,
    OwnedSafeVariant,
    SafeVariantOutcome,
)

LegacyCommandFloor = Literal["allow", "monitor", "review", "block"]

_MODE_FLOOR: dict[CommandRuleMode, LegacyCommandFloor] = {
    "disabled": "allow",
    "monitor": "monitor",
    "review": "review",
    "enforce": "block",
    "required": "review",
}
_CANONICAL_FLOOR: dict[LegacyCommandFloor, GuardAction] = {
    "allow": "allow",
    "monitor": "warn",
    "review": "review",
    "block": "block",
}
_SEVERITY: dict[str, EvidenceSeverity] = {
    "low": EvidenceSeverity.LOW,
    "medium": EvidenceSeverity.MEDIUM,
    "high": EvidenceSeverity.HIGH,
    "critical": EvidenceSeverity.CRITICAL,
}


def legacy_rule_floor(extension: CommandSafetyExtension, rule: CommandSafetyRule) -> LegacyCommandFloor:
    if extension.required and rule.severity == "critical":
        return "block"
    if extension.required:
        return "review"
    return _MODE_FLOOR[rule.default_mode]


def extension_evidence_batch(
    command: CanonicalCommand,
    observations: tuple[CommandExtensionObservation[CommandSafetyExtension], ...],
) -> ExtensionEvidenceBatch:
    """Translate every review-or-stronger match and matcher uncertainty."""

    evidence: list[ExtensionEvidence] = []
    operation_ref = f"operation:{command.security_identity.rsplit(':', 1)[-1]}"
    for observation in observations:
        floor = _CANONICAL_FLOOR[legacy_rule_floor(observation.extension, observation.rule)]
        if observation.uncertainty_reasons:
            evidence.append(
                ExtensionEvidence(
                    identity=_rule_identity(observation),
                    match_class=ExtensionMatchClass.UNCERTAINTY,
                    severity=EvidenceSeverity.CRITICAL,
                    declared_floor=maximum_action_floor(
                        UNCERTAINTY_FLOOR[item] for item in observation.uncertainty_reasons
                    ),
                    base_fact="matcher-failure",
                    segment_ref="segment:unknown",
                    operation_ref=operation_ref,
                    effect_claims=_effect_claims(observation.rule.risk_classes),
                    proof_requirements=_extension_proof_requirements(),
                    uncertainty_reasons=observation.uncertainty_reasons,
                )
            )
        if floor in {"allow", "warn"}:
            continue
        identity = _rule_identity(observation)
        for segment_index in sorted({match.segment_index for match in observation.matcher_evidence}):
            safe_variant_ids = sorted(
                {
                    variant.variant_id
                    for variant in observation.safe_variants
                    if any(item.segment_index == segment_index for item in variant.matcher_evidence)
                }
            )
            owned_safe_variants: tuple[OwnedSafeVariant | None, ...] = tuple(
                OwnedSafeVariant(identity, variant_id, SafeVariantOutcome.OWNED_RULE_NOT_RAISED)
                for variant_id in safe_variant_ids
            ) or (None,)
            for safe_variant in owned_safe_variants:
                evidence.append(
                    ExtensionEvidence(
                        identity=identity,
                        match_class=ExtensionMatchClass.UNSAFE,
                        severity=_SEVERITY[observation.rule.severity],
                        declared_floor=floor,
                        base_fact="rule-match",
                        segment_ref=f"segment:{segment_index}",
                        operation_ref=operation_ref,
                        effect_claims=_effect_claims(observation.rule.risk_classes),
                        proof_requirements=_extension_proof_requirements(),
                        safe_variant=safe_variant,
                    )
                )
    return ExtensionEvidenceBatch(tuple(evidence))


def decision_factors(
    batch: ExtensionEvidenceBatch,
    *,
    compatibility_action_class: str | None,
) -> tuple[DecisionFactor, ...]:
    factors = list(factors_from_extension_evidence(batch))
    if compatibility_action_class is not None:
        identity = hashlib.sha256(compatibility_action_class.strip().lower().encode("utf-8")).hexdigest()
        factors.append(
            DecisionFactor(
                source=DecisionFactorSource.POLICY,
                reason_code="compatibility-action",
                basis=DecisionBasis("review", None),
                producer_ref=f"legacy:{identity}",
            )
        )
    return tuple(factors)


def interaction_policy_factors(
    observations: tuple[CommandExtensionObservation[CommandSafetyExtension], ...],
) -> tuple[DecisionFactor, ...]:
    """Preserve the existing review floor outside extension-owned evidence."""

    factors: list[DecisionFactor] = []
    for observation in observations:
        if not observation.effective_evidence or not observation.rule.action_classes:
            continue
        segment_indexes = sorted({item.segment_index for item in observation.effective_evidence})
        for segment_index in segment_indexes:
            factors.append(
                DecisionFactor(
                    source=DecisionFactorSource.POLICY,
                    reason_code="extension-interaction-floor",
                    basis=DecisionBasis("review", None),
                    segment_ref=f"segment:{segment_index}",
                    producer_ref=f"rule:{observation.rule.rule_id}",
                )
            )
    return tuple(factors)


def evaluate_extension_interaction(
    command: CanonicalCommand,
    observations: tuple[CommandExtensionObservation[CommandSafetyExtension], ...],
) -> EffectDecision:
    """Evaluate extension evidence plus the compatibility review policy."""

    batch = extension_evidence_batch(command, observations)
    factors = (
        *decision_factors(batch, compatibility_action_class=None),
        *interaction_policy_factors(observations),
    )
    return evaluate_effect_decision(
        EffectDecisionRequest(
            factors=factors,
            uncertainties=extension_uncertainties(observations),
        )
    )


def command_uncertainties(command: CanonicalCommand, *, sensitive: bool) -> tuple[UncertaintyKind, ...]:
    if not sensitive or command.confidence == "exact":
        return ()
    if command.confidence == "fallback":
        return (UncertaintyKind.PARTIAL_PARSE,)
    return (UncertaintyKind.DYNAMIC_INPUT,)


def extension_uncertainties(
    observations: tuple[CommandExtensionObservation[CommandSafetyExtension], ...],
) -> tuple[UncertaintyKind, ...]:
    return tuple(
        sorted(
            {item for observation in observations for item in observation.uncertainty_reasons},
            key=lambda item: item.value,
        )
    )


def effect_decision_to_dict(decision: EffectDecision) -> dict[str, object]:
    return {
        "schema_version": decision.schema_version,
        "action": decision.action,
        "disposition": decision.disposition.value,
        "proof_routes": sorted(item.value for item in decision.proof_routes),
        "controlling_reasons": [_reason_to_dict(item) for item in decision.controlling_reasons],
        "reasons": [_reason_to_dict(item) for item in decision.reasons],
    }


def _reason_to_dict(reason: object) -> dict[str, object]:
    if not isinstance(reason, DecisionReason):
        raise ValueError("reason must be a DecisionReason")
    return {
        "source": reason.source.value,
        "reason_code": reason.reason_code,
        "action_floor": reason.action_floor,
        "segment_ref": reason.segment_ref,
        "operation_ref": reason.operation_ref,
    }


def _rule_identity(
    observation: CommandExtensionObservation[CommandSafetyExtension],
) -> ExtensionRuleIdentity:
    return ExtensionRuleIdentity(
        extension_id=observation.extension.extension_id,
        extension_version=observation.extension.version,
        rule_id=observation.rule.rule_id,
        rule_version=observation.rule.rule_version,
    )


def _extension_proof_requirements() -> frozenset[ProofRequirement]:
    return frozenset(
        {
            ProofRequirement.OPERATION_AND_TARGETS,
            ProofRequirement.PARSER_CONFIDENCE,
            ProofRequirement.EXPECTED_EFFECTS,
        }
    )


def _effect_claims(risk_classes: tuple[str, ...]) -> frozenset[EffectKind]:
    effects: set[EffectKind] = set()
    for risk in risk_classes:
        if "destructive" in risk:
            effects.add(EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION)
        if "network" in risk or "exfiltration" in risk:
            effects.add(EffectKind.NETWORK_WRITE)
        if "secret" in risk or "credential" in risk:
            effects.add(EffectKind.CREDENTIAL_OR_SECRET_OPERATION)
        if "execution" in risk:
            effects.add(EffectKind.PROCESS_EXECUTION)
        if "policy" in risk:
            effects.add(EffectKind.GUARD_CONTROL_OPERATION)
    return frozenset(effects or {EffectKind.PROCESS_EXECUTION})
