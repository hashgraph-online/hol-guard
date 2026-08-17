"""Composite command evaluation shared by inspection and runtime policy."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .command_contained_routine_candidates import contained_routine_candidate_factor
from .command_critical_floors import command_critical_floor_factors
from .command_decision_adapter import (
    command_uncertainties,
    decision_factors,
    effect_decision_to_dict,
    extension_evidence_batch,
    extension_uncertainties,
)
from .command_extension_observations import CommandExtensionObservation
from .command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
)
from .command_model import CanonicalCommand, parse_shell_command
from .command_rules import CommandRuleMatch, CommandRuleMode, CommandSafetyRule
from .command_verified_read_candidates import verified_read_candidate_factor
from .command_workspace_write_candidates import workspace_write_candidate_factors
from .effect_contract import DecisionBasis, ProofRequirement, ProofRoute, UncertaintyKind
from .effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    EffectDecision,
    EffectDecisionRequest,
    PositiveProof,
    evaluate_effect_decision,
)
from .extension_control_contract import ControlResolution, ControlSurface, ExtensionControlLayer
from .extension_control_resolver import resolve_extension_controls
from .extension_control_runtime import (
    ExtensionControlDecisionEvidence,
    ExtensionControlRuntimeSnapshot,
    current_extension_control_snapshot,
)
from .github_capability_contract import github_capability_contract
from .github_command_capabilities import classify_github_cli
from .github_workflow_authorization import (
    GitHubWorkflowAuthorization,
    github_workflow_authorization_evidence,
)

CommandDecisionFloor = Literal["allow", "monitor", "review", "block"]
_FLOOR_RANK: dict[CommandDecisionFloor, int] = {"allow": 0, "monitor": 1, "review": 2, "block": 3}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_MODE_FLOOR: dict[CommandRuleMode, CommandDecisionFloor] = {
    "disabled": "allow",
    "monitor": "monitor",
    "review": "review",
    "enforce": "block",
    "required": "review",
}


@dataclass(frozen=True, slots=True)
class OwnedCommandRuleMatch:
    """One rule match with its owning extension."""

    extension: CommandSafetyExtension
    match: CommandRuleMatch

    def to_dict(self) -> dict[str, object]:
        return {
            "extension_id": self.extension.extension_id,
            **self.match.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class CompositeCommandEvaluation:
    """All command matches plus the compatibility-preserving controlling action."""

    command: CanonicalCommand
    matches: tuple[OwnedCommandRuleMatch, ...]
    controlling_action_class: str | None
    controlling_reason: str | None
    controlling_rule_id: str | None
    minimum_action: CommandDecisionFloor
    extension_observations: tuple[CommandExtensionObservation[CommandSafetyExtension], ...]
    decision_plane: EffectDecision
    baseline_factors: tuple[DecisionFactor, ...]
    baseline_uncertainties: tuple[UncertaintyKind, ...]
    control_resolution: ControlResolution
    private_control_evidence: ExtensionControlDecisionEvidence | None

    @property
    def risk_classes(self) -> tuple[str, ...]:
        return tuple(sorted({risk for owned in self.matches for risk in owned.match.rule.risk_classes}))

    @property
    def matched(self) -> bool:
        return self.controlling_action_class is not None or bool(self.matches)

    def to_dict(self) -> dict[str, object]:
        return {
            "security_identity": self.command.security_identity,
            "controlling_action_class": self.controlling_action_class,
            "controlling_reason": self.controlling_reason,
            "controlling_rule_id": self.controlling_rule_id,
            "minimum_action": self.minimum_action,
            "risk_classes": list(self.risk_classes),
            "matches": [owned.to_dict() for owned in self.matches],
            "extension_observations": [item.to_dict() for item in self.extension_observations],
            "decision_plane": effect_decision_to_dict(self.decision_plane),
            "parse_confidence": self.command.confidence,
            "uncertainty_reason": self.command.uncertainty_reason,
        }


def evaluate_command(
    command_text: str,
    *,
    canonical_command: CanonicalCommand | None = None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    workflow_authorization: GitHubWorkflowAuthorization | None = None,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    extension_control_layers: tuple[ExtensionControlLayer, ...] | None = None,
    extension_control_snapshot: ExtensionControlRuntimeSnapshot | None = None,
) -> CompositeCommandEvaluation:
    """Evaluate every built-in rule without executing or persisting the command."""

    if extension_control_layers is not None and extension_control_snapshot is not None:
        raise ValueError("provide extension control layers or a runtime snapshot, not both")
    runtime_snapshot = extension_control_snapshot
    if extension_control_layers is None and runtime_snapshot is None:
        runtime_snapshot = current_extension_control_snapshot()
    control_layers = runtime_snapshot.layers if runtime_snapshot is not None else (extension_control_layers or ())

    command = canonical_command or parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    observations = registry.observations(command)
    structured = tuple(
        (item.extension, item.rule, item.effective_evidence) for item in observations if item.effective_evidence
    )
    selected = list(structured)
    selected_rule_ids = {rule.rule_id for _extension, rule, _evidence in selected}
    compatibility_rule: tuple[CommandSafetyExtension, CommandSafetyRule] | None = None
    if compatibility_action_class is not None:
        extension = registry.for_action_class(compatibility_action_class)
        rule = registry.rule_for_action_class(compatibility_action_class)
        if extension is not None and rule is not None:
            compatibility_rule = (extension, rule)
            if rule.rule_id not in selected_rule_ids:
                selected.append((extension, rule, ()))

    owned_matches: list[OwnedCommandRuleMatch] = []
    for extension, rule, evidence in selected:
        action_class = rule.action_classes[0] if rule.action_classes else compatibility_action_class
        reason = rule.description
        if rule.compatibility_fallback and compatibility_reason is not None:
            reason = compatibility_reason
        owned_matches.append(
            OwnedCommandRuleMatch(
                extension=extension,
                match=CommandRuleMatch(
                    rule=rule,
                    action_class=action_class,
                    reason=reason,
                    command=command,
                    matcher_evidence=evidence,
                ),
            )
        )

    extension_ids = tuple(sorted({observation.extension.extension_id for observation in observations}))
    permission_ids = tuple(
        sorted(
            {
                permission.permission_id
                for owned in owned_matches
                if (permission := registry.permission_for_rule_id(owned.match.rule.rule_id)) is not None
            }
            | _direct_github_permission_ids(command)
        )
    )
    control_resolution = resolve_extension_controls(
        control_layers,
        registry,
        extension_ids=extension_ids,
        permission_ids=permission_ids,
        surface=ControlSurface.COMMAND_EVALUATION,
        observations=tuple(
            f"{observation.extension.extension_id}:{observation.rule.rule_id}" for observation in observations
        ),
        authority_failure=runtime_snapshot.authority_failure if runtime_snapshot is not None else None,
    )
    explicitly_enabled_permissions = frozenset(control_resolution.explicitly_enabled_permission_ids)
    relaxable_enabled_permissions = (
        frozenset(
            permission_id
            for permission_id in explicitly_enabled_permissions
            if (permission := registry.permission(permission_id)) is not None and permission.configurable
        )
        if runtime_snapshot is not None and runtime_snapshot.authority_failure is None
        else frozenset()
    )
    explicitly_enabled_rule_ids = frozenset(
        rule_id
        for permission_id in relaxable_enabled_permissions
        for permission in (registry.permission(permission_id),)
        if permission is not None
        for rule_id in permission.rule_ids
    )
    controlling_match = max(owned_matches, key=_match_precedence_key, default=None)
    controlling_action_class = compatibility_action_class
    controlling_reason = compatibility_reason
    if controlling_action_class is None and controlling_match is not None:
        controlling_action_class = controlling_match.match.action_class
        controlling_reason = controlling_match.match.reason
    minimum_action: CommandDecisionFloor = "allow"
    for owned in owned_matches:
        if owned.match.rule.rule_id in explicitly_enabled_rule_ids:
            continue
        minimum_action = _stronger_floor(minimum_action, _rule_floor(owned))
    compatibility_owned_rule_ids = frozenset(
        owned.match.rule.rule_id for owned in owned_matches if owned.match.action_class == compatibility_action_class
    )
    compatibility_explicitly_enabled = (
        bool(compatibility_owned_rule_ids) and compatibility_owned_rule_ids.issubset(explicitly_enabled_rule_ids)
    ) or (compatibility_rule is not None and compatibility_rule[1].rule_id in explicitly_enabled_rule_ids)
    if compatibility_action_class is not None and not compatibility_explicitly_enabled:
        minimum_action = _stronger_floor(minimum_action, "review")
    if command.confidence != "exact" and (compatibility_action_class is not None or owned_matches):
        minimum_action = _stronger_floor(minimum_action, "review")
    observation_uncertainties = extension_uncertainties(observations)
    if observation_uncertainties:
        minimum_action = "block"
    evidence_batch = extension_evidence_batch(command, observations)
    effective_evidence_batch = type(evidence_batch)(
        tuple(
            evidence
            for evidence in evidence_batch.evidence
            if evidence.identity.rule_id not in explicitly_enabled_rule_ids or evidence.uncertainty_reasons
        )
    )
    contained_routine_candidate = contained_routine_candidate_factor(command)
    verified_read_candidate = verified_read_candidate_factor(command)
    workspace_write_candidates = workspace_write_candidate_factors(command)
    authorization_evidence = github_workflow_authorization_evidence(
        workflow_authorization,
        command_identity=command.security_identity,
    )
    baseline_critical_floor_factors = command_critical_floor_factors(command)
    explicitly_allowed_github_capabilities = frozenset(
        capability
        for permission_id in relaxable_enabled_permissions
        for permission in (registry.permission(permission_id),)
        if permission is not None
        for capability in permission.typed_capabilities
    )
    explicit_permission_allow_factors = _explicit_permission_allow_factors(
        command,
        control_layers,
        relaxable_enabled_permissions,
        runtime_snapshot.private_evidence if runtime_snapshot is not None else None,
    )
    critical_floor_factors = command_critical_floor_factors(
        command,
        workflow_authorization,
        explicitly_allowed_github_capabilities=(
            explicitly_allowed_github_capabilities if command.confidence == "exact" else frozenset()
        ),
    )
    authorized_action_class = authorization_evidence[1] if authorization_evidence is not None else None
    if contained_routine_candidate is not None:
        minimum_action = _stronger_floor(minimum_action, "review")
    if verified_read_candidate is not None:
        minimum_action = _stronger_floor(minimum_action, "review")
    for candidate in workspace_write_candidates:
        candidate_floor: CommandDecisionFloor = "block" if candidate.basis.action_floor == "block" else "review"
        minimum_action = _stronger_floor(minimum_action, candidate_floor)
    baseline_decision_factors = decision_factors(
        evidence_batch,
        compatibility_action_class=None,
        compatibility_rule=None,
    )
    decision_compatibility_action_class = (
        None
        if compatibility_explicitly_enabled
        or (authorized_action_class is not None and compatibility_action_class == authorized_action_class)
        else compatibility_action_class
    )
    current_decision_factors = (
        decision_factors(effective_evidence_batch, compatibility_action_class=None)
        if decision_compatibility_action_class is None
        else decision_factors(
            effective_evidence_batch,
            compatibility_action_class=decision_compatibility_action_class,
            compatibility_rule=compatibility_rule,
        )
    )
    baseline_factors = (
        *baseline_decision_factors,
        *workspace_write_candidates,
        *baseline_critical_floor_factors,
    )
    baseline_uncertainties = tuple(
        sorted(
            {
                *command_uncertainties(command, sensitive=bool(owned_matches)),
                *observation_uncertainties,
            },
            key=lambda item: item.value,
        )
    )
    decision_uncertainties = (
        baseline_uncertainties
        if compatibility_action_class is None
        else tuple(
            sorted(
                {
                    *command_uncertainties(command, sensitive=True),
                    *observation_uncertainties,
                },
                key=lambda item: item.value,
            )
        )
    )
    if control_resolution.blocked:
        minimum_action = _stronger_floor(minimum_action, "block")
    decision_plane = evaluate_effect_decision(
        EffectDecisionRequest(
            factors=(
                *current_decision_factors,
                *((contained_routine_candidate,) if contained_routine_candidate is not None else ()),
                *((verified_read_candidate,) if verified_read_candidate is not None else ()),
                *workspace_write_candidates,
                *critical_floor_factors,
                *control_resolution.factors,
                *explicit_permission_allow_factors,
            ),
            uncertainties=decision_uncertainties,
        )
    )
    return CompositeCommandEvaluation(
        command=command,
        matches=tuple(owned_matches),
        controlling_action_class=controlling_action_class,
        controlling_reason=controlling_reason,
        controlling_rule_id=controlling_match.match.rule.rule_id if controlling_match is not None else None,
        minimum_action=minimum_action,
        extension_observations=observations,
        decision_plane=decision_plane,
        baseline_factors=baseline_factors,
        baseline_uncertainties=baseline_uncertainties,
        control_resolution=control_resolution,
        private_control_evidence=runtime_snapshot.private_evidence if runtime_snapshot is not None else None,
    )


def _explicit_permission_allow_factors(
    command: CanonicalCommand,
    layers: tuple[ExtensionControlLayer, ...],
    permission_ids: frozenset[str],
    authority_evidence: ExtensionControlDecisionEvidence | None,
) -> tuple[DecisionFactor, ...]:
    if command.confidence != "exact" or not permission_ids:
        return ()
    canonical_layers = [
        {
            "kind": layer.kind.value,
            "catalog_digest": layer.catalog_digest,
            "global_lockdown": layer.global_lockdown,
            "controls": [
                {
                    "kind": control.target.kind.value,
                    "target_id": control.target.target_id,
                    "state": control.state.value,
                }
                for control in sorted(
                    layer.controls,
                    key=lambda item: (item.target.kind.value, item.target.target_id),
                )
            ],
        }
        for layer in sorted(layers, key=lambda item: item.kind.value)
    ]
    requirements = frozenset(
        {
            ProofRequirement.CONFIGURATION_IDENTITY,
            ProofRequirement.PARSER_CONFIDENCE,
            ProofRequirement.CAPABILITY_CONSTRAINTS,
        }
    )
    factors: list[DecisionFactor] = []
    for permission_id in sorted(permission_ids):
        binding_digest = hashlib.sha256(
            json.dumps(
                {
                    "command_security_identity": command.security_identity,
                    "permission_id": permission_id,
                    "layers": canonical_layers,
                    "authority": (
                        {
                            "revision": authority_evidence.revision,
                            "effective_digest": authority_evidence.effective_digest,
                        }
                        if authority_evidence is not None
                        else None
                    ),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        proof = PositiveProof(ProofRoute.VERIFIED, binding_digest, requirements)
        factors.append(
            DecisionFactor(
                source=DecisionFactorSource.CONTROL,
                reason_code="control.explicitly-enabled-permission",
                basis=DecisionBasis("allow", ProofRoute.VERIFIED),
                producer_ref=f"control:{permission_id}",
                evidence_digest=binding_digest,
                proof=proof,
            )
        )
    return tuple(factors)


def _direct_github_permission_ids(command: CanonicalCommand) -> set[str]:
    """Resolve catalog permissions for exact GitHub capabilities without matcher rules."""

    permission_ids: set[str] = set()
    for segment in command.segments:
        executable = (segment.executable or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        if executable.removesuffix(".exe") != "gh":
            continue
        assessment = classify_github_cli(segment.arguments)
        permission_ids.update(
            github_capability_contract(capability).permission_id for capability in assessment.capabilities
        )
    return permission_ids


def _rule_floor(owned: OwnedCommandRuleMatch) -> CommandDecisionFloor:
    rule = owned.match.rule
    if owned.extension.required and rule.severity == "critical":
        return "block"
    if owned.extension.required:
        return "review"
    return _MODE_FLOOR[rule.default_mode]


def _stronger_floor(left: CommandDecisionFloor, right: CommandDecisionFloor) -> CommandDecisionFloor:
    return left if _FLOOR_RANK[left] >= _FLOOR_RANK[right] else right


def _match_precedence_key(owned: OwnedCommandRuleMatch) -> tuple[int, int, int]:
    return (
        _FLOOR_RANK[_rule_floor(owned)],
        _SEVERITY_RANK[owned.match.rule.severity],
        0 if owned.match.rule.compatibility_fallback else 1,
    )
