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
from .command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
    CommandSafetyRule,
    risk_classes_for_command_action,
)
from .command_model import CanonicalCommand
from .command_shell_read_factors import shell_read_floor_factors
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
from .extension_control_contract import (
    ControlResolution,
    ControlSurface,
    ExtensionControlLayer,
    ResolverFailureCode,
)
from .extension_control_resolver import resolve_extension_controls
from .extension_control_runtime import (
    ExtensionControlDecisionEvidence,
    ExtensionControlRuntimeSnapshot,
    current_extension_control_snapshot,
)
from .extension_trust import filter_inert_external_observations
from .github_capability_contract import github_capability_contract
from .github_command_capabilities import classify_github_cli
from .github_workflow_authorization import (
    GitHubWorkflowAuthorization,
    github_workflow_authorization_evidence,
)
from .native_command_extension_evidence import (
    NativeCommandExtensionObservation,
    NativeMatcherEvidence,
    observations_from_native_evidence,
)

CommandDecisionFloor = Literal["allow", "monitor", "review", "block"]
_FLOOR_RANK: dict[CommandDecisionFloor, int] = {"allow": 0, "monitor": 1, "review": 2, "block": 3}
_UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS = frozenset(
    {
        "destructive_shell",
        "credential_exfiltration",
        "data_flow_exfiltration",
        "encoded_execution",
        "encoded_exfiltration",
        "guard_bypass",
        "policy_bypass",
    }
)
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_MODE_FLOOR: dict[str, CommandDecisionFloor] = {
    "disabled": "allow",
    "monitor": "monitor",
    "review": "review",
    "enforce": "block",
    "required": "review",
}


@dataclass(frozen=True, slots=True)
class CommandRuleMatch:
    rule: CommandSafetyRule
    action_class: str | None
    reason: str
    command: CanonicalCommand
    matcher_evidence: tuple[NativeMatcherEvidence, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule.rule_id,
            "severity": self.rule.severity,
            "risk_classes": list(self.rule.risk_classes),
            "action_class": self.action_class,
            "reason": self.reason,
            "safer_alternatives": list(self.rule.safer_alternatives),
            "matcher_evidence": [item.to_dict() for item in self.matcher_evidence],
            "parse_confidence": self.command.confidence,
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
    extension_observations: tuple[NativeCommandExtensionObservation, ...]
    decision_plane: EffectDecision
    baseline_factors: tuple[DecisionFactor, ...]
    baseline_uncertainties: tuple[UncertaintyKind, ...]
    control_resolution: ControlResolution
    private_control_evidence: ExtensionControlDecisionEvidence | None

    @property
    def risk_classes(self) -> tuple[str, ...]:
        risks = {risk for owned in self.matches for risk in owned.match.rule.risk_classes}
        if self.controlling_action_class is not None:
            risks.update(risk_classes_for_command_action(self.controlling_action_class))
        if any(factor.reason_code == "critical.local-secret-read" for factor in self.baseline_factors):
            risks.add("local_secret_read")
        if any(factor.reason_code == "critical.local-script-execution" for factor in self.baseline_factors):
            risks.add("execution")
        return tuple(sorted(risks))

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
    native_extension_evidence: object | None = None,
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

    if native_extension_evidence is None:
        raise RuntimeError("native command extension evidence is required; the Python matcher oracle is retired")
    if canonical_command is None:
        raise RuntimeError("native canonical command model is required; Python semantic parsing is retired")
    command = canonical_command
    if runtime_snapshot is None:
        raise RuntimeError("authenticated extension control snapshot is required with native evidence")
    observations = filter_inert_external_observations(
        observations_from_native_evidence(
            native_extension_evidence,
            registry,
            command=command,
            control_snapshot=runtime_snapshot,
        ),
        control_layers,
    )
    structured = tuple(
        (item.extension, item.rule, item.effective_evidence) for item in observations if item.effective_evidence
    )
    selected = list(structured)
    # Compatibility labels are display metadata, not additional observations.
    # Several rules share one label (for example, Git workspace operations),
    # so looking it up globally can invent an unrelated matched rule.
    compatibility_rule = next(
        (
            (extension, rule)
            for extension, rule, _evidence in selected
            if compatibility_action_class in rule.action_classes
        ),
        None,
    )
    effective_compatibility_class = (
        compatibility_action_class
        if compatibility_rule is not None
        or (compatibility_action_class is not None and registry.for_action_class(compatibility_action_class) is None)
        else None
    )

    owned_matches: list[OwnedCommandRuleMatch] = []
    for extension, rule, evidence in selected:
        action_class = rule.action_classes[0] if rule.action_classes else effective_compatibility_class
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
    controlling_action_class = effective_compatibility_class
    controlling_reason = compatibility_reason if effective_compatibility_class is not None else None
    if controlling_action_class is None and controlling_match is not None:
        controlling_action_class = controlling_match.match.action_class
        controlling_reason = controlling_match.match.reason
    authorization_evidence = github_workflow_authorization_evidence(
        workflow_authorization,
        command_identity=command.security_identity,
    )
    authorized_action_class = authorization_evidence[1] if authorization_evidence is not None else None
    workflow_authorized_rule_ids = frozenset(
        observation.rule.rule_id
        for observation in observations
        if authorized_action_class is not None
        and not observation.uncertainty_reasons
        and authorized_action_class in observation.rule.action_classes
    )
    minimum_action: CommandDecisionFloor = "allow"
    native_explicitly_benign = (
        isinstance(native_extension_evidence, dict)
        and command.confidence == "exact"
        and native_extension_evidence.get("minimum_action") == "allow"
        and native_extension_evidence.get("explicitly_benign") is True
    )
    # Ownership by a default-disabled rule is not proof that the command is
    # safe. Only an explicit native benign classification may discharge an
    # optional allow-floor observation; required rule floors remain active.
    native_benign_rule_ids = (
        frozenset(
            owned.match.rule.rule_id
            for owned in owned_matches
            if _rule_floor(owned) == "allow"
            and any(
                observation.rule.rule_id == owned.match.rule.rule_id and not observation.uncertainty_reasons
                for observation in observations
            )
        )
        if native_explicitly_benign
        else frozenset()
    )
    # A syntax-level benign classification does not bind a read/write executor,
    # filesystem boundary, or launch identity. These candidates retain their
    # independent proof requirement even when no extension rule raises a floor.
    contained_routine_candidate = contained_routine_candidate_factor(command)
    verified_read_candidate = verified_read_candidate_factor(command)
    workspace_write_candidates = workspace_write_candidate_factors(command)
    execution_proof_required = (
        contained_routine_candidate is not None
        or verified_read_candidate is not None
        or bool(workspace_write_candidates)
    )
    native_host_floor_exempt = native_explicitly_benign and not execution_proof_required
    for owned in owned_matches:
        if owned.match.rule.rule_id in (
            native_benign_rule_ids | explicitly_enabled_rule_ids | workflow_authorized_rule_ids
        ):
            continue
        minimum_action = _stronger_floor(minimum_action, _rule_floor(owned))
    compatibility_owned_rule_ids = frozenset(
        owned.match.rule.rule_id for owned in owned_matches if owned.match.action_class == effective_compatibility_class
    )
    compatibility_explicitly_enabled = (
        bool(compatibility_owned_rule_ids) and compatibility_owned_rule_ids.issubset(explicitly_enabled_rule_ids)
    ) or (compatibility_rule is not None and compatibility_rule[1].rule_id in explicitly_enabled_rule_ids)
    compatibility_workflow_authorized = bool(compatibility_owned_rule_ids) and compatibility_owned_rule_ids.issubset(
        workflow_authorized_rule_ids
    )
    if (
        effective_compatibility_class is not None
        and not compatibility_explicitly_enabled
        and not compatibility_workflow_authorized
    ):
        minimum_action = _stronger_floor(minimum_action, "review")
    if command.confidence != "exact" and (effective_compatibility_class is not None or owned_matches):
        minimum_action = _stronger_floor(minimum_action, "review")
    observation_uncertainties = extension_uncertainties(observations)
    if observation_uncertainties:
        minimum_action = "block"
    evidence_batch = extension_evidence_batch(command, observations)
    effective_evidence_batch = type(evidence_batch)(
        tuple(
            evidence
            for evidence in evidence_batch.evidence
            if evidence.identity.rule_id not in native_benign_rule_ids
            and (evidence.identity.rule_id not in explicitly_enabled_rule_ids or evidence.uncertainty_reasons)
        )
    )
    # A native benign proof cannot establish the resolved target of a file
    # read, so secret-read floors remain active even for proven benign commands.
    read_factors = shell_read_floor_factors(command_text, command.security_identity, cwd=cwd, home_dir=home_dir)
    if native_host_floor_exempt:
        read_factors = tuple(factor for factor in read_factors if factor.reason_code == "critical.local-secret-read")
    if authorization_evidence is not None:
        # Claimed workflow proof already covers exact GitHub CLI execution.
        # Keep secret-read floors; do not let a script-shaped interpreter
        # argv raise an independent local-code review on that same claim.
        read_factors = tuple(factor for factor in read_factors if factor.reason_code == "critical.local-secret-read")
    if read_factors:
        minimum_action = _stronger_floor(minimum_action, "review")
    explicitly_allowed_github_capabilities = frozenset(
        capability
        for permission_id in relaxable_enabled_permissions
        for permission in (registry.permission(permission_id),)
        if permission is not None
        for capability in permission.typed_capabilities
    )
    # Syntax classification cannot waive a candidate's execution proof. Other
    # exact native benign commands retain their existing classification;
    # permissions and non-benign commands keep the independent critical floors.
    critical_floor_factors = (
        ()
        if native_host_floor_exempt
        else command_critical_floor_factors(
            command,
            workflow_authorization,
            explicitly_allowed_github_capabilities=(
                explicitly_allowed_github_capabilities if command.confidence == "exact" else frozenset()
            ),
        )
    )
    baseline_critical_floor_factors = (*critical_floor_factors, *read_factors)
    explicit_permission_allow_factors = _explicit_permission_allow_factors(
        command,
        control_layers,
        relaxable_enabled_permissions,
        runtime_snapshot.private_evidence if runtime_snapshot is not None else None,
    )
    if authorized_action_class is not None:
        effective_evidence_batch = type(effective_evidence_batch)(
            tuple(
                evidence
                for evidence in effective_evidence_batch.evidence
                if evidence.identity.rule_id not in workflow_authorized_rule_ids or evidence.uncertainty_reasons
            )
        )
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
        if effective_compatibility_class is None
        or compatibility_explicitly_enabled
        or (authorized_action_class is not None and effective_compatibility_class == authorized_action_class)
        else effective_compatibility_class
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
    native_classification_factors = _native_classification_factors(
        native_extension_evidence, command, allow_benign_proof=not execution_proof_required
    )
    baseline_factors = (
        *native_classification_factors,
        *baseline_decision_factors,
        *((contained_routine_candidate,) if contained_routine_candidate is not None else ()),
        *((verified_read_candidate,) if verified_read_candidate is not None else ()),
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
        if effective_compatibility_class is None
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
    # Unavailable authority still fail-closes cataloged, destructive, or write
    # commands. Secret reads and unmatched PATH tools keep their review floor
    # instead of becoming terminal blocks just because enrollment is missing.
    apply_control_fail_closed = False
    if control_resolution.blocked:
        authority_unavailable_only = bool(control_resolution.failures) and all(
            failure.code is ResolverFailureCode.AUTHORITY_UNAVAILABLE for failure in control_resolution.failures
        )
        write_redirect = any(
            redirect.operator.lstrip("0123456789") in {">", ">>", ">|"} for redirect in command.redirects
        )
        apply_control_fail_closed = (
            not authority_unavailable_only
            or bool(extension_ids)
            or minimum_action == "block"
            or bool(workspace_write_candidates)
            or write_redirect
        )
        if not apply_control_fail_closed:
            for owned in owned_matches:
                if _UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS.intersection(owned.match.rule.risk_classes):
                    apply_control_fail_closed = True
                    break
        if (
            not apply_control_fail_closed
            and effective_compatibility_class is not None
            and _UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS.intersection(
                risk_classes_for_command_action(effective_compatibility_class)
            )
        ):
            apply_control_fail_closed = True
        if apply_control_fail_closed:
            minimum_action = _stronger_floor(minimum_action, "block")
    decision_plane = evaluate_effect_decision(
        EffectDecisionRequest(
            factors=(
                *native_classification_factors,
                *current_decision_factors,
                *((contained_routine_candidate,) if contained_routine_candidate is not None else ()),
                *((verified_read_candidate,) if verified_read_candidate is not None else ()),
                *workspace_write_candidates,
                *critical_floor_factors,
                *read_factors,
                *(control_resolution.factors if apply_control_fail_closed else ()),
                *explicit_permission_allow_factors,
            ),
            uncertainties=decision_uncertainties,
        )
    )
    # The central decision plane includes intrinsic native evidence and
    # non-extension factors that are intentionally absent from the legacy
    # rule-floor accumulator. Public/runtime consumers must receive the
    # strongest materialized floor rather than an internally contradictory
    # ``minimum_action=allow`` with ``decision_plane.action=review``.
    minimum_action = _stronger_floor(minimum_action, _decision_action_floor(decision_plane.action))
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


def _native_classification_factors(
    value: object,
    command: CanonicalCommand,
    *,
    allow_benign_proof: bool = True,
) -> tuple[DecisionFactor, ...]:
    """Carry native hard blocks and benign proof into host policy composition.

    Called only after request/control-bound native observation validation.
    It supplies the positive proof missing from an otherwise empty policy
    request; independent restrictive factors still win in the reducer.
    """
    if not isinstance(value, dict):
        return ()
    blocked = value.get("minimum_action") == "block"
    privileged_wrapper_reapproval = (
        value.get("minimum_action") == "require-reapproval"
        and value.get("reason_code") == "native_privileged_wrapper_reapproval"
    )
    explicitly_benign = (
        allow_benign_proof
        and command.confidence == "exact"
        and value.get("minimum_action") == "allow"
        and value.get("explicitly_benign") is True
    )
    factors: list[DecisionFactor] = []
    if blocked or privileged_wrapper_reapproval or explicitly_benign:
        digest = hashlib.sha256(
            json.dumps(
                {
                    "schema": "guard.native-classification-projection.v1",
                    "command_security_identity": command.security_identity,
                    "command_extensions": value["command_extensions"],
                    "minimum_action": (
                        "block" if blocked else "require-reapproval" if privileged_wrapper_reapproval else "allow"
                    ),
                    "explicitly_benign": explicitly_benign,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if blocked:
            factors.append(
                DecisionFactor(
                    source=DecisionFactorSource.ASSURANCE,
                    reason_code="native.classification-block",
                    basis=DecisionBasis("block", None),
                    producer_ref="native:command-classification",
                    evidence_digest=digest,
                )
            )
        elif privileged_wrapper_reapproval:
            factors.append(
                DecisionFactor(
                    source=DecisionFactorSource.ASSURANCE,
                    reason_code="native.privileged-wrapper-reapproval",
                    basis=DecisionBasis("require-reapproval", None),
                    producer_ref="native:command-classification",
                    evidence_digest=digest,
                )
            )
        else:
            proof = PositiveProof(
                ProofRoute.VERIFIED,
                digest,
                frozenset({ProofRequirement.CONFIGURATION_IDENTITY, ProofRequirement.PARSER_CONFIDENCE}),
            )
            factors.append(
                DecisionFactor(
                    source=DecisionFactorSource.ASSURANCE,
                    reason_code="native.explicit-benign",
                    basis=DecisionBasis("allow", ProofRoute.VERIFIED),
                    producer_ref="native:command-classification",
                    evidence_digest=digest,
                    proof=proof,
                )
            )
    return tuple(factors)


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
    # Required extensions may also contain configurable, noncritical rules
    # whose declared baseline is allow. They still need positive allow proof.
    if rule.default_mode == "disabled":
        return "allow"
    if owned.extension.required:
        return "review"
    return _MODE_FLOOR[rule.default_mode]


def _stronger_floor(left: CommandDecisionFloor, right: CommandDecisionFloor) -> CommandDecisionFloor:
    return left if _FLOOR_RANK[left] >= _FLOOR_RANK[right] else right


def _decision_action_floor(action: str) -> CommandDecisionFloor:
    if action == "allow":
        return "allow"
    if action == "warn":
        return "monitor"
    if action == "block":
        return "block"
    return "review"


def _match_precedence_key(owned: OwnedCommandRuleMatch) -> tuple[int, int, int]:
    return (
        _FLOOR_RANK[_rule_floor(owned)],
        _SEVERITY_RANK[owned.match.rule.severity],
        0 if owned.match.rule.compatibility_fallback else 1,
    )
