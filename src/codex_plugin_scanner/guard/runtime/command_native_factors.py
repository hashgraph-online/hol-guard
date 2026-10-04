"""Native authority and explicit permission factors for command policy."""

from __future__ import annotations

import hashlib
import json

from .command_model import CanonicalCommand
from .effect_contract import DecisionBasis, ProofRequirement, ProofRoute
from .effect_decision import DecisionFactor, DecisionFactorSource, PositiveProof
from .extension_control_contract import ExtensionControlLayer
from .extension_control_runtime import ExtensionControlDecisionEvidence
from .github_capability_contract import github_capability_contract
from .github_command_capabilities import classify_github_cli


def _native_classification_factors(
    value: object,
    command: CanonicalCommand,
    *,
    allow_benign_proof: bool = True,
) -> tuple[DecisionFactor, ...]:
    """Carry native hard blocks, reapproval, and benign proof into host policy composition.

    Called only after request/control-bound native observation validation.
    It supplies the positive proof missing from an otherwise empty policy
    request; independent restrictive factors still win in the reducer.
    """
    if not isinstance(value, dict):
        return ()
    blocked = value.get("minimum_action") == "block"
    requires_reapproval = value.get("minimum_action") == "require-reapproval"
    reapproval_reason = (
        "native.privileged-wrapper-reapproval"
        if value.get("reason_code") == "native_privileged_wrapper_reapproval"
        else "native.classification-reapproval"
    )
    explicitly_benign = (
        allow_benign_proof
        and command.confidence == "exact"
        and value.get("minimum_action") == "allow"
        and value.get("explicitly_benign") is True
    )
    factors: list[DecisionFactor] = []
    if blocked or requires_reapproval or explicitly_benign:
        digest = hashlib.sha256(
            json.dumps(
                {
                    "schema": "guard.native-classification-projection.v1",
                    "command_security_identity": command.security_identity,
                    "command_extensions": value["command_extensions"],
                    "minimum_action": (
                        "block" if blocked else "require-reapproval" if requires_reapproval else "allow"
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
        elif requires_reapproval:
            factors.append(
                DecisionFactor(
                    source=DecisionFactorSource.ASSURANCE,
                    reason_code=reapproval_reason,
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
