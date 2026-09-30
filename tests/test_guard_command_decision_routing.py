"""Reducer tests over synthetic, wire-valid native evidence projections."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.runtime.command_decision_adapter import extension_evidence_batch
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_risk_effects import COMMAND_RISK_EFFECTS
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind, ProofRoute
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from codex_plugin_scanner.guard.runtime.native_command_extension_evidence import (
    NativeCommandExtensionEvidenceError,
)

_FLOOR = {"disabled": "allow", "monitor": "warn", "review": "review", "enforce": "block", "required": "review"}


def _synthetic_native_fixture(
    *,
    mode: str = "review",
    required: bool = False,
    severity: str = "high",
    risk_classes: tuple[str, ...] = ("destructive_shell",),
    safe: bool = False,
    uncertainty: bool = False,
    disabled: bool = False,
    command_text: str = "aws apigateway delete-rest-api --rest-api-id abc",
    evidence_indexes: tuple[int, ...] = (0,),
    safe_indexes: tuple[int, ...] | None = None,
    uncertain_command: bool = False,
    explicitly_benign: bool = False,
    native_minimum_action: str | None = None,
):
    source = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.api-gateway")
    assert source is not None
    rule = replace(
        source.rules[0],
        default_mode=mode,
        severity=severity,
        risk_classes=risk_classes,
    )
    permission = replace(
        source.permissions[0],
        baseline_floor=_FLOOR[mode],
        risk_tier=severity,
        rule_ids=(rule.rule_id,),
    )
    extension = replace(
        source,
        required=required,
        risk_classes=risk_classes,
        rules=(rule,),
        permissions=(permission,),
    )
    registry = GeneratedCommandCatalog(
        (extension,),
        program_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.program_digest,
        source_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.source_digest,
        implementation_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.implementation_digest,
    )
    layers = ()
    if disabled:
        layers = (
            ExtensionControlLayer(
                schema_version=CONTROL_SCHEMA_VERSION,
                kind=ControlLayerKind.LOCAL_ADMIN,
                catalog_digest=registry.catalog_digest,
                global_lockdown=False,
                controls=(
                    ExtensionControl(
                        ControlTarget(ControlTargetKind.EXTENSION, extension.extension_id),
                        ControlState.DISABLED,
                    ),
                ),
            ),
        )
    snapshot = ExtensionControlRuntimeSnapshot(
        AuthorityHealth.PROTECTED,
        1,
        registry.catalog_digest,
        "d" * 64,
        layers,
        0,
    )
    command = parse_shell_command(command_text)
    if uncertain_command:
        command = replace(command, confidence="uncertain", uncertainty_reason="native_test_uncertainty")
    evidence = [
        {
            "segment_index": index,
            "executable": "aws",
            "detail": "Matched bounded structured command constraints.",
        }
        for index in evidence_indexes
    ]
    safe_variants = []
    if safe:
        selected_safe_indexes = evidence_indexes if safe_indexes is None else safe_indexes
        safe_variants = [
            {
                "match_class": "safe-variant",
                "variant_id": rule.safe_variants[0].variant_id,
                "matcher_evidence": [item for item in evidence if item["segment_index"] in selected_safe_indexes],
            }
        ]
    observation = {
        "extension_id": extension.extension_id,
        "extension_version": extension.version,
        "rule_id": rule.rule_id,
        "rule_version": rule.rule_version,
        "match_class": "uncertainty" if uncertainty else "unsafe",
        "match_classes": ["unsafe", "uncertainty"] if uncertainty else ["unsafe"],
        "matcher_evidence": evidence,
        "safe_variants": safe_variants,
        "uncertainty_reasons": ["matcher-failure"] if uncertainty else [],
        "effective_segment_indexes": [
            index
            for index in evidence_indexes
            if not safe or index not in (evidence_indexes if safe_indexes is None else safe_indexes)
        ],
    }
    native = {
        "schema": "guard.native-command-observations.v1",
        "binding": {
            "schema": "guard.native-command-receipt-binding.v1",
            "program_digest": registry.program_digest,
            "catalog_digest": registry.catalog_digest,
            "trust_digest": "c" * 64,
            "control_revision": snapshot.revision,
            "managed_control_revision": snapshot.managed_revision,
            "control_effective_digest": snapshot.effective_digest,
            "observations_digest": "0" * 64,
            "observation_count": 1,
            "uncertainty_count": int(uncertainty),
        },
        "observations": [observation],
        "permission_observations": [],
        "evaluation_error": None,
    }
    canonical = json.dumps(
        {key: native[key] for key in ("observations", "permission_observations", "evaluation_error")},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    native["binding"]["observations_digest"] = hashlib.sha256(
        b"hol-guard.native-command-observations.v1\0" + canonical
    ).hexdigest()
    payload = {
        "command_model": {"normalized_text": command.normalized_text},
        "command_extensions": native,
        "minimum_action": native_minimum_action or ("allow" if explicitly_benign else "review"),
        "explicitly_benign": explicitly_benign,
    }
    return registry, snapshot, command, payload


def _evaluate(**kwargs):
    registry, snapshot, command, payload = _synthetic_native_fixture(**kwargs)
    return evaluate_command(
        command.normalized_text,
        canonical_command=command,
        registry=registry,
        extension_control_snapshot=snapshot,
        native_extension_evidence=payload,
    )


def test_native_evidence_cannot_fall_back_to_python_semantic_parsing() -> None:
    registry, snapshot, command, payload = _synthetic_native_fixture()
    with pytest.raises(RuntimeError, match="native canonical command model is required"):
        evaluate_command(
            command.normalized_text,
            registry=registry,
            extension_control_snapshot=snapshot,
            native_extension_evidence=payload,
        )


@pytest.mark.parametrize(
    ("mode", "legacy", "plane"),
    [
        ("disabled", "review", "review"),
        ("monitor", "review", "review"),
        ("review", "review", "review"),
        ("enforce", "block", "block"),
        ("required", "review", "review"),
    ],
)
def test_generated_rule_floor_is_preserved_without_permissive_proof(mode: str, legacy: str, plane: str) -> None:
    evaluation = _evaluate(mode=mode)
    assert evaluation.minimum_action == legacy
    assert evaluation.decision_plane.action == plane


def test_native_uncertainty_is_typed_blocking_and_private() -> None:
    evaluation = _evaluate(mode="disabled", uncertainty=True)
    assert evaluation.minimum_action == "block"
    payload = evaluation.extension_observations[0].to_dict()
    assert payload["match_class"] == "uncertainty"
    assert payload["uncertainty_reasons"] == ["matcher-failure"]
    assert "private" not in repr(evaluation.to_dict())


def test_native_safe_variant_remains_visible_and_suppresses_only_its_segment() -> None:
    evaluation = _evaluate(safe=True)
    observation = evaluation.extension_observations[0]
    assert observation.safe_variants
    assert observation.effective_evidence == ()
    assert evaluation.matches == ()


def test_partial_native_safe_evidence_cannot_silence_matcher_uncertainty() -> None:
    # Python matcher callbacks no longer exist. This is the wire-level native
    # replacement for the former "one safe matcher fails" callback test: an
    # authenticated partial safe projection still carries native uncertainty.
    evaluation = _evaluate(
        command_text=(
            "aws apigateway delete-rest-api --rest-api-id abc && aws apigateway delete-rest-api --rest-api-id def"
        ),
        evidence_indexes=(0, 1),
        safe=True,
        safe_indexes=(0,),
        uncertainty=True,
    )
    observation = evaluation.extension_observations[0]
    assert tuple(item.segment_index for item in observation.effective_evidence) == (1,)
    assert observation.uncertainty_reasons
    assert evaluation.minimum_action == "block"
    assert evaluation.decision_plane.action == "block"


def test_adapter_rejects_out_of_bounds_native_matcher_evidence() -> None:
    # Native evidence is rejected at admission; the adapter never normalizes
    # attacker-controlled indexes into a projected match.
    with pytest.raises(NativeCommandExtensionEvidenceError, match="native_command_extension_evidence_invalid"):
        _evaluate(evidence_indexes=(128,))


def test_uncertain_command_cannot_claim_native_parser_confidence_proof() -> None:
    evaluation = _evaluate(safe=True, uncertain_command=True, explicitly_benign=True)
    assert ProofRoute.VERIFIED not in evaluation.decision_plane.proof_routes
    assert evaluation.decision_plane.action != "allow"


def test_explicit_benign_cannot_discharge_unrelated_enforced_rule() -> None:
    evaluation = _evaluate(mode="enforce", explicitly_benign=True)
    assert evaluation.minimum_action == "block"
    assert evaluation.decision_plane.action == "block"


def test_explicit_benign_cannot_discharge_native_block_or_matcher_uncertainty() -> None:
    native_block = _evaluate(explicitly_benign=True, native_minimum_action="block")
    uncertain = _evaluate(mode="disabled", explicitly_benign=True, uncertainty=True)
    assert native_block.decision_plane.action == "block"
    assert uncertain.minimum_action == "block"
    assert uncertain.decision_plane.action == "block"


def test_explicit_benign_cannot_discharge_control_floor() -> None:
    evaluation = _evaluate(mode="disabled", explicitly_benign=True, disabled=True)
    assert evaluation.control_resolution.blocked
    assert evaluation.minimum_action == "block"
    assert evaluation.decision_plane.action == "block"


def test_public_projection_contains_versions_without_raw_command_or_private_detail() -> None:
    private_operand = "private-customer-name"
    evaluation = _evaluate(command_text=f"aws apigateway delete-rest-api --rest-api-id {private_operand}")
    payload = evaluation.to_dict()
    observations = payload["extension_observations"]
    assert isinstance(observations, list) and observations
    assert all(item["extension_version"] and item["rule_version"] for item in observations)
    assert private_operand not in repr(payload)
    assert "private matcher detail" not in repr(payload)


def test_disabled_extension_is_a_monotonic_blocking_factor() -> None:
    evaluation = _evaluate(mode="disabled", safe=True, disabled=True)
    assert evaluation.control_resolution.blocked
    assert evaluation.minimum_action == "block"
    assert evaluation.decision_plane.action == "block"


def test_required_extension_floors_remain_monotonic() -> None:
    evaluation = _evaluate(mode="disabled", required=True)
    assert evaluation.minimum_action == "review"
    assert ProofRoute.VERIFIED not in evaluation.decision_plane.proof_routes
    assert (_evaluate(mode="disabled", required=True, severity="critical").minimum_action) == "block"


@pytest.mark.parametrize("required", [False, True])
def test_noncritical_disabled_rule_requires_explicit_native_benign_proof_to_allow(required: bool) -> None:
    evaluation = _evaluate(mode="disabled", required=required, explicitly_benign=True)
    assert evaluation.minimum_action == "allow"
    assert evaluation.decision_plane.action == "allow"
    assert ProofRoute.VERIFIED in evaluation.decision_plane.proof_routes


def test_native_benign_proof_cannot_discharge_required_critical_disabled_rule() -> None:
    evaluation = _evaluate(mode="disabled", required=True, severity="critical", explicitly_benign=True)
    assert evaluation.minimum_action == "block"
    assert evaluation.decision_plane.action == "block"


def test_risk_effect_mapping_does_not_use_substring_classification() -> None:
    evaluation = _evaluate(risk_classes=("non-destructive",))
    batch = extension_evidence_batch(evaluation.command, evaluation.extension_observations)
    effects = frozenset(effect for item in batch.evidence for effect in item.effect_claims)
    assert EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION not in effects
    assert EffectKind.PROCESS_EXECUTION in effects


@pytest.mark.parametrize(("risk_class", "expected"), tuple(COMMAND_RISK_EFFECTS.items()))
def test_native_extension_evidence_uses_canonical_risk_effect_mapping(
    risk_class: str, expected: frozenset[EffectKind]
) -> None:
    evaluation = _evaluate(risk_classes=(risk_class,))
    batch = extension_evidence_batch(evaluation.command, evaluation.extension_observations)
    assert frozenset(effect for item in batch.evidence for effect in item.effect_claims) == expected
