"""Composite command evaluation, resident-owned (RTM-008).

The resident's ``command_effect_decide`` op owns the effect lattice, the
positive-proof/uncertainty/extension precedence, extension-control resolution
and the local read/write/Git/workflow floors. This module sends one bound
request and projects the answer onto the Python records callers already use.
It never recomputes, relaxes, or falls back to a Python evaluator: anything
other than a bound ``ok`` result raises.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .. import native_context
from ..models import GuardAction
from ..native_command_effect import (
    COMMAND_EFFECT_BATCH_MAX_ITEMS,
    NATIVE_COMMAND_CONTROL_BINDING_SCHEMA,
    CommandEffectItem,
    NativeCommandEffectMalformedError,
    NativeCommandEffectRejectedError,
    command_effect_decide_batch_native,
    command_effect_decide_native,
    wire_canonical_command,
)
from .command_evaluation_types import (
    CommandDecisionFloor as CommandDecisionFloor,
)
from .command_evaluation_types import (
    CommandRuleMatch as CommandRuleMatch,
)
from .command_evaluation_types import (
    CompositeCommandEvaluation as CompositeCommandEvaluation,
)
from .command_evaluation_types import (
    OwnedCommandRuleMatch as OwnedCommandRuleMatch,
)
from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .command_model import CanonicalCommand
from .effect_contract import DecisionBasis, ProofRoute, UncertaintyKind
from .effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    DecisionReason,
    EffectDecision,
    FinalDisposition,
)
from .extension_control_contract import (
    ComposedExtensionControls,
    ControlLayerKind,
    ControlResolution,
    ControlResolverFailure,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ResolverFailureCode,
)
from .extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    _layer_payload,  # pyright: ignore[reportPrivateUsage]
    current_extension_control_snapshot,
)
from .github_workflow_authorization import GitHubWorkflowAuthorization
from .native_command_extension_evidence import (
    NativeCommandExtensionEvidenceError,
    NativeCommandExtensionObservation,
    NativeMatcherEvidence,
    NativeSafeVariantObservation,
)

_FLOORS = frozenset({"allow", "monitor", "review", "block"})
_UNAVAILABLE = "native_command_effect_unavailable"
_Obj = Mapping[str, object]


@dataclass(frozen=True)
class CommandEvaluationInput:
    """One command's inputs for ``evaluate_commands_batch``."""

    command_text: str
    canonical_command: CanonicalCommand
    native_extension_evidence: object
    extension_control_snapshot: ExtensionControlRuntimeSnapshot
    cwd: Path | None = None
    home_dir: Path | None = None
    compatibility_action_class: str | None = None
    compatibility_reason: str | None = None
    workflow_authorization: GitHubWorkflowAuthorization | None = None


def _wire_item(
    entry: CommandEvaluationInput,
) -> tuple[CommandEffectItem, dict[str, object]]:
    if entry.native_extension_evidence is None:
        raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_required")
    if not isinstance(entry.native_extension_evidence, dict):
        raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_invalid")
    evidence = cast(dict[str, object], entry.native_extension_evidence)
    workflow = entry.workflow_authorization
    item = CommandEffectItem(
        command_text=entry.command_text,
        canonical_command=wire_canonical_command(entry.canonical_command.to_dict()),
        native_extension_evidence=evidence,
        control_snapshot=_control_binding(evidence, entry.extension_control_snapshot),
        compatibility_action_class=entry.compatibility_action_class,
        compatibility_reason=entry.compatibility_reason,
        workflow_authorization=workflow.to_wire() if workflow is not None else None,
        cwd=entry.cwd,
        home_dir=entry.home_dir,
    )
    return item, evidence


def _resolve_home(guard_home: Path | None) -> Path:
    home = guard_home or native_context.context_digest_guard_home()
    if home is None:
        from ..config import resolve_guard_home

        home = resolve_guard_home()
    return home


def evaluate_command(
    command_text: str,
    *,
    canonical_command: CanonicalCommand | None = None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    workflow_authorization: GitHubWorkflowAuthorization | None = None,
    native_extension_evidence: object | None = None,
    extension_control_snapshot: ExtensionControlRuntimeSnapshot | None = None,
    guard_home: Path | None = None,
    counterfactual_enabled_permission_ids: Sequence[str] = (),
) -> CompositeCommandEvaluation:
    """Evaluate one command through the resident without executing or persisting it.

    ``counterfactual_enabled_permission_ids`` asks the resident to treat those
    permissions as enabled for this evaluation only; the snapshot stays the
    authenticated one the native evidence is bound to.
    """

    snapshot = extension_control_snapshot or current_extension_control_snapshot()
    if native_extension_evidence is None:
        raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_required")
    if canonical_command is None:
        raise NativeCommandExtensionEvidenceError("native_canonical_command_required")
    if snapshot is None:
        raise NativeCommandExtensionEvidenceError("native_command_control_snapshot_required")
    item, _ = _wire_item(
        CommandEvaluationInput(
            command_text=command_text,
            canonical_command=canonical_command,
            native_extension_evidence=native_extension_evidence,
            extension_control_snapshot=snapshot,
            cwd=cwd,
            home_dir=home_dir,
            compatibility_action_class=compatibility_action_class,
            compatibility_reason=compatibility_reason,
            workflow_authorization=workflow_authorization,
        )
    )
    try:
        payload = command_effect_decide_native(
            command_text=item.command_text,
            canonical_command=item.canonical_command,
            native_extension_evidence=item.native_extension_evidence,
            control_snapshot=item.control_snapshot,
            guard_home=_resolve_home(guard_home),
            compatibility_action_class=item.compatibility_action_class,
            compatibility_reason=item.compatibility_reason,
            workflow_authorization=item.workflow_authorization,
            cwd=item.cwd,
            home_dir=item.home_dir,
            counterfactual_enabled_permission_ids=counterfactual_enabled_permission_ids,
        )
    except NativeCommandEffectRejectedError as error:
        raise NativeCommandExtensionEvidenceError(error.code) from error
    if payload is None:
        raise NativeCommandExtensionEvidenceError(_UNAVAILABLE)
    return _project_payload(payload, canonical_command, snapshot)


def evaluate_commands_batch(
    entries: Sequence[CommandEvaluationInput],
    *,
    guard_home: Path | None = None,
) -> tuple[CompositeCommandEvaluation, ...]:
    """Evaluate many commands in few resident round trips, for offline corpora.

    Each command is judged by the single-op rules and projected exactly as
    ``evaluate_command`` projects it; any refusal or unavailable resident
    raises the same error the single path raises. Hook callers do not use this.
    """

    if not entries:
        return ()
    home = _resolve_home(guard_home)
    results: list[CompositeCommandEvaluation] = []
    # One wire group at a time: request bytes and parsed payloads are released
    # as each group is projected, so peak memory tracks the group, not the list.
    for start in range(0, len(entries), COMMAND_EFFECT_BATCH_MAX_ITEMS):
        group = entries[start : start + COMMAND_EFFECT_BATCH_MAX_ITEMS]
        outcomes = command_effect_decide_batch_native([_wire_item(entry)[0] for entry in group], guard_home=home)
        if outcomes is None:
            raise NativeCommandExtensionEvidenceError(_UNAVAILABLE)
        for entry, outcome in zip(group, outcomes, strict=True):
            if isinstance(outcome, NativeCommandEffectRejectedError):
                raise NativeCommandExtensionEvidenceError(outcome.code) from outcome
            results.append(_project_payload(outcome, entry.canonical_command, entry.extension_control_snapshot))
        del outcomes
    return tuple(results)


def _project_payload(
    payload: _Obj,
    command: CanonicalCommand,
    snapshot: ExtensionControlRuntimeSnapshot,
) -> CompositeCommandEvaluation:
    try:
        return _project(payload, command, snapshot)
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise NativeCommandEffectMalformedError("command_effect payload failed projection") from error


def _control_binding(evidence: _Obj, snapshot: ExtensionControlRuntimeSnapshot) -> dict[str, object]:
    """Bind the authenticated snapshot to the resident-attested program identity.

    The effective digest is carried as-is: the resident cross-checks it against
    the evidence binding, and Python never recomputes it.
    """

    extensions = evidence.get("command_extensions")
    binding = extensions.get("binding") if isinstance(extensions, dict) else None
    if not isinstance(binding, dict):
        raise NativeCommandExtensionEvidenceError("native_command_extension_evidence_invalid")
    return {
        "schema": NATIVE_COMMAND_CONTROL_BINDING_SCHEMA,
        "program_digest": binding.get("program_digest"),
        "catalog_digest": binding.get("catalog_digest"),
        "trust_digest": binding.get("trust_digest"),
        "health": snapshot.health.value,
        "revision": snapshot.revision,
        "managed_revision": snapshot.managed_revision,
        "effective_digest": snapshot.effective_digest,
        "layers": sorted((_layer_payload(layer) for layer in snapshot.layers), key=lambda item: str(item["kind"])),
    }


def _items(value: object) -> list[_Obj]:
    return cast("list[_Obj]", value)


def _project(
    payload: _Obj,
    command: CanonicalCommand,
    snapshot: ExtensionControlRuntimeSnapshot,
) -> CompositeCommandEvaluation:
    minimum_action = payload["minimum_action"]
    if minimum_action not in _FLOORS:
        raise ValueError("minimum_action")
    observations = tuple(_observation(item) for item in _items(payload["extension_observations"]))
    matches = tuple(_match(item, command) for item in _items(payload["matches"]))
    return CompositeCommandEvaluation(
        command=command,
        matches=matches,
        controlling_action_class=cast("str | None", payload["controlling_action_class"]),
        controlling_reason=cast("str | None", payload["controlling_reason"]),
        controlling_rule_id=cast("str | None", payload["controlling_rule_id"]),
        minimum_action=cast(CommandDecisionFloor, minimum_action),
        extension_observations=observations,
        decision_plane=_decision(cast(_Obj, payload["decision_plane"])),
        baseline_decision=_decision(cast(_Obj, payload["baseline_decision"])),
        risk_classes=tuple(cast("list[str]", payload["risk_classes"])),
        control_resolution=_control_resolution(cast(_Obj, payload["control_resolution"]), observations),
        private_control_evidence=snapshot.private_evidence,
    )


def _identity(extension_id: object, rule_id: object):
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    extension = registry.get(cast(str, extension_id))
    rule = registry.get_rule(cast(str, rule_id))
    if extension is None or rule is None or rule not in extension.rules:
        raise ValueError("unknown extension or rule identity")
    return extension, rule


def _evidence(value: object) -> tuple[NativeMatcherEvidence, ...]:
    return tuple(
        NativeMatcherEvidence(
            cast(int, item["segment_index"]),
            cast("str | None", item["executable"]),
            cast(str, item["detail"]),
        )
        for item in _items(value)
    )


def _match(raw: _Obj, command: CanonicalCommand) -> OwnedCommandRuleMatch:
    extension, rule = _identity(raw["extension_id"], raw["rule_id"])
    return OwnedCommandRuleMatch(
        extension=extension,
        match=CommandRuleMatch(
            rule=rule,
            action_class=cast("str | None", raw["action_class"]),
            reason=cast(str, raw["reason"]),
            command=command,
            matcher_evidence=_evidence(raw["matcher_evidence"]),
        ),
    )


def _observation(raw: _Obj) -> NativeCommandExtensionObservation:
    extension, rule = _identity(raw["extension_id"], raw["rule_id"])
    return NativeCommandExtensionObservation(
        extension=extension,
        rule=rule,
        matcher_evidence=_evidence(raw["matcher_evidence"]),
        safe_variants=tuple(
            NativeSafeVariantObservation(cast(str, item["variant_id"]), _evidence(item["matcher_evidence"]))
            for item in _items(raw["safe_variants"])
        ),
        uncertainty_reasons=tuple(UncertaintyKind(item) for item in cast("list[str]", raw["uncertainty_reasons"])),
    )


def _reason(raw: _Obj) -> DecisionReason:
    return DecisionReason(
        DecisionFactorSource(cast(str, raw["source"])),
        cast(str, raw["reason_code"]),
        cast(GuardAction, raw["action_floor"]),
        cast("str | None", raw["segment_ref"]),
        cast("str | None", raw["operation_ref"]),
    )


def _decision(raw: _Obj) -> EffectDecision:
    return EffectDecision(
        action=cast(GuardAction, raw["action"]),
        disposition=FinalDisposition(cast(str, raw["disposition"])),
        controlling_reasons=tuple(_reason(item) for item in _items(raw["controlling_reasons"])),
        reasons=tuple(_reason(item) for item in _items(raw["reasons"])),
        proof_routes=frozenset(ProofRoute(item) for item in cast("list[str]", raw["proof_routes"])),
        schema_version=cast(str, raw["schema_version"]),
    )


def _failure(raw: _Obj) -> ControlResolverFailure:
    layer_kind = raw.get("layer_kind")
    return ControlResolverFailure(
        ResolverFailureCode(cast(str, raw["code"])),
        ControlLayerKind(cast(str, layer_kind)) if layer_kind is not None else None,
    )


def _factor(raw: _Obj) -> DecisionFactor:
    if raw.get("assessment") is not None or raw.get("proof") is not None:
        raise ValueError("control factors carry no assessment or proof")
    basis = cast(_Obj, raw["basis"])
    route = basis.get("proof_route")
    return DecisionFactor(
        source=DecisionFactorSource(cast(str, raw["source"])),
        reason_code=cast(str, raw["reason_code"]),
        basis=DecisionBasis(cast(GuardAction, basis["action_floor"]), ProofRoute(route) if route is not None else None),
        segment_ref=cast("str | None", raw.get("segment_ref")),
        operation_ref=cast("str | None", raw.get("operation_ref")),
        producer_ref=cast("str | None", raw.get("producer_ref")),
        evidence_digest=cast("str | None", raw.get("evidence_digest")),
    )


def _control_resolution(
    raw: _Obj,
    observations: tuple[NativeCommandExtensionObservation, ...],
) -> ControlResolution:
    composed = cast(_Obj, raw["composed"])
    return ControlResolution(
        composed=ComposedExtensionControls(
            global_lockdown=cast(bool, composed["global_lockdown"]),
            controls=tuple(
                ExtensionControl(
                    ControlTarget(ControlTargetKind(cast(str, item["target_kind"])), cast(str, item["target_id"])),
                    ControlState(cast(str, item["state"])),
                )
                for item in _items(composed["controls"])
            ),
            failures=tuple(_failure(item) for item in _items(composed["failures"])),
        ),
        blocked=cast(bool, raw["blocked"]),
        factors=tuple(_factor(item) for item in _items(raw["factors"])),
        failures=tuple(_failure(item) for item in _items(raw["failures"])),
        observations=tuple(f"{item.extension.extension_id}:{item.rule.rule_id}" for item in observations),
        explicitly_enabled_permission_ids=tuple(cast("list[str]", raw["explicitly_enabled_permission_ids"])),
    )
