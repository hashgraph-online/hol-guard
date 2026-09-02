"""Typed, deterministic action-explanation builder for Guard Core.

The builder consumes the authoritative typed action envelope plus an optional
CanonicalCommand. It does not execute, authorize, or classify policy. Policy and
decision data can add reason context only after action semantics are established.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import cast

from codex_plugin_scanner.guard.redaction import redact_text

from .action_explanation_contract import (
    ACTION_EXPLANATION_REDACTION_VERSION,
    ACTION_EXPLANATION_RENDERER_VERSION,
    GuardActionExplanationV1,
    parse_action_explanation,
)
from .command_model import CanonicalCommand
from .semantic_explanations import (
    CommandSemanticInput,
    explain_command,
    stable_semantic_catalog_digest,
)


@dataclass(frozen=True, slots=True)
class ActionSemanticFacts:
    """Intermediate facts kept separate from rendered prose."""

    action_identity: str
    canonical_identity: str | None
    actor_label: str
    action_type: str | None
    tool_name: str | None
    command: str | None
    executable: str | None
    arguments: tuple[str, ...]
    operands: tuple[str, ...]
    target_paths: tuple[str, ...]
    network_hosts: tuple[str, ...]
    package_names: tuple[str, ...]
    remote_targets: tuple[str, ...]
    extension_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    risk_signals: tuple[str, ...]
    decision_reason_codes: tuple[str, ...]
    policy_source: str | None
    parse_confidence: str | None
    dialect: str | None
    transport: str | None
    working_scope_display: str | None
    retained: bool
    exact_details_authorized: bool


@dataclass(frozen=True, slots=True)
class ExplanationBuildContext:
    """Reason/outcome context that must never be used to infer action intent."""

    reason_codes: tuple[str, ...] = ()
    policy_source: str | None = None
    proof_level: str | None = None
    receipt_id: str | None = None
    locale: str = "en-US"


def semantic_facts_from_action(
    *,
    action_envelope: Mapping[str, object],
    action_identity: str,
    actor_label: str,
    canonical_command: CanonicalCommand | None = None,
    risk_signals: Sequence[str] = (),
    extension_ids: Sequence[str] = (),
    rule_ids: Sequence[str] = (),
    build_context: ExplanationBuildContext | None = None,
    retained: bool = True,
    exact_details_authorized: bool = False,
) -> ActionSemanticFacts:
    """Extract bounded typed facts without reinterpreting policy outcome."""

    context = build_context or ExplanationBuildContext()
    command = _optional_text(action_envelope.get("command"))
    target_paths = _string_tuple(action_envelope.get("target_paths"))
    network_hosts = _string_tuple(action_envelope.get("network_hosts"))
    package_names = _string_tuple(action_envelope.get("package_names"))
    package_name = _optional_text(action_envelope.get("package_name"))
    if package_name and package_name not in package_names:
        package_names = (*package_names, package_name)
    remote_targets = _string_tuple(action_envelope.get("remote_targets"))
    operands = _string_tuple(action_envelope.get("operands"))

    executable: str | None = None
    arguments: tuple[str, ...] = ()
    canonical_identity: str | None = None
    parse_confidence: str | None = None
    dialect = _optional_text(action_envelope.get("dialect"))
    transport = _optional_text(action_envelope.get("transport"))
    if canonical_command is not None:
        canonical_identity = canonical_command.security_identity
        parse_confidence = canonical_command.confidence
        dialect = canonical_command.dialect
        transport = canonical_command.transport
        if canonical_command.segments:
            segment = canonical_command.segments[0]
            executable = segment.executable
            arguments = tuple(segment.arguments)

    return ActionSemanticFacts(
        action_identity=_bounded_text(action_identity, 512),
        canonical_identity=canonical_identity,
        actor_label=_bounded_text(actor_label, 120),
        action_type=_optional_text(action_envelope.get("action_type")),
        tool_name=_optional_text(action_envelope.get("tool_name")),
        command=command,
        executable=executable,
        arguments=arguments,
        operands=_bounded_tuple(operands, 128, 512),
        target_paths=_bounded_tuple(target_paths, 32, 1024),
        network_hosts=_bounded_tuple(network_hosts, 32, 253),
        package_names=_bounded_tuple(package_names, 32, 256),
        remote_targets=_bounded_tuple(remote_targets, 32, 512),
        extension_ids=_bounded_tuple(tuple(extension_ids), 64, 128),
        rule_ids=_bounded_tuple(tuple(rule_ids), 64, 128),
        risk_signals=_bounded_tuple(tuple(risk_signals), 64, 256),
        decision_reason_codes=_bounded_tuple(context.reason_codes, 64, 128),
        policy_source=_bounded_optional(context.policy_source, 128),
        parse_confidence=parse_confidence,
        dialect=_bounded_optional(dialect, 64),
        transport=_bounded_optional(transport, 64),
        working_scope_display=_bounded_optional(_optional_text(action_envelope.get("working_scope")), 500),
        retained=retained,
        exact_details_authorized=exact_details_authorized,
    )


def build_action_explanation(
    *,
    action_envelope: Mapping[str, object],
    action_identity: str,
    actor_label: str,
    canonical_command: CanonicalCommand | None = None,
    risk_signals: Sequence[str] = (),
    extension_ids: Sequence[str] = (),
    rule_ids: Sequence[str] = (),
    build_context: ExplanationBuildContext | None = None,
    retained: bool = True,
    exact_details_authorized: bool = False,
) -> GuardActionExplanationV1:
    """Render the typed action using deterministic Core semantics."""

    context = build_context or ExplanationBuildContext()
    facts = semantic_facts_from_action(
        action_envelope=action_envelope,
        action_identity=action_identity,
        actor_label=actor_label,
        canonical_command=canonical_command,
        risk_signals=risk_signals,
        extension_ids=extension_ids,
        rule_ids=rule_ids,
        build_context=context,
        retained=retained,
        exact_details_authorized=exact_details_authorized,
    )
    if canonical_command is not None and len(canonical_command.segments) > 1:
        return _build_compound_explanation(facts, canonical_command, context)
    return _build_single_explanation(facts, context, canonical_command)


def action_explanation_cache_key(
    *,
    action_identity: str,
    canonical_identity: str | None,
    catalog_digest: str | None = None,
    renderer_version: str = ACTION_EXPLANATION_RENDERER_VERSION,
    locale: str = "en-US",
    redaction_version: str = ACTION_EXPLANATION_REDACTION_VERSION,
) -> str:
    """Build a stable cache identity from all explanation compatibility inputs."""

    material = {
        "action_identity": action_identity,
        "canonical_identity": canonical_identity,
        "catalog_digest": catalog_digest or stable_semantic_catalog_digest(),
        "renderer_version": renderer_version,
        "locale": locale,
        "redaction_version": redaction_version,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def explanation_matches_current_action(
    explanation: GuardActionExplanationV1,
    *,
    action_identity: str,
    canonical_identity: str | None,
    catalog_digest: str | None = None,
) -> bool:
    if explanation.action_identity != action_identity:
        return False
    if canonical_identity is not None and explanation.canonical_identity != canonical_identity:
        return False
    if catalog_digest is not None and explanation.catalog_digest != catalog_digest:
        return False
    return True


def _build_single_explanation(
    facts: ActionSemanticFacts,
    context: ExplanationBuildContext,
    canonical_command: CanonicalCommand | None,
) -> GuardActionExplanationV1:
    normalized = canonical_command.normalized_text if canonical_command is not None else facts.command
    explanation = explain_command(
        CommandSemanticInput(
            action_identity=facts.action_identity,
            canonical_identity=facts.canonical_identity,
            actor_label=facts.actor_label,
            executable=facts.executable,
            arguments=facts.arguments,
            operands=facts.operands,
            target_paths=facts.target_paths,
            network_hosts=facts.network_hosts,
            package_names=facts.package_names,
            remote_targets=facts.remote_targets,
            command_display=facts.command,
            normalized_command_display=normalized,
            dialect=facts.dialect,
            transport=facts.transport,
            working_scope_display=facts.working_scope_display,
            extension_ids=facts.extension_ids,
            rule_ids=facts.rule_ids,
            reason_codes=(*facts.decision_reason_codes, *facts.risk_signals),
            policy_source=facts.policy_source,
            parse_confidence=facts.parse_confidence,
            proof_level=context.proof_level,
            receipt_id=context.receipt_id,
            exact_details_authorized=facts.exact_details_authorized,
            retained=facts.retained,
        )
    )
    if context.locale == "en-US":
        return explanation
    payload = explanation.to_dict()
    payload["locale"] = _bounded_text(context.locale, 32)
    return parse_action_explanation(cast(dict[str, object], payload))


def _build_compound_explanation(
    facts: ActionSemanticFacts,
    command: CanonicalCommand,
    context: ExplanationBuildContext,
) -> GuardActionExplanationV1:
    step_explanations: list[GuardActionExplanationV1] = []
    for index, segment in enumerate(command.segments[:16], start=1):
        step_explanations.append(
            explain_command(
                CommandSemanticInput(
                    action_identity=f"{facts.action_identity}:step:{index}",
                    canonical_identity=facts.canonical_identity,
                    actor_label=facts.actor_label,
                    executable=segment.executable,
                    arguments=tuple(segment.arguments),
                    operands=tuple(segment.arguments),
                    target_paths=facts.target_paths,
                    network_hosts=facts.network_hosts,
                    package_names=facts.package_names,
                    remote_targets=facts.remote_targets,
                    exact_details_authorized=False,
                    retained=facts.retained,
                )
            )
        )
    material = [step for step in step_explanations if step.kind != "unknown_action"]
    steps = material if material else step_explanations
    headline = f"Review {len(command.segments)} ordered actions"
    labels = [step.everyday.headline.rstrip(".") for step in steps[:4]]
    summary = f"{facts.actor_label} wants to run several actions in order"
    if labels:
        summary += ": " + "; then ".join(labels)
    if len(command.segments) > len(labels):
        summary += f"; plus {len(command.segments) - len(labels)} more step(s)"
    summary += "."
    consequences = []
    alternatives = []
    targets = []
    uncertainty: list[str] = []
    for step in steps:
        consequences.extend(step.everyday.consequences)
        alternatives.extend(step.everyday.safer_alternatives)
        targets.extend(step.everyday.targets)
        uncertainty.extend(step.uncertainty_reasons)
    if len(command.segments) > 16:
        uncertainty.append("compound_step_limit_exceeded")
    technical_available = bool(facts.retained and facts.exact_details_authorized and facts.command)
    redacted_command = redact_text(facts.command or "")
    technical_segments = []
    if technical_available:
        for segment in command.segments[:16]:
            technical_segments.append(
                {
                    "executable": _bounded_optional(segment.executable, 240),
                    "arguments_display": [
                        _bounded_text(redact_text(value).text, 240) for value in segment.arguments[:128]
                    ],
                    "execution_context": _bounded_text(segment.execution_context, 64),
                    "pipeline_index": segment.pipeline_index,
                }
            )
    unavailable_reason: str | None
    if technical_available:
        unavailable_reason = None
    elif not facts.retained:
        unavailable_reason = "not_retained"
    else:
        unavailable_reason = "not_authorized"
    payload = {
        "schema_version": "guard.action-explanation.v1",
        "explanation_version": "1.0.0",
        "renderer_version": ACTION_EXPLANATION_RENDERER_VERSION,
        "action_identity": facts.action_identity,
        "canonical_identity": facts.canonical_identity,
        "catalog_digest": stable_semantic_catalog_digest(),
        "locale": context.locale,
        "kind": "compound_action",
        "confidence": "limited" if uncertainty else "derived",
        "uncertainty_reasons": list(dict.fromkeys(uncertainty))[:32],
        "everyday": {
            "headline_message_id": "guard.everyday.compound.headline",
            "headline": _bounded_text(headline, 240),
            "summary_message_id": "guard.everyday.compound.summary",
            "summary": _bounded_text(summary, 800),
            "impact_message_id": "guard.everyday.compound.impact",
            "impact": "Later steps can hide destructive or external side effects, so review each material action in order.",
            "why_guard_intervened_message_id": None,
            "why_guard_intervened": None,
            "recommendation_message_id": "guard.everyday.compound.recommendation",
            "recommendation": "Split the command into reviewable steps when possible and confirm each material action before running it.",
            "actor_label": facts.actor_label,
            "targets": [item.__dict__ if hasattr(item, "__dict__") else {"kind": item.kind, "label": item.label, "scope": item.scope, "sensitivity": item.sensitivity} for item in targets[:16]],
            "consequences": [
                {"message_id": item.message_id, "message": item.message, "severity": item.severity, "confirmed": item.confirmed}
                for item in consequences[:16]
            ],
            "safer_alternatives": [
                {"message_id": item.message_id, "message": item.message, "kind": item.kind}
                for item in _dedupe_alternatives(alternatives)[:10]
            ] + [
                {
                    "message_id": "guard.everyday.compound.alternative.split",
                    "message": "Split the command into ordered steps and review each material action.",
                    "kind": "preview",
                }
            ],
        },
        "technical": {
            "available": technical_available,
            "unavailable_reason": unavailable_reason,
            "action_type": "compound_action",
            "command_display": _bounded_optional(redacted_command.text if technical_available else None, 4096),
            "normalized_command_display": _bounded_optional(
                redact_text(command.normalized_text).text if technical_available else None, 4096
            ),
            "executable": None,
            "arguments_display": None,
            "dialect": command.dialect,
            "transport": command.transport,
            "working_scope_display": None,
            "wrappers": list(command.wrapper_chain[:32]),
            "segments": technical_segments,
            "extension_ids": list(facts.extension_ids),
            "rule_ids": list(facts.rule_ids),
            "reason_codes": list((*facts.decision_reason_codes, *facts.risk_signals)[:64]),
            "policy_source": facts.policy_source,
            "parse_confidence": command.confidence,
            "proof_level": context.proof_level,
            "receipt_id": context.receipt_id,
            "action_id": facts.action_identity,
        },
        "redaction": {
            "level": "redacted" if redacted_command.count or not technical_available else "none",
            "policy_version": ACTION_EXPLANATION_REDACTION_VERSION,
            "omitted_fields": [] if technical_available else ["technical.command_display", "technical.segments"],
            "truncated_fields": ["technical.segments"] if len(command.segments) > 16 else [],
            "secret_like_values_removed": redacted_command.count > 0,
        },
    }
    return parse_action_explanation(cast(dict[str, object], payload))


def _dedupe_alternatives(items: Sequence[object]) -> list[object]:
    seen: set[tuple[str, str]] = set()
    result: list[object] = []
    for item in items:
        message = getattr(item, "message", "")
        kind = getattr(item, "kind", "")
        key = (str(kind), str(message))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item).strip() for item in value if isinstance(item, str) and item.strip())


def _optional_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _bounded_tuple(values: Sequence[str], max_items: int, max_length: int) -> tuple[str, ...]:
    return tuple(_bounded_text(value, max_length) for value in values[:max_items])


def _bounded_optional(value: str | None, max_length: int) -> str | None:
    return None if value is None else _bounded_text(value, max_length)


def _bounded_text(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return value[: max_length - 1] + "…"
