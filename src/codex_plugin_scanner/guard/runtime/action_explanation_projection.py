"""Deterministic projections of persisted Guard action facts into Everyday explanations."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import cast

from codex_plugin_scanner.guard.redaction import redact_text

from .action_explanation_contract import (
    ACTION_EXPLANATION_REDACTION_VERSION,
    ACTION_EXPLANATION_RENDERER_VERSION,
    ACTION_EXPLANATION_SCHEMA_VERSION,
    ACTION_EXPLANATION_VERSION,
    GuardActionExplanationV1,
    parse_action_explanation,
)
from .action_explanation_semantics import (
    ActionExplanationSemantics,
    derive_action_semantics,
    normalized_string_sequence,
)
from .command_model import CanonicalCommand

TARGET_LABEL_MAX_LENGTH = 240
COMMAND_DISPLAY_MAX_LENGTH = 4096
_ARGUMENT_DISPLAY_MAX_LENGTH = 240
_ACTION_IDENTITY_DOMAIN = b"hol-guard:action-explanation:v1\0"


def project_action_explanation(
    action_envelope: Mapping[str, object] | None,
    *,
    action_identity: str,
    actor_label: str,
    exact_details_authorized: bool = False,
    retained: bool = True,
    receipt_id: str | None = None,
) -> GuardActionExplanationV1 | None:
    """Project persisted Core facts into the versioned explanation contract."""

    if not isinstance(action_envelope, Mapping) or not action_identity:
        return None
    safe_actor = _safe_text(actor_label, 120)
    semantics = derive_action_semantics(action_envelope, actor_label=safe_actor)
    raw_command = _text(action_envelope.get("command"))
    opaque_identity = opaque_action_explanation_identity(action_identity)
    payload: dict[str, object] = {
        "schema_version": ACTION_EXPLANATION_SCHEMA_VERSION,
        "explanation_version": ACTION_EXPLANATION_VERSION,
        "renderer_version": ACTION_EXPLANATION_RENDERER_VERSION,
        "action_identity": opaque_identity,
        "canonical_identity": _safe_optional(semantics.canonical_identity, 256),
        "catalog_digest": _safe_optional(semantics.catalog_digest, 256),
        "locale": "en-US",
        "kind": semantics.kind,
        "confidence": semantics.confidence,
        "uncertainty_reasons": [_safe_text(reason, 128) for reason in semantics.uncertainty_reasons[:32]],
        "everyday": _everyday_projection(
            semantics,
            actor_label=safe_actor,
            action_envelope=action_envelope,
        ),
        "technical": _technical_projection(
            semantics,
            raw_command=raw_command,
            retained=retained,
            exact_details_authorized=exact_details_authorized,
            receipt_id=receipt_id,
            opaque_identity=opaque_identity,
        ),
        "redaction": _redaction_projection(
            semantics,
            action_envelope=action_envelope,
            raw_command=raw_command,
            retained=retained,
            exact_details_authorized=exact_details_authorized,
        ),
    }
    return parse_action_explanation(cast(dict[str, object], payload))


def opaque_action_explanation_identity(action_identity: str) -> str:
    """Return a domain-separated identifier safe to expose outside Core internals."""

    normalized = action_identity.strip()
    if not normalized:
        raise ValueError("Action identity is required.")
    digest = hashlib.sha256(_ACTION_IDENTITY_DOMAIN + normalized.encode("utf-8")).hexdigest()
    return f"act_{digest}"


def _everyday_projection(
    semantics: ActionExplanationSemantics,
    *,
    actor_label: str,
    action_envelope: Mapping[str, object],
) -> dict[str, object]:
    kind = semantics.kind
    consequences = [
        {
            "message_id": f"guard.everyday.{kind}.consequence.{index}",
            "message": _safe_text(item.message, 500),
            "severity": item.severity,
            "confirmed": False,
        }
        for index, item in enumerate(semantics.consequences[:16])
    ]
    alternatives = [
        {
            "message_id": f"guard.everyday.{kind}.alternative.{index}",
            "message": _safe_text(message, 500),
            "kind": "review",
        }
        for index, message in enumerate(semantics.safer_alternatives[:12])
    ]
    return {
        "headline_message_id": f"guard.everyday.{kind}.headline",
        "headline": _safe_text(semantics.headline, 240),
        "summary_message_id": f"guard.everyday.{kind}.summary",
        "summary": _safe_text(semantics.summary, 800),
        "impact_message_id": f"guard.everyday.{kind}.impact",
        "impact": _safe_text(semantics.impact, 800),
        "why_guard_intervened_message_id": (f"guard.everyday.{kind}.why" if semantics.rule_ids else None),
        "why_guard_intervened": (
            "Guard matched a built-in protection for this action." if semantics.rule_ids else None
        ),
        "recommendation_message_id": f"guard.everyday.{kind}.recommendation",
        "recommendation": _safe_text(semantics.recommendation, 800),
        "actor_label": actor_label,
        "targets": _everyday_targets(
            semantics,
            action_envelope=action_envelope,
        ),
        "consequences": consequences,
        "safer_alternatives": alternatives,
    }


def _everyday_targets(
    semantics: ActionExplanationSemantics,
    *,
    action_envelope: Mapping[str, object],
) -> list[dict[str, object]]:
    if semantics.action_type == "network_request":
        hosts = normalized_string_sequence(action_envelope.get("network_hosts"))
        if hosts:
            return [
                {
                    "kind": "network_host",
                    "label": _safe_text(f"the service {hosts[0]}", TARGET_LABEL_MAX_LENGTH),
                    "scope": None,
                    "sensitivity": "normal",
                }
            ]
    return [
        {
            "kind": _safe_identifier(target.kind, fallback="action"),
            "label": _safe_text(target.label, TARGET_LABEL_MAX_LENGTH),
            "scope": None,
            "sensitivity": target.sensitivity,
        }
        for target in semantics.targets[:16]
    ]


def _technical_projection(
    semantics: ActionExplanationSemantics,
    *,
    raw_command: str | None,
    retained: bool,
    exact_details_authorized: bool,
    receipt_id: str | None,
    opaque_identity: str,
) -> dict[str, object]:
    authorized = bool(retained and exact_details_authorized and raw_command)
    command = semantics.canonical_command
    unavailable_reason = _technical_unavailable_reason(
        raw_command=raw_command,
        retained=retained,
        authorized=authorized,
    )
    exact = _exact_command_projection(command, raw_command=raw_command) if authorized else {}
    return {
        "available": authorized,
        "unavailable_reason": unavailable_reason,
        "action_type": _safe_text(semantics.action_type, 120),
        "command_display": exact.get("command_display"),
        "normalized_command_display": exact.get("normalized_command_display"),
        "executable": exact.get("executable"),
        "arguments_display": exact.get("arguments_display"),
        "dialect": command.dialect if command is not None else None,
        "transport": command.transport if command is not None else None,
        "working_scope_display": None,
        "wrappers": exact.get("wrappers", []),
        "segments": exact.get("segments", []),
        "extension_ids": [_safe_text(value, 128) for value in semantics.extension_ids[:64]],
        "rule_ids": [_safe_text(value, 128) for value in semantics.rule_ids[:64]],
        "reason_codes": [_safe_text(value, 128) for value in semantics.uncertainty_reasons[:64]],
        "policy_source": None,
        "parse_confidence": command.confidence if command is not None else None,
        "proof_level": None,
        "receipt_id": _safe_optional(receipt_id, 256),
        "action_id": opaque_identity,
    }


def _exact_command_projection(
    command: CanonicalCommand | None,
    *,
    raw_command: str | None,
) -> dict[str, object]:
    command_display = _redacted_exact(raw_command, COMMAND_DISPLAY_MAX_LENGTH)
    if command is None:
        return {"command_display": command_display}
    segments = [
        {
            "executable": _redacted_exact(segment.executable, 240),
            "arguments_display": [
                _redacted_exact(argument, _ARGUMENT_DISPLAY_MAX_LENGTH) or "" for argument in segment.arguments[:128]
            ],
            "execution_context": _safe_text(segment.execution_context, 120),
            "pipeline_index": min(segment.pipeline_index, 128),
        }
        for segment in command.segments[:128]
    ]
    first = command.segments[0] if command.segments else None
    return {
        "command_display": command_display,
        "normalized_command_display": _redacted_exact(
            command.normalized_text,
            COMMAND_DISPLAY_MAX_LENGTH,
        ),
        "executable": _redacted_exact(first.executable, 240) if first else None,
        "arguments_display": (
            [_redacted_exact(argument, _ARGUMENT_DISPLAY_MAX_LENGTH) or "" for argument in first.arguments[:128]]
            if first
            else None
        ),
        "wrappers": [_safe_text(value, 120) for value in command.wrapper_chain[:32]],
        "segments": segments,
    }


def _redaction_projection(
    semantics: ActionExplanationSemantics,
    *,
    action_envelope: Mapping[str, object],
    raw_command: str | None,
    retained: bool,
    exact_details_authorized: bool,
) -> dict[str, object]:
    command_redaction = redact_text(raw_command) if raw_command else None
    authorized = bool(retained and exact_details_authorized and raw_command)
    omitted = (
        []
        if authorized
        else [
            "technical.command_display",
            "technical.normalized_command_display",
            "technical.executable",
            "technical.arguments_display",
            "technical.segments",
        ]
    )
    truncated = _truncated_fields(
        semantics,
        action_envelope=action_envelope,
        raw_command=raw_command,
        exact_details_authorized=authorized,
    )
    return {
        "level": ("redacted" if (command_redaction and command_redaction.count) or not authorized else "none"),
        "policy_version": ACTION_EXPLANATION_REDACTION_VERSION,
        "omitted_fields": omitted,
        "truncated_fields": truncated,
        "secret_like_values_removed": bool(command_redaction and command_redaction.count),
    }


def _truncated_fields(
    semantics: ActionExplanationSemantics,
    *,
    action_envelope: Mapping[str, object],
    raw_command: str | None,
    exact_details_authorized: bool,
) -> list[str]:
    fields: list[str] = []
    if any(len(target.label) > TARGET_LABEL_MAX_LENGTH for target in semantics.targets):
        fields.append("everyday.targets.label")
    if semantics.action_type == "network_request":
        hosts = normalized_string_sequence(action_envelope.get("network_hosts"))
        if hosts and len(f"the service {hosts[0]}") > TARGET_LABEL_MAX_LENGTH:
            fields.append("everyday.targets.label")
    if exact_details_authorized and raw_command:
        redacted_command = redact_text(raw_command).text
        if len(redacted_command) > COMMAND_DISPLAY_MAX_LENGTH:
            fields.append("technical.command_display")
        command = semantics.canonical_command
        if command is not None:
            if len(redact_text(command.normalized_text).text) > COMMAND_DISPLAY_MAX_LENGTH:
                fields.append("technical.normalized_command_display")
            if any(
                len(redact_text(argument).text) > _ARGUMENT_DISPLAY_MAX_LENGTH
                for segment in command.segments[:128]
                for argument in segment.arguments[:128]
            ):
                fields.append("technical.arguments_display")
    return fields


def _technical_unavailable_reason(
    *,
    raw_command: str | None,
    retained: bool,
    authorized: bool,
) -> str | None:
    if authorized:
        return None
    if not retained:
        return "The exact action was not retained."
    if raw_command:
        return "Exact technical details require deliberate local disclosure."
    return "No exact command was retained for this action."


def _redacted_exact(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    return _safe_text(value, limit)


def _safe_optional(value: str | None, limit: int) -> str | None:
    return _safe_text(value, limit) if value else None


def _safe_identifier(value: str, *, fallback: str) -> str:
    normalized = "".join(
        character for character in value.lower() if character.isascii() and (character.isalnum() or character == "_")
    )[:64]
    if not normalized or not normalized[0].isalpha():
        return fallback
    return normalized


def _safe_text(value: str, limit: int) -> str:
    redacted = redact_text(value).text.replace("\n", " ").replace("\r", " ").replace("\x1b", "")
    return redacted[:limit]


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
