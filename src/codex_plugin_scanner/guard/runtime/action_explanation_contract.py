"""Versioned action-explanation contract shared by Guard surfaces."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

ACTION_EXPLANATION_SCHEMA_VERSION = "guard.action-explanation.v1"
ACTION_EXPLANATION_VERSION = "1.0.0"
ACTION_EXPLANATION_RENDERER_VERSION = "1.0.0"
ACTION_EXPLANATION_REDACTION_VERSION = "1"
_ACTION_EXPLANATION_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "guard_action_explanation_v1.json"

GuardExplanationConfidence = Literal["exact", "derived", "limited"]
GuardExplanationRedactionLevel = Literal["none", "summary", "redacted"]
GuardEverydayActionKind = Literal[
    "file_read",
    "file_write",
    "file_delete",
    "file_move",
    "permission_change",
    "process_start",
    "process_stop",
    "system_change",
    "disk_change",
    "network_read",
    "network_send",
    "download",
    "download_and_execute",
    "package_install",
    "package_remove",
    "package_update",
    "package_script",
    "git_read",
    "git_local_change",
    "git_history_rewrite",
    "git_remote_change",
    "secret_read",
    "secret_send",
    "container_change",
    "cluster_change",
    "cloud_change",
    "database_read",
    "database_change",
    "mcp_tool",
    "browser_action",
    "prompt_submission",
    "skill_install",
    "extension_change",
    "guard_control_change",
    "compound_action",
    "unknown_action",
]

ACTION_KINDS = frozenset(
    {
        "file_read",
        "file_write",
        "file_delete",
        "file_move",
        "permission_change",
        "process_start",
        "process_stop",
        "system_change",
        "disk_change",
        "network_read",
        "network_send",
        "download",
        "download_and_execute",
        "package_install",
        "package_remove",
        "package_update",
        "package_script",
        "git_read",
        "git_local_change",
        "git_history_rewrite",
        "git_remote_change",
        "secret_read",
        "secret_send",
        "container_change",
        "cluster_change",
        "cloud_change",
        "database_read",
        "database_change",
        "mcp_tool",
        "browser_action",
        "prompt_submission",
        "skill_install",
        "extension_change",
        "guard_control_change",
        "compound_action",
        "unknown_action",
    }
)


@dataclass(frozen=True, slots=True)
class EverydayTarget:
    kind: str
    label: str
    scope: str | None = None
    sensitivity: str = "normal"


@dataclass(frozen=True, slots=True)
class EverydayConsequence:
    message_id: str
    message: str
    severity: str
    confirmed: bool = False


@dataclass(frozen=True, slots=True)
class EverydayAlternative:
    message_id: str
    message: str
    kind: str


@dataclass(frozen=True, slots=True)
class EverydayExplanation:
    headline_message_id: str
    headline: str
    summary_message_id: str
    summary: str
    impact_message_id: str | None
    impact: str | None
    why_guard_intervened_message_id: str | None
    why_guard_intervened: str | None
    recommendation_message_id: str | None
    recommendation: str | None
    actor_label: str
    targets: tuple[EverydayTarget, ...] = ()
    consequences: tuple[EverydayConsequence, ...] = ()
    safer_alternatives: tuple[EverydayAlternative, ...] = ()


@dataclass(frozen=True, slots=True)
class TechnicalSegment:
    executable: str | None
    arguments_display: tuple[str, ...]
    execution_context: str
    pipeline_index: int


@dataclass(frozen=True, slots=True)
class TechnicalExplanation:
    available: bool
    unavailable_reason: str | None
    action_type: str
    command_display: str | None = None
    normalized_command_display: str | None = None
    executable: str | None = None
    arguments_display: tuple[str, ...] | None = None
    dialect: str | None = None
    transport: str | None = None
    working_scope_display: str | None = None
    wrappers: tuple[str, ...] = ()
    segments: tuple[TechnicalSegment, ...] = ()
    extension_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    policy_source: str | None = None
    parse_confidence: str | None = None
    proof_level: str | None = None
    receipt_id: str | None = None
    action_id: str | None = None


@dataclass(frozen=True, slots=True)
class ExplanationRedaction:
    level: GuardExplanationRedactionLevel
    policy_version: str = ACTION_EXPLANATION_REDACTION_VERSION
    omitted_fields: tuple[str, ...] = ()
    truncated_fields: tuple[str, ...] = ()
    secret_like_values_removed: bool = False


@dataclass(frozen=True, slots=True)
class GuardActionExplanationV1:
    action_identity: str
    kind: GuardEverydayActionKind
    confidence: GuardExplanationConfidence
    everyday: EverydayExplanation
    technical: TechnicalExplanation
    redaction: ExplanationRedaction
    canonical_identity: str | None = None
    catalog_digest: str | None = None
    locale: str = "en-US"
    uncertainty_reasons: tuple[str, ...] = ()
    schema_version: str = ACTION_EXPLANATION_SCHEMA_VERSION
    explanation_version: str = ACTION_EXPLANATION_VERSION
    renderer_version: str = ACTION_EXPLANATION_RENDERER_VERSION

    def to_dict(self) -> dict[str, object]:
        return cast(dict[str, object], asdict(self))

    def list_projection(self) -> dict[str, object]:
        payload = self.to_dict()
        everyday = cast(dict[str, object], payload["everyday"])
        payload["everyday"] = {
            "headline_message_id": everyday["headline_message_id"],
            "headline": everyday["headline"],
            "summary_message_id": everyday["summary_message_id"],
            "summary": everyday["summary"],
            "actor_label": everyday["actor_label"],
            "targets": everyday["targets"],
            "consequences": everyday["consequences"],
            "safer_alternatives": everyday["safer_alternatives"],
            "impact_message_id": everyday["impact_message_id"],
            "impact": everyday["impact"],
            "why_guard_intervened_message_id": None,
            "why_guard_intervened": None,
            "recommendation_message_id": everyday["recommendation_message_id"],
            "recommendation": everyday["recommendation"],
        }
        technical = cast(dict[str, object], payload["technical"])
        payload["technical"] = {
            **technical,
            "command_display": None,
            "normalized_command_display": None,
            "arguments_display": None,
            "segments": [],
        }
        return payload

    def cloud_safe_projection(self) -> dict[str, object]:
        payload = self.list_projection()
        payload["technical"] = {
            "available": False,
            "unavailable_reason": "Technical content stays on the protected device.",
            "action_type": self.technical.action_type,
            "command_display": None,
            "normalized_command_display": None,
            "executable": None,
            "arguments_display": None,
            "dialect": None,
            "transport": None,
            "working_scope_display": None,
            "wrappers": [],
            "segments": [],
            "extension_ids": [],
            "rule_ids": [],
            "reason_codes": list(self.technical.reason_codes),
            "policy_source": None,
            "parse_confidence": self.technical.parse_confidence,
            "proof_level": self.technical.proof_level,
            "receipt_id": None,
            "action_id": self.technical.action_id,
        }
        payload["redaction"] = {
            "level": "redacted",
            "policy_version": ACTION_EXPLANATION_REDACTION_VERSION,
            "omitted_fields": ["technical.command", "technical.paths", "technical.arguments", "technical.rule_ids"],
            "truncated_fields": [],
            "secret_like_values_removed": self.redaction.secret_like_values_removed,
        }
        return payload


@lru_cache(maxsize=1)
def _action_explanation_validator() -> Draft202012Validator:
    raw_schema = json.loads(_ACTION_EXPLANATION_SCHEMA_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw_schema, dict):
        raise ValueError("Action explanation schema must be an object.")
    schema = cast(dict[str, object], raw_schema)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _ensure_json_compatible(value: object) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if math.isfinite(value):
            return
        raise ValueError("Action explanation payload must contain finite JSON numbers.")
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("Action explanation objects must use string keys.")
            _ensure_json_compatible(nested)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            _ensure_json_compatible(nested)
        return
    raise ValueError("Action explanation payload contains a non-JSON value.")


def _schema_instance(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _schema_instance(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_schema_instance(nested) for nested in value]
    return value


def _validated_payload(payload: object) -> Mapping[str, object]:
    if not isinstance(payload, Mapping):
        raise ValueError("Action explanation payload must be an object.")
    _ensure_json_compatible(payload)
    schema_payload = _schema_instance(payload)
    try:
        _action_explanation_validator().validate(schema_payload)
    except ValidationError as error:
        prefix = (
            "Unknown action explanation field"
            if error.validator == "additionalProperties"
            else "Invalid action explanation payload"
        )
        raise ValueError(f"{prefix}: {error.message}") from error
    except TypeError as error:
        raise ValueError("Invalid action explanation payload.") from error
    return cast(Mapping[str, object], payload)


def _mapping_sequence(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Action explanation arrays are required.")
    items: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("Action explanation array items must be objects.")
        items.append(cast(Mapping[str, object], item))
    return tuple(items)


def _target_from_mapping(item: Mapping[str, object]) -> EverydayTarget:
    return EverydayTarget(
        kind=cast(str, item["kind"]),
        label=cast(str, item["label"]),
        scope=cast(str | None, item["scope"]),
        sensitivity=cast(str, item["sensitivity"]),
    )


def _consequence_from_mapping(item: Mapping[str, object]) -> EverydayConsequence:
    return EverydayConsequence(
        message_id=cast(str, item["message_id"]),
        message=cast(str, item["message"]),
        severity=cast(str, item["severity"]),
        confirmed=cast(bool, item["confirmed"]),
    )


def _alternative_from_mapping(item: Mapping[str, object]) -> EverydayAlternative:
    return EverydayAlternative(
        message_id=cast(str, item["message_id"]),
        message=cast(str, item["message"]),
        kind=cast(str, item["kind"]),
    )


def parse_action_explanation(payload: Mapping[str, object]) -> GuardActionExplanationV1:
    """Strictly parse the identity and version boundary before UI use.

    Full JSON Schema validation remains the compatibility gate; this narrow parser is
    intentionally strict about unknown top-level fields and identity-bearing values.
    """

    payload = _validated_payload(payload)
    allowed = {
        "schema_version",
        "explanation_version",
        "renderer_version",
        "action_identity",
        "canonical_identity",
        "catalog_digest",
        "locale",
        "kind",
        "confidence",
        "uncertainty_reasons",
        "everyday",
        "technical",
        "redaction",
    }
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError(f"Unknown action explanation fields: {', '.join(sorted(unknown))}")
    if payload.get("schema_version") != ACTION_EXPLANATION_SCHEMA_VERSION:
        raise ValueError("Unsupported action explanation schema")
    action_identity = cast(object, payload["action_identity"])
    kind_value = cast(object, payload["kind"])
    confidence = cast(object, payload["confidence"])
    if not isinstance(action_identity, str) or not action_identity:
        raise ValueError("Action explanation identity is required")
    if not isinstance(kind_value, str) or kind_value not in ACTION_KINDS:
        raise ValueError("Invalid action explanation kind")
    if confidence not in {"exact", "derived", "limited"}:
        raise ValueError("Invalid action explanation confidence")
    everyday_raw = cast(Mapping[str, object], payload["everyday"])
    technical_raw = cast(Mapping[str, object], payload["technical"])
    redaction_raw = cast(Mapping[str, object], payload["redaction"])
    targets = tuple(_target_from_mapping(item) for item in _mapping_sequence(everyday_raw["targets"]))
    consequences = tuple(_consequence_from_mapping(item) for item in _mapping_sequence(everyday_raw["consequences"]))
    alternatives = tuple(
        _alternative_from_mapping(item) for item in _mapping_sequence(everyday_raw["safer_alternatives"])
    )
    everyday = EverydayExplanation(
        headline_message_id=str(everyday_raw.get("headline_message_id", "")),
        headline=str(everyday_raw.get("headline", "")),
        summary_message_id=str(everyday_raw.get("summary_message_id", "")),
        summary=str(everyday_raw.get("summary", "")),
        impact_message_id=_optional_string(everyday_raw.get("impact_message_id")),
        impact=_optional_string(everyday_raw.get("impact")),
        why_guard_intervened_message_id=_optional_string(everyday_raw.get("why_guard_intervened_message_id")),
        why_guard_intervened=_optional_string(everyday_raw.get("why_guard_intervened")),
        recommendation_message_id=_optional_string(everyday_raw.get("recommendation_message_id")),
        recommendation=_optional_string(everyday_raw.get("recommendation")),
        actor_label=str(everyday_raw.get("actor_label", "Guard-protected app")),
        targets=targets,
        consequences=consequences,
        safer_alternatives=alternatives,
    )
    segments = tuple(
        TechnicalSegment(
            executable=cast(str | None, item["executable"]),
            arguments_display=_string_tuple(item["arguments_display"]),
            execution_context=cast(str, item["execution_context"]),
            pipeline_index=cast(int, item["pipeline_index"]),
        )
        for item in _mapping_sequence(technical_raw["segments"])
    )
    technical = TechnicalExplanation(
        available=technical_raw.get("available") is True,
        unavailable_reason=_optional_string(technical_raw.get("unavailable_reason")),
        action_type=str(technical_raw.get("action_type", "unknown")),
        command_display=_optional_string(technical_raw.get("command_display")),
        normalized_command_display=_optional_string(technical_raw.get("normalized_command_display")),
        executable=_optional_string(technical_raw.get("executable")),
        arguments_display=_optional_string_tuple(technical_raw.get("arguments_display")),
        dialect=_optional_string(technical_raw.get("dialect")),
        transport=_optional_string(technical_raw.get("transport")),
        working_scope_display=_optional_string(technical_raw.get("working_scope_display")),
        wrappers=_string_tuple(technical_raw.get("wrappers")),
        segments=segments,
        extension_ids=_string_tuple(technical_raw.get("extension_ids")),
        rule_ids=_string_tuple(technical_raw.get("rule_ids")),
        reason_codes=_string_tuple(technical_raw.get("reason_codes")),
        policy_source=_optional_string(technical_raw.get("policy_source")),
        parse_confidence=_optional_string(technical_raw.get("parse_confidence")),
        proof_level=_optional_string(technical_raw.get("proof_level")),
        receipt_id=_optional_string(technical_raw.get("receipt_id")),
        action_id=_optional_string(technical_raw.get("action_id")),
    )
    level_value = redaction_raw["level"]
    if level_value not in {"none", "summary", "redacted"}:
        raise ValueError("Invalid action explanation redaction level")
    level = cast(GuardExplanationRedactionLevel, level_value)
    redaction = ExplanationRedaction(
        level=level,  # type: ignore[arg-type]
        policy_version=str(redaction_raw.get("policy_version", ACTION_EXPLANATION_REDACTION_VERSION)),
        omitted_fields=_string_tuple(redaction_raw.get("omitted_fields")),
        truncated_fields=_string_tuple(redaction_raw.get("truncated_fields")),
        secret_like_values_removed=redaction_raw.get("secret_like_values_removed") is True,
    )
    return GuardActionExplanationV1(
        action_identity=action_identity,
        kind=cast(GuardEverydayActionKind, kind_value),
        confidence=cast(GuardExplanationConfidence, confidence),
        everyday=everyday,
        technical=technical,
        redaction=redaction,
        canonical_identity=_optional_string(payload.get("canonical_identity")),
        catalog_digest=_optional_string(payload.get("catalog_digest")),
        locale=str(payload.get("locale", "en-US")),
        uncertainty_reasons=_string_tuple(payload.get("uncertainty_reasons")),
        explanation_version=str(payload.get("explanation_version", ACTION_EXPLANATION_VERSION)),
        renderer_version=str(payload.get("renderer_version", ACTION_EXPLANATION_RENDERER_VERSION)),
    )


def explanation_identity_matches(
    payload: GuardActionExplanationV1, *, action_identity: str, canonical_identity: str | None = None
) -> bool:
    if payload.action_identity != action_identity:
        return False
    return canonical_identity is None or payload.canonical_identity == canonical_identity


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _string_tuple(value: object) -> tuple[str, ...]:
    return tuple(item for item in value if isinstance(item, str)) if isinstance(value, (list, tuple)) else ()


def _optional_string_tuple(value: object) -> tuple[str, ...] | None:
    return None if value is None else _string_tuple(value)
