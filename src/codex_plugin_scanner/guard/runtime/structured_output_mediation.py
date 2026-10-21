"""Structured-output DTOs and callback transport; native authority decides."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any, Literal

from ..native_content_sensitivity import (
    NativeContentSensitivityDeadlineError,
    NativeContentSensitivityError,
    content_query,
)
from .structured_data_sensitivity import DeclaredField, DeclaredSchema

_LOG = logging.getLogger(__name__)

STRUCTURED_OUTPUT_SETTING_PATH = "data_control.structured_output"
STRUCTURED_OUTPUT_POLICY_VERSION = "hol-guard-structured-output-policy.v1"
STRUCTURED_CONTENT_MEDIATION_SCHEMA = "guard-structured-content-mediation.v1"
STRUCTURED_DESTINATION_ROLE = "model_visible_tool_result"
STRUCTURED_MEDIATION_MAX_BYTES = 64 * 1024
STRUCTURED_MEDIATION_MAX_SAFE_INTEGER = 2**53 - 1
MediationAction = Literal["forward", "withhold"]


@dataclass(frozen=True, slots=True)
class StructuredOutputPolicy:
    harnesses: tuple[str, ...]
    schema: DeclaredSchema


@dataclass(frozen=True, slots=True)
class StructuredOutputBinding:
    harness: str
    managed_policy_hash: str
    policy: StructuredOutputPolicy
    rule_version: str

    @property
    def identity(self) -> tuple[object, ...]:
        return (
            self.harness,
            self.managed_policy_hash,
            self.rule_version,
            self.policy.harnesses,
            self.policy.schema.fields,
        )


@dataclass(frozen=True, slots=True)
class StructuredOutputResolution:
    binding: StructuredOutputBinding | None
    required: bool
    reason_code: str | None = None


def _policy_dto(value: dict[str, Any]) -> StructuredOutputPolicy:
    fields = []
    for item in value["schema"]["fields"]:
        field = object.__new__(DeclaredField)
        for key, raw in item.items():
            object.__setattr__(field, key, tuple(raw) if key == "path" else raw)
        fields.append(field)
    schema = object.__new__(DeclaredSchema)
    object.__setattr__(schema, "fields", tuple(fields))
    return StructuredOutputPolicy(tuple(value["harnesses"]), schema)


def _binding_dto(value: dict[str, Any] | None) -> StructuredOutputBinding | None:
    return (
        None
        if value is None
        else StructuredOutputBinding(
            value["harness"], value["managed_policy_hash"], _policy_dto(value["policy"]), value["rule_version"]
        )
    )


def canonical_harness_name(value: str) -> str:
    # This public spelling helper is presentation, not a policy decision.
    # The native operation independently normalizes and checks its binding.
    normalized = value.strip().lower().replace("_", "-")
    return {"pi-agent": "pi", "pi-coding-agent": "pi", "oh-my-pi": "omp"}.get(normalized, normalized)


def _config_wire(config: object) -> dict[str, Any]:
    policy = getattr(config, "managed_policy", None)
    locked = getattr(config, "managed_locked_settings", ())
    settings = getattr(policy, "settings", None)
    if isinstance(settings, Mapping):
        control = settings.get("data_control")
        settings = (
            {"data_control": {"structured_output": control["structured_output"]}}
            if isinstance(control, Mapping) and "structured_output" in control
            else {}
        )
    return {
        "managed_policy_status": getattr(config, "managed_policy_status", None),
        "managed_policy_hash": getattr(config, "managed_policy_hash", None),
        "managed_locked_settings": list(locked) if isinstance(locked, (list, tuple, set, frozenset)) else [],
        "managed_policy": None
        if policy is None
        else {
            "content_hash": getattr(policy, "content_hash", None),
            "settings": settings,
        },
    }


def resolve_managed_structured_output_resolution(config: object, *, harness: str) -> StructuredOutputResolution:
    try:
        result = content_query("resolution", {"config": _config_wire(config), "harness": harness})
        return StructuredOutputResolution(_binding_dto(result["binding"]), result["required"], result["reason_code"])
    except NativeContentSensitivityError:
        return StructuredOutputResolution(None, True, "structured_managed_authority_unavailable")


def resolve_managed_structured_output_binding(config: object, *, harness: str) -> StructuredOutputBinding | None:
    return resolve_managed_structured_output_resolution(config, harness=harness).binding


@dataclass(frozen=True, slots=True)
class StructuredContentMediation:
    action: MediationAction
    reason_code: str
    native_decision_id: str | None
    content_sha256: str | None = None

    def to_harness_json(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema": STRUCTURED_CONTENT_MEDIATION_SCHEMA,
            "action": self.action,
            "reason_code": self.reason_code,
        }
        if self.native_decision_id:
            result["native_decision_id"] = self.native_decision_id
        if self.action == "forward" and self.content_sha256:
            result["content_sha256"] = self.content_sha256
        return result


def mediate_native_post_tool_content(
    *,
    harness: str,
    event_name: str,
    native_result: Mapping[str, object],
    validated_receipt: Mapping[str, object] | None,
    structured_output_json: object,
    binding: StructuredOutputBinding | None,
    required_reason_code: str | None = None,
    recheck_binding: Callable[[], StructuredOutputBinding | None] | None = None,
    deadline_monotonic: float | None = None,
    cancelled: bool = False,
    allow_observe_mode: bool = False,
) -> StructuredContentMediation | None:
    body: dict[str, Any] = {
        "harness": harness,
        "event_name": event_name,
        "native_result": {key: native_result.get(key) for key in ("decision", "observe_mode", "model_output_action")},
        "validated_receipt": dict(validated_receipt) if validated_receipt is not None else None,
        "structured_output_json": structured_output_json,
        "binding": asdict(binding) if binding is not None else None,
        "required_reason_code": required_reason_code,
        "cancelled": cancelled,
        "allow_observe_mode": allow_observe_mode,
        "recheck_available": recheck_binding is not None,
    }
    try:
        result = content_query("mediate_prepare", body, deadline_monotonic=deadline_monotonic)
        if isinstance(result, dict) and result == {"recheck_required": True}:
            refreshed = None
            error = False
            try:
                refreshed = recheck_binding() if recheck_binding is not None else None
            except (AttributeError, TypeError, ValueError):
                pass
            except Exception as exc:
                _LOG.warning("Structured output binding recheck failed (%s)", type(exc).__name__)
                error = True
            body.update(refreshed_binding=asdict(refreshed) if refreshed is not None else None, recheck_error=error)
            result = content_query("mediate_finish", body, deadline_monotonic=deadline_monotonic)
        return None if result is None else StructuredContentMediation(**result)
    except NativeContentSensitivityDeadlineError:
        return StructuredContentMediation("withhold", "structured_review_deadline_exceeded", None)
    except NativeContentSensitivityError:
        return StructuredContentMediation("withhold", "structured_managed_authority_unavailable", None)


__all__ = [
    "STRUCTURED_CONTENT_MEDIATION_SCHEMA",
    "STRUCTURED_DESTINATION_ROLE",
    "STRUCTURED_OUTPUT_POLICY_VERSION",
    "STRUCTURED_OUTPUT_SETTING_PATH",
    "StructuredContentMediation",
    "StructuredOutputBinding",
    "StructuredOutputPolicy",
    "StructuredOutputResolution",
    "canonical_harness_name",
    "mediate_native_post_tool_content",
    "resolve_managed_structured_output_binding",
    "resolve_managed_structured_output_resolution",
]
