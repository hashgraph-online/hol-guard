"""Bounded destination mediation for native Pi and Oh My Pi tool results.

The native Rust result and receipt remain the authoritative hook decision.  This
module is a strictly more restrictive, adapter-only control for the bytes a
managed Pi/OMP receiver may preserve for the model.  It never evaluates a
command and it never changes the native result or receipt.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal, TypeGuard

from ..stable_json import stable_json_serialize
from ..strict_json_pairs import unique_json_object
from .structured_data_sensitivity import (
    DeclaredField,
    DeclaredSchema,
    FieldRole,
    FieldType,
    PersonalCategory,
    SensitiveScanResult,
    classifier_rule_version,
    classify_declared_content,
)

STRUCTURED_OUTPUT_SETTING_PATH = "data_control.structured_output"
STRUCTURED_OUTPUT_POLICY_VERSION = "hol-guard-structured-output-policy.v1"
STRUCTURED_CONTENT_MEDIATION_SCHEMA = "guard-structured-content-mediation.v1"
STRUCTURED_DESTINATION_ROLE = "model_visible_tool_result"
_LOGGER = logging.getLogger(__name__)
STRUCTURED_MEDIATION_MAX_BYTES = 64 * 1024
STRUCTURED_MEDIATION_MAX_SAFE_INTEGER = 2**53 - 1
_SUPPORTED_HARNESSES = frozenset({"pi", "omp"})
_HEX = frozenset("0123456789abcdef")

MediationAction = Literal["forward", "withhold"]


@dataclass(frozen=True, slots=True)
class StructuredOutputPolicy:
    """Strict, closed machine-managed structured-output policy."""

    harnesses: tuple[str, ...]
    schema: DeclaredSchema


@dataclass(frozen=True, slots=True)
class StructuredOutputBinding:
    """The active managed binding used for one server-derived destination role."""

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
    """The managed authority state for one native adapter route.

    ``required`` distinguishes an intentionally unconfigured optional setting
    from an authority that was configured but cannot be validated.  A missing
    binding is therefore safe only when ``required`` is false; callers must
    withhold model-visible output for the required-but-invalid case.
    """

    binding: StructuredOutputBinding | None
    required: bool
    reason_code: str | None = None


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be an object")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _strict_string_list(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{name} must be a non-empty array of strings")
    items = tuple(value)
    if len(set(items)) != len(items):
        raise ValueError(f"{name} must not contain duplicates")
    return items


def _is_field_role(value: object) -> TypeGuard[FieldRole]:
    return isinstance(value, str) and value in ("protected_personal", "ordinary")


def _is_field_type(value: object) -> TypeGuard[FieldType]:
    return isinstance(value, str) and value in ("string", "integer")


def _is_personal_category(value: object) -> TypeGuard[PersonalCategory | None]:
    return value is None or (isinstance(value, str) and value in ("person_name", "email_address", "employee_id"))


def parse_structured_output_policy(value: object) -> StructuredOutputPolicy:
    """Parse the reserved setting without accepting aliases or extensions."""

    root = _mapping(value, "structured output policy")
    if set(root) != {
        "version",
        "enabled",
        "harnesses",
        "event",
        "destinationRole",
        "schema",
        "onMatch",
        "onUnsupported",
    }:
        raise ValueError("structured output policy has unknown or missing keys")
    if root["version"] != STRUCTURED_OUTPUT_POLICY_VERSION:
        raise ValueError("structured output policy version is unsupported")
    if root["enabled"] is not True:
        raise ValueError("structured output policy must be enabled")
    harnesses = _strict_string_list(root["harnesses"], "structured output policy harnesses")
    if not set(harnesses) <= _SUPPORTED_HARNESSES:
        raise ValueError("structured output policy harness is unsupported")
    if root["event"] != "PostToolUse":
        raise ValueError("structured output policy event is unsupported")
    if root["destinationRole"] != STRUCTURED_DESTINATION_ROLE:
        raise ValueError("structured output policy destination role is unsupported")
    if root["onMatch"] != "withhold" or root["onUnsupported"] != "withhold":
        raise ValueError("structured output policy must withhold non-clean content")

    schema_root = _mapping(root["schema"], "structured output policy schema")
    if set(schema_root) != {"fields"}:
        raise ValueError("structured output policy schema has unknown or missing keys")
    fields_raw = schema_root["fields"]
    if not isinstance(fields_raw, list) or not fields_raw:
        raise ValueError("structured output policy schema fields must be non-empty")
    fields: list[DeclaredField] = []
    for index, raw_field in enumerate(fields_raw):
        field = _mapping(raw_field, f"structured output policy schema field {index}")
        role = field.get("role")
        if not _is_field_role(role):
            raise ValueError(f"structured output policy schema field {index} role is invalid")
        expected_keys = (
            {"path", "role", "valueType", "category"}
            if role == "protected_personal"
            else {
                "path",
                "role",
                "valueType",
            }
        )
        if set(field) != expected_keys:
            raise ValueError(f"structured output policy schema field {index} has unknown or missing keys")
        path_raw = field["path"]
        if not isinstance(path_raw, list) or not path_raw or not all(isinstance(part, str) for part in path_raw):
            raise ValueError(f"structured output policy schema field {index} path is invalid")
        value_type = field["valueType"]
        if not _is_field_type(value_type):
            raise ValueError(f"structured output policy schema field {index} value type is invalid")
        category = field.get("category")
        if not _is_personal_category(category):
            raise ValueError(f"structured output policy schema field {index} category is invalid")
        fields.append(
            DeclaredField(
                tuple(path_raw),
                role,
                value_type=value_type,
                category=category,
            )
        )
    return StructuredOutputPolicy(harnesses=tuple(sorted(harnesses)), schema=DeclaredSchema(tuple(fields)))


def _setting_at_path(settings: Mapping[str, object], path: str) -> object | None:
    current: object = settings
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return None
        current = current[segment]
    return current


def _setting_path_present(settings: Mapping[str, object], path: str) -> bool:
    current: object = settings
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            return False
        current = current[segment]
    return True


def _valid_policy_hash(value: object) -> str | None:
    if not isinstance(value, str) or len(value) != 64 or any(character not in _HEX for character in value):
        return None
    return value


def _locked_setting_names(value: object) -> frozenset[str]:
    if not isinstance(value, (tuple, list, set, frozenset)):
        return frozenset()
    return frozenset(item for item in value if isinstance(item, str))


def canonical_harness_name(value: str) -> str:
    """Use the same server-side harness identity as the native route."""

    normalized = value.strip().lower().replace("_", "-")
    return {"pi-agent": "pi", "pi-coding-agent": "pi", "oh-my-pi": "omp"}.get(normalized, normalized)


def resolve_managed_structured_output_binding(config: object, *, harness: str) -> StructuredOutputBinding | None:
    """Resolve only an active locked machine setting for the actual harness."""

    canonical_harness = canonical_harness_name(harness)
    if canonical_harness not in _SUPPORTED_HARNESSES:
        return None
    if getattr(config, "managed_policy_status", None) != "active":
        return None
    policy_hash = _valid_policy_hash(getattr(config, "managed_policy_hash", None))
    managed_policy = getattr(config, "managed_policy", None)
    locked_settings = _locked_setting_names(getattr(config, "managed_locked_settings", ()))
    if policy_hash is None or managed_policy is None or STRUCTURED_OUTPUT_SETTING_PATH not in locked_settings:
        return None
    content_hash = getattr(managed_policy, "content_hash", None)
    if _valid_policy_hash(content_hash) is None or content_hash != policy_hash:
        return None
    settings = getattr(managed_policy, "settings", None)
    if not isinstance(settings, Mapping):
        return None
    try:
        structured_policy = parse_structured_output_policy(_setting_at_path(settings, STRUCTURED_OUTPUT_SETTING_PATH))
    except (TypeError, ValueError):
        return None
    if canonical_harness not in structured_policy.harnesses:
        return None
    return StructuredOutputBinding(
        harness=canonical_harness,
        managed_policy_hash=policy_hash,
        policy=structured_policy,
        rule_version=classifier_rule_version(structured_policy.schema),
    )


def resolve_managed_structured_output_resolution(config: object, *, harness: str) -> StructuredOutputResolution:
    """Resolve the optional binding while preserving fail-closed authority states.

    A normal active machine policy may omit this optional setting, and an
    absent user policy keeps the adapter off.  Once the reserved path is
    machine-locked, malformed/missing fields are a configured authority
    failure rather than an opt-out.  Unreadable or tampered machine policy is
    likewise required to fail closed at this model-visible destination.
    """

    canonical_harness = canonical_harness_name(harness)
    if canonical_harness not in _SUPPORTED_HARNESSES:
        return StructuredOutputResolution(None, False)

    status = getattr(config, "managed_policy_status", None)
    managed_policy = getattr(config, "managed_policy", None)
    policy_hash = getattr(config, "managed_policy_hash", None)
    locked_settings = _locked_setting_names(getattr(config, "managed_locked_settings", ()))
    reserved_locked = STRUCTURED_OUTPUT_SETTING_PATH in locked_settings

    if status in {"invalid", "inaccessible", "tampered"}:
        return StructuredOutputResolution(None, True, "structured_managed_authority_unavailable")
    if status in {"revoked", "removed", "expired", "stale"}:
        return StructuredOutputResolution(None, True, "structured_managed_authority_revoked")

    if status not in {None, "absent", "active"}:
        return StructuredOutputResolution(None, True, "structured_managed_authority_unavailable")

    if status != "active":
        # A stale policy object, hash, or lock marker after revocation is
        # evidence that a previously configured authority cannot be resolved.
        if reserved_locked or managed_policy is not None or policy_hash is not None:
            return StructuredOutputResolution(None, True, "structured_managed_authority_revoked")
        return StructuredOutputResolution(None, False)

    # An active policy without this exact locked path has not enrolled the
    # adapter when the reserved value is absent.  A value present outside the
    # lock set is a configured but unverifiable authority and must not silently
    # downgrade to the text-only path.
    if not reserved_locked:
        settings = getattr(managed_policy, "settings", None)
        if isinstance(settings, Mapping) and _setting_path_present(settings, STRUCTURED_OUTPUT_SETTING_PATH):
            return StructuredOutputResolution(None, True, "structured_managed_policy_invalid")
        return StructuredOutputResolution(None, False)

    if _valid_policy_hash(policy_hash) is None:
        return StructuredOutputResolution(None, True, "structured_managed_policy_invalid")
    if managed_policy is None:
        return StructuredOutputResolution(None, True, "structured_managed_policy_missing")
    content_hash = getattr(managed_policy, "content_hash", None)
    if _valid_policy_hash(content_hash) is None or content_hash != policy_hash:
        return StructuredOutputResolution(None, True, "structured_managed_policy_invalid")
    settings = getattr(managed_policy, "settings", None)
    if not isinstance(settings, Mapping):
        return StructuredOutputResolution(None, True, "structured_managed_policy_invalid")
    try:
        structured_policy = parse_structured_output_policy(_setting_at_path(settings, STRUCTURED_OUTPUT_SETTING_PATH))
    except (TypeError, ValueError):
        return StructuredOutputResolution(None, True, "structured_managed_policy_invalid")
    if canonical_harness not in structured_policy.harnesses:
        return StructuredOutputResolution(None, False)

    binding = resolve_managed_structured_output_binding(config, harness=canonical_harness)
    if binding is None:
        return StructuredOutputResolution(None, True, "structured_managed_policy_invalid")
    return StructuredOutputResolution(binding, True)


def _reject_constant(_value: str) -> object:
    raise ValueError("nonstandard JSON constant")


def _has_safe_numbers(value: object, *, deadline_monotonic: float | None = None) -> bool:
    """Require safe integers within the object-only declared field schema.

    Arrays are unsupported by that schema even when their elements are safe.
    """
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        return False
    if type(value) is int:
        return abs(value) <= STRUCTURED_MEDIATION_MAX_SAFE_INTEGER
    if isinstance(value, float):
        return False
    if isinstance(value, dict):
        return all(_has_safe_numbers(child, deadline_monotonic=deadline_monotonic) for child in value.values())
    return not isinstance(value, list)


def canonical_structured_content_bytes(value: object, *, deadline_monotonic: float | None = None) -> bytes | None:
    """Validate the receiver's exact canonical JSON text without rewriting it.

    Sorted object keys, compact separators, literal Unicode and the closed
    field schema bind the checked bytes to the bytes forwarded by the receiver.
    Semantically equivalent JSON with different formatting is unsupported.
    """

    def deadline_exceeded() -> bool:
        return deadline_monotonic is not None and time.monotonic() >= deadline_monotonic

    if deadline_exceeded():
        return None
    if not isinstance(value, str) or "\\" in value:
        return None
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    if deadline_exceeded():
        return None
    if not encoded or len(encoded) > STRUCTURED_MEDIATION_MAX_BYTES:
        return None
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=lambda pairs: unique_json_object(pairs, duplicate_error="duplicate JSON field"),
            parse_constant=_reject_constant,
        )
    except (TypeError, ValueError, RecursionError):
        return None
    if deadline_exceeded():
        return None
    try:
        safe_numbers = _has_safe_numbers(parsed, deadline_monotonic=deadline_monotonic)
    except RecursionError:
        return None
    if not isinstance(parsed, dict) or not safe_numbers:
        return None
    try:
        # The closed value validation above excludes floats and non-finite
        # numbers before using the shared canonical serializer.
        canonical = stable_json_serialize(parsed)
        canonical_bytes = canonical.encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None
    if deadline_exceeded():
        return None
    if len(canonical_bytes) > STRUCTURED_MEDIATION_MAX_BYTES or canonical != value:
        return None
    return encoded


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


def _withhold(reason_code: str, native_decision_id: str | None) -> StructuredContentMediation:
    return StructuredContentMediation(
        action="withhold",
        reason_code=reason_code,
        native_decision_id=native_decision_id,
    )


def _decision_id(receipt: Mapping[str, object] | None) -> str | None:
    value = receipt.get("decision_id") if receipt is not None else None
    return value if isinstance(value, str) and value else None


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
    """Create one ephemeral adapter disposition after native receipt validation.

    ``cancelled`` is reserved for callers that expose cancellation directly.
    The daemon caller currently supplies its deadline; generated receivers
    check their lifecycle signal before returning model-visible content.

    ``allow_observe_mode`` is reserved for an enrolled managed structured
    policy.  It lets this stricter destination check run while the broader
    native command posture is recording-only; it never changes the Rust
    result, receipt, or watch behavior for an unconfigured route.
    """

    canonical_harness = canonical_harness_name(harness)
    if canonical_harness not in _SUPPORTED_HARNESSES:
        return None
    if event_name != "PostToolUse":
        return None
    native_decision_id = _decision_id(validated_receipt)
    if native_result.get("decision") != "allow":
        return None
    if native_result.get("observe_mode") is True and not allow_observe_mode:
        return None
    if native_result.get("model_output_action") != "allow_original":
        return _withhold("structured_content_unproved", native_decision_id)
    if validated_receipt is None or validated_receipt.get("decision") != "allow" or native_decision_id is None:
        return _withhold("structured_receipt_missing", native_decision_id)
    if binding is None:
        if required_reason_code is None:
            return None
        return _withhold(required_reason_code, native_decision_id)
    if binding.harness != canonical_harness:
        return None
    if cancelled:
        return _withhold("structured_review_cancelled", native_decision_id)
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        return _withhold("structured_review_deadline_exceeded", native_decision_id)
    candidate = canonical_structured_content_bytes(
        structured_output_json,
        deadline_monotonic=deadline_monotonic,
    )
    if candidate is None:
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            return _withhold("structured_review_deadline_exceeded", native_decision_id)
        return _withhold("structured_content_unproved", native_decision_id)
    scan: SensitiveScanResult = classify_declared_content(
        candidate,
        schema=binding.policy.schema,
        deadline_monotonic=deadline_monotonic,
    )
    if scan.status != "no_declared_match" or not scan.complete:
        return _withhold(f"structured_{scan.reason_code}", native_decision_id)
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        return _withhold("structured_review_deadline_exceeded", native_decision_id)
    if recheck_binding is None:
        return _withhold("structured_binding_recheck_missing", native_decision_id)
    try:
        refreshed = recheck_binding()
    except (AttributeError, TypeError, ValueError):
        refreshed = None
    except Exception as exc:
        # Error classes aid diagnosis without recording callback data or paths.
        _LOGGER.warning("Structured output binding recheck failed (%s)", type(exc).__name__)
        return _withhold("structured_binding_recheck_failed", native_decision_id)
    if refreshed is None or refreshed.identity != binding.identity:
        return _withhold("structured_binding_changed", native_decision_id)
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        return _withhold("structured_review_deadline_exceeded", native_decision_id)
    return StructuredContentMediation(
        action="forward",
        reason_code="structured_clean_forward",
        native_decision_id=native_decision_id,
        content_sha256=hashlib.sha256(candidate).hexdigest(),
    )


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
    "canonical_structured_content_bytes",
    "mediate_native_post_tool_content",
    "parse_structured_output_policy",
    "resolve_managed_structured_output_binding",
    "resolve_managed_structured_output_resolution",
]
