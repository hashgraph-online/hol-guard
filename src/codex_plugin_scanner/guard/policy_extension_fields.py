"""Strict HOL Guard Extension fields embedded in canonical GuardPolicy documents.

The Cloud owns signed orchestration. The Local registry remains authoritative for
Extension and permission identities, detector ownership, floors, delegation,
and configurability.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, TypeGuard, cast

from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from .runtime.extension_control_limits import MAX_CONTROL_SET_TARGETS, MAX_CONTROLS_PER_LAYER

HOL_EXTENSION_CONTROLS_FIELD: Final = "x-hol-extension-controls"
HOL_EXTENSION_TARGETS_FIELD: Final = "x-hol-extension-targets"
HOL_EXTENSION_CONTROLS_SCHEMA_VERSION: Final = "guard.extension-controls.v1"
HOL_EXTENSION_TARGETS_SCHEMA_VERSION: Final = "guard.policy-extension-targets.v1"

EXTENSION_CONTROL_LAYER_CAPABILITY: Final = "extension-control-layer.v1"
POLICY_EXTENSION_TARGETS_CAPABILITY: Final = "policy-extension-targets.v1"
MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY: Final = "managed-controls-atomic-apply.v1"

_LEGACY_CAPABILITY_ALIASES: Final[dict[str, frozenset[str]]] = {
    EXTENSION_CONTROL_LAYER_CAPABILITY: frozenset({"guard.managed-extension-controls.v1"}),
    POLICY_EXTENSION_TARGETS_CAPABILITY: frozenset({"guard.policy-extension-targets.v1"}),
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY: frozenset({"guard.managed-controls-atomic-apply.v1"}),
}

_AUTHORITY_MODES: Final = frozenset({"personal-shared", "workspace-shared", "managed-restrictive"})
_TARGET_KINDS: Final = frozenset({"extension", "permission"})
_CONTROL_STATES: Final = frozenset({"enabled", "disabled"})
_EXTENSION_ID = re.compile(r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_PERMISSION_ID = re.compile(
    r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$"
)
_MAX_ID_BYTES: Final = 256


class PolicyExtensionFieldError(ValueError):
    """A stable, bounded rejection for malformed or unsupported Extension fields."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True, order=True)
class PolicyExtensionControl:
    target_kind: str
    target_id: str
    state: str


@dataclass(frozen=True, slots=True)
class PolicyExtensionControlEnvelope:
    authority_mode: str
    global_lockdown: bool
    controls: tuple[PolicyExtensionControl, ...]


@dataclass(frozen=True, slots=True)
class PolicyExtensionRuleTargets:
    extension_ids: tuple[str, ...]
    permission_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ParsedPolicyExtensionFields:
    controls: PolicyExtensionControlEnvelope | None
    rule_targets: tuple[tuple[str, PolicyExtensionRuleTargets], ...]

    @property
    def has_semantics(self) -> bool:
        return self.controls is not None or bool(self.rule_targets)

    def targets_for_rule(self, rule_id: str) -> PolicyExtensionRuleTargets | None:
        return next((targets for candidate, targets in self.rule_targets if candidate == rule_id), None)


@dataclass(frozen=True, slots=True)
class ValidatedPolicyExtensionProjection:
    parsed: ParsedPolicyExtensionFields
    signed_cloud_layer: ExtensionControlLayer | None



def _is_mapping(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in cast(dict[object, object], value))


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not _is_mapping(value):
        raise PolicyExtensionFieldError("invalid_shape", f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, object], *, allowed: frozenset[str], label: str) -> None:
    if any(key not in allowed for key in value):
        raise PolicyExtensionFieldError("unknown_field", f"{label} contains an unknown field")


def _canonical_extension_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > _MAX_ID_BYTES
        or _EXTENSION_ID.fullmatch(value) is None
        or ".permission." in value
    ):
        raise PolicyExtensionFieldError("invalid_extension_id", "Extension ID is not canonical")
    return value


def _canonical_permission_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > _MAX_ID_BYTES
        or _PERMISSION_ID.fullmatch(value) is None
    ):
        raise PolicyExtensionFieldError("invalid_permission_id", "Permission ID is not canonical")
    return value


def _unique_ids(value: object, *, label: str, parser: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyExtensionFieldError("invalid_shape", f"{label} must be an array")
    parse = cast(object, parser)
    if parse is _canonical_extension_id:
        parsed = tuple(sorted(_canonical_extension_id(item) for item in value))
    elif parse is _canonical_permission_id:
        parsed = tuple(sorted(_canonical_permission_id(item) for item in value))
    else:
        raise AssertionError("unsupported ID parser")
    if len(parsed) != len(set(parsed)):
        raise PolicyExtensionFieldError("duplicate_target", f"{label} contains a duplicate target")
    return parsed


def _parse_control(value: object) -> PolicyExtensionControl:
    control = _mapping(value, label="Extension control")
    _exact_keys(
        control,
        allowed=frozenset({"targetKind", "targetId", "state"}),
        label="Extension control",
    )
    target_kind = control.get("targetKind")
    state = control.get("state")
    if target_kind not in _TARGET_KINDS:
        raise PolicyExtensionFieldError("invalid_target_kind", "Extension control target kind is invalid")
    if state not in _CONTROL_STATES:
        raise PolicyExtensionFieldError("invalid_control_state", "Extension control state is invalid")
    target_id = (
        _canonical_extension_id(control.get("targetId"))
        if target_kind == "extension"
        else _canonical_permission_id(control.get("targetId"))
    )
    return PolicyExtensionControl(str(target_kind), target_id, str(state))


def _parse_controls(value: object) -> PolicyExtensionControlEnvelope:
    envelope = _mapping(value, label=HOL_EXTENSION_CONTROLS_FIELD)
    _exact_keys(
        envelope,
        allowed=frozenset({"schemaVersion", "authorityMode", "globalLockdown", "controls"}),
        label=HOL_EXTENSION_CONTROLS_FIELD,
    )
    if envelope.get("schemaVersion") != HOL_EXTENSION_CONTROLS_SCHEMA_VERSION:
        raise PolicyExtensionFieldError("unsupported_control_schema", "Extension control schema is unsupported")
    authority_mode = envelope.get("authorityMode")
    if authority_mode not in _AUTHORITY_MODES:
        raise PolicyExtensionFieldError("invalid_authority", "Extension authority mode is invalid")
    raw_controls = envelope.get("controls")
    if not isinstance(raw_controls, list):
        raise PolicyExtensionFieldError("invalid_shape", "Extension controls must be an array")
    if len(raw_controls) > MAX_CONTROLS_PER_LAYER:
        raise PolicyExtensionFieldError("control_limit_exceeded", "Extension control layer exceeds its limit")
    controls = tuple(sorted(_parse_control(item) for item in raw_controls))
    for previous, current in zip(controls, controls[1:], strict=False):
        if previous.target_kind == current.target_kind and previous.target_id == current.target_id:
            code = "duplicate_target" if previous.state == current.state else "conflicting_target"
            raise PolicyExtensionFieldError(code, "Duplicate or conflicting Extension controls are not allowed")
    raw_lockdown = envelope.get("globalLockdown", False)
    if type(raw_lockdown) is not bool:
        raise PolicyExtensionFieldError("invalid_global_lockdown", "Global lockdown must be a boolean")
    global_lockdown = cast(bool, raw_lockdown)
    if global_lockdown and authority_mode != "managed-restrictive":
        raise PolicyExtensionFieldError("invalid_authority", "Global lockdown requires managed-restrictive authority")
    if authority_mode == "managed-restrictive" and any(control.state != "disabled" for control in controls):
        raise PolicyExtensionFieldError(
            "managed_restrictive_broadening",
            "Managed-restrictive controls cannot enable a capability",
        )
    return PolicyExtensionControlEnvelope(str(authority_mode), global_lockdown, controls)


def _parse_rule_targets(value: object) -> PolicyExtensionRuleTargets:
    targets = _mapping(value, label=HOL_EXTENSION_TARGETS_FIELD)
    _exact_keys(
        targets,
        allowed=frozenset({"schemaVersion", "extensionIds", "permissionIds"}),
        label=HOL_EXTENSION_TARGETS_FIELD,
    )
    if targets.get("schemaVersion") != HOL_EXTENSION_TARGETS_SCHEMA_VERSION:
        raise PolicyExtensionFieldError("unsupported_target_schema", "Extension target schema is unsupported")
    extension_ids = _unique_ids(
        targets.get("extensionIds"),
        label="extensionIds",
        parser=_canonical_extension_id,
    )
    permission_ids = _unique_ids(
        targets.get("permissionIds"),
        label="permissionIds",
        parser=_canonical_permission_id,
    )
    if len(extension_ids) + len(permission_ids) > MAX_CONTROL_SET_TARGETS:
        raise PolicyExtensionFieldError("target_limit_exceeded", "Extension targets exceed their limit")
    return PolicyExtensionRuleTargets(extension_ids, permission_ids)


def parse_policy_extension_fields(document: Mapping[str, object]) -> ParsedPolicyExtensionFields:
    controls = (
        _parse_controls(document[HOL_EXTENSION_CONTROLS_FIELD])
        if HOL_EXTENSION_CONTROLS_FIELD in document
        else None
    )
    spec = _mapping(document.get("spec"), label="GuardPolicy spec")
    rules = spec.get("rules")
    if not isinstance(rules, list):
        raise PolicyExtensionFieldError("invalid_policy_document", "GuardPolicy rules must be an array")
    parsed_targets: list[tuple[str, PolicyExtensionRuleTargets]] = []
    seen_rule_ids: set[str] = set()
    for item in rules:
        rule = _mapping(item, label="GuardPolicy rule")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyExtensionFieldError("invalid_policy_document", "GuardPolicy rule ID is invalid")
        if rule_id in seen_rule_ids:
            raise PolicyExtensionFieldError("duplicate_rule_id", "GuardPolicy rule IDs must be unique")
        seen_rule_ids.add(rule_id)
        if HOL_EXTENSION_TARGETS_FIELD in rule:
            parsed_targets.append((rule_id, _parse_rule_targets(rule[HOL_EXTENSION_TARGETS_FIELD])))
    return ParsedPolicyExtensionFields(controls, tuple(sorted(parsed_targets)))


def _capability_present(capabilities: frozenset[str], required: str) -> bool:
    return required in capabilities or any(alias in capabilities for alias in _LEGACY_CAPABILITY_ALIASES[required])


def required_policy_extension_capabilities(parsed: ParsedPolicyExtensionFields) -> tuple[str, ...]:
    if not parsed.has_semantics:
        return ()
    required = {
        POLICY_EXTENSION_TARGETS_CAPABILITY,
        MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    }
    if parsed.controls is not None:
        required.add(EXTENSION_CONTROL_LAYER_CAPABILITY)
    return tuple(sorted(required))


def validate_policy_extension_capabilities(
    parsed: ParsedPolicyExtensionFields,
    negotiated_capabilities: frozenset[str],
) -> None:
    missing = tuple(
        capability
        for capability in required_policy_extension_capabilities(parsed)
        if not _capability_present(negotiated_capabilities, capability)
    )
    if missing:
        raise PolicyExtensionFieldError(
            "unnegotiated_extension_semantics",
            "Extension semantics require negotiated capabilities: " + ", ".join(missing),
        )


def _validate_extension_target(registry: CommandSafetyExtensionRegistry, target_id: str) -> None:
    extension = registry.get(target_id)
    if extension is None:
        raise PolicyExtensionFieldError("unknown_extension_target", "Extension target is not in the Local catalog")
    if extension.extension_id != target_id:
        raise PolicyExtensionFieldError("non_canonical_target", "Extension target uses an alias")


def _validate_permission_target(registry: CommandSafetyExtensionRegistry, target_id: str) -> None:
    permission = registry.permission(target_id)
    if permission is None:
        raise PolicyExtensionFieldError("unknown_permission_target", "Permission target is not in the Local catalog")
    if permission.permission_id != target_id:
        raise PolicyExtensionFieldError("non_canonical_target", "Permission target is not canonical")


def validate_policy_extension_targets(
    parsed: ParsedPolicyExtensionFields,
    registry: CommandSafetyExtensionRegistry,
) -> None:
    if parsed.controls is not None:
        for control in parsed.controls.controls:
            if control.target_kind == "extension":
                _validate_extension_target(registry, control.target_id)
            else:
                _validate_permission_target(registry, control.target_id)
                permission = registry.permission(control.target_id)
                if (
                    control.state == "enabled"
                    and permission is not None
                    and not permission.configurable
                ):
                    raise PolicyExtensionFieldError(
                        "immutable_permission_enable",
                        "Cloud cannot enable an immutable permission",
                    )
    for _rule_id, targets in parsed.rule_targets:
        for extension_id in targets.extension_ids:
            _validate_extension_target(registry, extension_id)
        for permission_id in targets.permission_ids:
            _validate_permission_target(registry, permission_id)


def signed_cloud_extension_layer(
    parsed: ParsedPolicyExtensionFields,
    registry: CommandSafetyExtensionRegistry,
) -> ExtensionControlLayer | None:
    if parsed.controls is None:
        return None
    controls = tuple(
        ExtensionControl(
            target=ControlTarget(
                ControlTargetKind.EXTENSION
                if control.target_kind == "extension"
                else ControlTargetKind.PERMISSION,
                control.target_id,
            ),
            state=ControlState.ENABLED if control.state == "enabled" else ControlState.DISABLED,
        )
        for control in parsed.controls.controls
    )
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.SIGNED_CLOUD,
        catalog_digest=registry.catalog_digest,
        global_lockdown=parsed.controls.global_lockdown,
        controls=controls,
    )


def validate_and_project_policy_extension_fields(
    document: Mapping[str, object],
    *,
    negotiated_capabilities: frozenset[str],
    registry: CommandSafetyExtensionRegistry,
) -> ValidatedPolicyExtensionProjection:
    parsed = parse_policy_extension_fields(document)
    validate_policy_extension_capabilities(parsed, negotiated_capabilities)
    validate_policy_extension_targets(parsed, registry)
    return ValidatedPolicyExtensionProjection(parsed, signed_cloud_extension_layer(parsed, registry))
