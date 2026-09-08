"""Strict parsing for the frozen signed Extension-targeted policy fields."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .authority import AuthorityMode, ControlEffect, ControlInstruction
from .catalog import CatalogProjection, CatalogValidationError

_CONTROLS_FIELD = "x-hol-extension-controls"
_TARGETS_FIELD = "x-hol-extension-targets"
_CONTROLS_SCHEMA = "guard.extension-controls.v1"
_TARGETS_SCHEMA = "guard.policy-extension-targets.v1"


class ManagedControlsBundleError(ValueError):
    """Raised when a bundle extension is malformed or unsupported."""


@dataclass(frozen=True, slots=True)
class ExtensionTarget:
    extension_id: str
    permission_id: str | None


@dataclass(frozen=True, slots=True)
class ParsedExtensionContract:
    controls: tuple[ControlInstruction, ...]
    rule_targets: dict[str, tuple[ExtensionTarget, ...]]


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ManagedControlsBundleError(f"{label} must be an object")
    return value


def _exact_keys(value: dict[str, object], allowed: frozenset[str], label: str) -> None:
    if not set(value) <= allowed:
        raise ManagedControlsBundleError(f"{label} contains unsupported fields")


def _extension_target(extension_id: object, catalog: CatalogProjection) -> ExtensionTarget:
    if not isinstance(extension_id, str):
        raise ManagedControlsBundleError("extension target id is required")
    if not any(item.extension_id == extension_id for item in catalog.extensions):
        raise CatalogValidationError("unknown extension target")
    return ExtensionTarget(extension_id, None)


def _permission_target(permission_id: object, catalog: CatalogProjection) -> ExtensionTarget:
    if not isinstance(permission_id, str):
        raise ManagedControlsBundleError("permission target id is required")
    extension_id, _permission = catalog.permission_target(permission_id)
    return ExtensionTarget(extension_id, permission_id)


def _control_instruction(
    value: object,
    *,
    authority: AuthorityMode,
    index: int,
    catalog: CatalogProjection,
) -> ControlInstruction:
    control = _mapping(value, "extension control")
    _exact_keys(control, frozenset({"targetKind", "targetId", "state"}), "extension control")
    kind = control.get("targetKind")
    if kind == "extension":
        target = _extension_target(control.get("targetId"), catalog)
    elif kind == "permission":
        target = _permission_target(control.get("targetId"), catalog)
    else:
        raise ManagedControlsBundleError("extension control target kind is invalid")
    state = control.get("state")
    if state == "enabled":
        effect = ControlEffect.PERMIT
    elif state == "disabled":
        effect = ControlEffect.BLOCK
    else:
        raise ManagedControlsBundleError("extension control state is invalid")
    return ControlInstruction(
        target.extension_id,
        target.permission_id,
        effect,
        authority,
        f"control-{index}",
    )


def _parse_controls(
    document: dict[str, Any],
    catalog: CatalogProjection,
) -> tuple[ControlInstruction, ...]:
    if _CONTROLS_FIELD not in document:
        return ()
    field = _mapping(document[_CONTROLS_FIELD], _CONTROLS_FIELD)
    _exact_keys(
        field,
        frozenset({"schemaVersion", "authorityMode", "globalLockdown", "controls"}),
        _CONTROLS_FIELD,
    )
    if field.get("schemaVersion") != _CONTROLS_SCHEMA:
        raise ManagedControlsBundleError("extension control schema is unsupported")
    authority_value = field.get("authorityMode")
    try:
        authority = AuthorityMode(authority_value)
    except (TypeError, ValueError) as error:
        raise ManagedControlsBundleError("extension control authority is invalid") from error
    raw_controls = field.get("controls")
    if not isinstance(raw_controls, list):
        raise ManagedControlsBundleError("extension controls must be an array")
    controls = [
        _control_instruction(
            value,
            authority=authority,
            index=index,
            catalog=catalog,
        )
        for index, value in enumerate(raw_controls)
    ]
    lockdown = field.get("globalLockdown")
    if lockdown not in (None, True):
        raise ManagedControlsBundleError("global lockdown must be true when present")
    if lockdown is True:
        controls.append(
            ControlInstruction(
                None,
                None,
                ControlEffect.LOCKDOWN,
                authority,
                "global-lockdown",
            )
        )
    return tuple(controls)


def _parse_rule_targets(
    document: dict[str, Any],
    catalog: CatalogProjection,
) -> dict[str, tuple[ExtensionTarget, ...]]:
    spec = _mapping(document.get("spec"), "policy spec")
    raw_rules = spec.get("rules")
    if not isinstance(raw_rules, list):
        raise ManagedControlsBundleError("policy rules must be an array")
    parsed: dict[str, tuple[ExtensionTarget, ...]] = {}
    for rule_value in raw_rules:
        rule = _mapping(rule_value, "policy rule")
        if _TARGETS_FIELD not in rule:
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise ManagedControlsBundleError("extension-targeted rule requires an id")
        if rule_id in parsed:
            raise ManagedControlsBundleError("duplicate extension-targeted rule id")
        field = _mapping(rule[_TARGETS_FIELD], _TARGETS_FIELD)
        _exact_keys(
            field,
            frozenset({"schemaVersion", "extensionIds", "permissionIds"}),
            _TARGETS_FIELD,
        )
        if field.get("schemaVersion") != _TARGETS_SCHEMA:
            raise ManagedControlsBundleError("extension target schema is unsupported")
        extension_ids = field.get("extensionIds")
        permission_ids = field.get("permissionIds")
        if not isinstance(extension_ids, list) or not isinstance(permission_ids, list):
            raise ManagedControlsBundleError("extension target ids must be arrays")
        targets = [
            *(_extension_target(value, catalog) for value in extension_ids),
            *(_permission_target(value, catalog) for value in permission_ids),
        ]
        if len(set(targets)) != len(targets):
            raise ManagedControlsBundleError("duplicate extension target")
        parsed[rule_id] = tuple(targets)
    return parsed


def parse_extension_contract(
    document: dict[str, Any],
    catalog: CatalogProjection,
) -> ParsedExtensionContract:
    return ParsedExtensionContract(
        _parse_controls(document, catalog),
        _parse_rule_targets(document, catalog),
    )
