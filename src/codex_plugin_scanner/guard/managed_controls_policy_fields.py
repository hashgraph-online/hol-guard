"""Strict HOL Guard Managed Controls policy-field parsing entry point.

The implementation remains isolated in ``managed_controls_policy_fields_core`` so
this module can enforce presence-sensitive wire bounds before any projection.
"""

from __future__ import annotations

from typing import TypeGuard, cast

from . import managed_controls_policy_fields_core as _core
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_limits import MAX_CONTROL_SET_RULES

EXTENSION_CONTROL_LAYER_CAPABILITY = _core.EXTENSION_CONTROL_LAYER_CAPABILITY
HOL_EXTENSION_CONTROLS_FIELD = _core.HOL_EXTENSION_CONTROLS_FIELD
HOL_EXTENSION_CONTROLS_SCHEMA_VERSION = _core.HOL_EXTENSION_CONTROLS_SCHEMA_VERSION
HOL_EXTENSION_TARGETS_FIELD = _core.HOL_EXTENSION_TARGETS_FIELD
HOL_EXTENSION_TARGETS_SCHEMA_VERSION = _core.HOL_EXTENSION_TARGETS_SCHEMA_VERSION
MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY = _core.MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY
PACKAGE_FIREWALL_CAPABILITY = _core.PACKAGE_FIREWALL_CAPABILITY
POLICY_EXTENSION_TARGETS_CAPABILITY = _core.POLICY_EXTENSION_TARGETS_CAPABILITY
DelegatedExtensionTarget = _core.DelegatedExtensionTarget
ExtensionRuleTargets = _core.ExtensionRuleTargets
ManagedControlsPolicyError = _core.ManagedControlsPolicyError
ParsedManagedControlsPolicy = _core.ParsedManagedControlsPolicy


def is_mapping(value: object) -> TypeGuard[dict[str, object]]:
    """Return whether a value is a string-keyed object."""

    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in cast(dict[object, object], value))


def _mapping(value: object, *, code: str, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in cast(dict[object, object], value)):
        raise ManagedControlsPolicyError(code, f"{label} must be an object.")
    return cast(dict[str, object], value)


def _validate_presence_sensitive_fields(document: dict[str, object]) -> None:
    """Reject explicit nulls and excessive targeted rules before core parsing."""

    if HOL_EXTENSION_CONTROLS_FIELD in document:
        _mapping(
            document[HOL_EXTENSION_CONTROLS_FIELD],
            code="invalid_extension_controls",
            label=HOL_EXTENSION_CONTROLS_FIELD,
        )

    spec = _mapping(
        document.get("spec"),
        code="invalid_policy_document",
        label="GuardPolicy spec",
    )
    rules = spec.get("rules")
    if not isinstance(rules, list):
        raise ManagedControlsPolicyError(
            "invalid_policy_document",
            "GuardPolicy rules must be an array.",
        )

    targeted_rule_count = 0
    for rule_value in rules:
        rule = _mapping(
            rule_value,
            code="invalid_policy_document",
            label="GuardPolicy rule",
        )
        if HOL_EXTENSION_TARGETS_FIELD not in rule:
            continue
        targeted_rule_count += 1
        if targeted_rule_count > MAX_CONTROL_SET_RULES:
            raise ManagedControlsPolicyError(
                "rule_limit_exceeded",
                "Extension-targeted rules exceed the supported limit.",
            )
        _mapping(
            rule[HOL_EXTENSION_TARGETS_FIELD],
            code="invalid_extension_targets",
            label=HOL_EXTENSION_TARGETS_FIELD,
        )


def parse_managed_controls_policy_fields(
    document: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry,
    negotiated_capabilities: frozenset[str],
    package_firewall_supported: bool = False,
) -> ParsedManagedControlsPolicy:
    """Validate presence-sensitive fields, then use the canonical projection."""

    _validate_presence_sensitive_fields(document)
    capabilities = negotiated_capabilities
    if package_firewall_supported:
        capabilities = capabilities | frozenset({PACKAGE_FIREWALL_CAPABILITY})
    return _core.parse_managed_controls_policy_fields(
        document,
        registry=registry,
        capabilities=capabilities,
    )
