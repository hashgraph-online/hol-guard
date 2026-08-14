"""Immutable command-extension permission metadata and deterministic indexes."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, final

from ..models import GuardAction
from .command_rules import CommandRuleMode, CommandRuleSeverity, CommandSafetyRule, example_for_matcher

PermissionRiskTier = CommandRuleSeverity
COMMAND_PERMISSION_SCHEMA_VERSION: Final = 1
_PERMISSION_ID_PATTERN = re.compile(r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:-[a-z0-9]+)*$")
_FAMILY_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_EXAMPLE_MAX_LENGTH = 120
_MODE_FLOOR: Final[dict[CommandRuleMode, GuardAction]] = {
    "disabled": "allow",
    "monitor": "warn",
    "review": "review",
    "enforce": "block",
    "required": "review",
}


@dataclass(frozen=True, slots=True)
class CommandPermissionSpec:
    """Static metadata for one independently controllable command capability."""

    permission_id: str
    schema_version: int
    extension_id: str
    implementation_version: str
    label: str
    description: str
    risk_tier: PermissionRiskTier
    baseline_floor: GuardAction
    default_enabled: bool
    configurable: bool
    fixed_reason: str | None
    typed_capabilities: tuple[str, ...]
    action_classes: tuple[str, ...]
    rule_ids: tuple[str, ...]
    dependencies: tuple[str, ...]
    conflicts: tuple[str, ...]
    implied_permissions: tuple[str, ...]
    introduced_version: str
    deprecated: bool
    replacement_permission_id: str | None
    safer_guidance: tuple[str, ...]
    example_command: str | None = None
    family: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "permission_id": self.permission_id,
            "schema_version": self.schema_version,
            "extension_id": self.extension_id,
            "implementation_version": self.implementation_version,
            "label": self.label,
            "description": self.description,
            "risk_tier": self.risk_tier,
            "baseline_floor": self.baseline_floor,
            "default_enabled": self.default_enabled,
            "configurable": self.configurable,
            "fixed_reason": self.fixed_reason,
            "typed_capabilities": list(self.typed_capabilities),
            "action_classes": list(self.action_classes),
            "rule_ids": list(self.rule_ids),
            "dependencies": list(self.dependencies),
            "conflicts": list(self.conflicts),
            "implied_permissions": list(self.implied_permissions),
            "introduced_version": self.introduced_version,
            "deprecated": self.deprecated,
            "replacement_permission_id": self.replacement_permission_id,
            "safer_guidance": list(self.safer_guidance),
            "example_command": self.example_command,
            "family": self.family,
        }


@final
class CommandPermissionCatalog:
    """Validated permission metadata with stable deterministic indexes."""

    __slots__ = (
        "_by_action_class",
        "_by_capability",
        "_by_id",
        "_by_rule_id",
        "_digest",
        "_permissions",
    )

    def __init__(self, permissions: tuple[CommandPermissionSpec, ...]) -> None:
        ordered = tuple(sorted(permissions, key=lambda permission: permission.permission_id))
        by_id: dict[str, CommandPermissionSpec] = {}
        by_rule_id: dict[str, CommandPermissionSpec] = {}
        by_action_class: dict[str, CommandPermissionSpec] = {}
        by_capability: dict[str, CommandPermissionSpec] = {}
        for permission in ordered:
            _validate_permission(permission)
            if permission.permission_id in by_id:
                raise ValueError(f"duplicate permission ID: {permission.permission_id}")
            by_id[permission.permission_id] = permission
            _index_unique(by_rule_id, permission.rule_ids, permission, "rule", normalize=True)
            _index_first(
                by_action_class,
                permission.action_classes,
                permission,
                normalize=True,
            )
            _index_unique(
                by_capability,
                permission.typed_capabilities,
                permission,
                "typed capability",
                normalize=True,
            )
        _validate_references(ordered, by_id)
        _validate_dependency_cycles(ordered, by_id)
        _validate_family_scope(ordered)
        self._permissions = ordered
        self._by_id = MappingProxyType(by_id)
        self._by_rule_id = MappingProxyType(by_rule_id)
        self._by_action_class = MappingProxyType(by_action_class)
        self._by_capability = MappingProxyType(by_capability)
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self._digest = hashlib.sha256(canonical).hexdigest()

    @property
    def permissions(self) -> tuple[CommandPermissionSpec, ...]:
        return self._permissions

    @property
    def digest(self) -> str:
        return self._digest

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": COMMAND_PERMISSION_SCHEMA_VERSION,
            "permissions": [permission.to_dict() for permission in self.permissions],
        }

    def get(self, permission_id: str) -> CommandPermissionSpec | None:
        return self._by_id.get(permission_id.strip().lower())

    def for_rule_id(self, rule_id: str) -> CommandPermissionSpec | None:
        return self._by_rule_id.get(rule_id.strip().lower())

    def for_action_class(self, action_class: str) -> CommandPermissionSpec | None:
        """Return one permission for a shared action class.

        Compatibility lookups remain action-class keyed. Independent floors use
        ``for_rule_id`` because several rules may share one action class.
        """

        return self._by_action_class.get(action_class.strip().lower())

    def for_typed_capability(self, capability: str) -> CommandPermissionSpec | None:
        return self._by_capability.get(capability.strip().lower())


def permission_for_rule(
    extension_id: str,
    implementation_version: str,
    rule: CommandSafetyRule,
    *,
    configurable: bool,
) -> CommandPermissionSpec:
    suffix = rule.rule_id.removeprefix(f"{extension_id}.")
    return CommandPermissionSpec(
        permission_id=f"{extension_id}.permission.{suffix}",
        schema_version=COMMAND_PERMISSION_SCHEMA_VERSION,
        extension_id=extension_id,
        implementation_version=implementation_version,
        label=rule.title,
        description=rule.description,
        risk_tier=rule.severity,
        baseline_floor=_MODE_FLOOR[rule.default_mode],
        default_enabled=True,
        configurable=configurable,
        fixed_reason=None if configurable else "This safety permission is immutable.",
        typed_capabilities=(),
        action_classes=rule.action_classes,
        rule_ids=(rule.rule_id,),
        dependencies=(),
        conflicts=(),
        implied_permissions=(),
        introduced_version="2.2.0",
        deprecated=False,
        replacement_permission_id=None,
        safer_guidance=rule.safer_alternatives,
        example_command=rule.example_command or example_for_matcher(rule.matcher),
        family=rule.family,
    )


def permissions_for_rules(
    extension_id: str,
    implementation_version: str,
    rules: tuple[CommandSafetyRule, ...],
    *,
    configurable: bool,
) -> tuple[CommandPermissionSpec, ...]:
    return tuple(
        sorted(
            (
                permission_for_rule(
                    extension_id,
                    implementation_version,
                    rule,
                    configurable=configurable,
                )
                for rule in rules
            ),
            key=lambda permission: permission.permission_id,
        )
    )


def permissions_for_action_classes(
    extension_id: str,
    implementation_version: str,
    action_classes: tuple[str, ...],
    safer_guidance: tuple[str, ...],
    *,
    configurable: bool,
    example_command: str | None = None,
) -> tuple[CommandPermissionSpec, ...]:
    permissions: list[CommandPermissionSpec] = []
    for action_class in action_classes:
        suffix = re.sub(r"[^a-z0-9]+", "-", action_class.lower()).strip("-")
        permissions.append(
            CommandPermissionSpec(
                permission_id=f"{extension_id}.permission.{suffix}",
                schema_version=COMMAND_PERMISSION_SCHEMA_VERSION,
                extension_id=extension_id,
                implementation_version=implementation_version,
                label=action_class,
                description=f"Controls the {action_class} capability.",
                risk_tier="high",
                baseline_floor="review",
                default_enabled=True,
                configurable=configurable,
                fixed_reason=None if configurable else "This safety permission is immutable.",
                typed_capabilities=(),
                action_classes=(action_class,),
                rule_ids=(),
                dependencies=(),
                conflicts=(),
                implied_permissions=(),
                introduced_version="2.2.0",
                deprecated=False,
                replacement_permission_id=None,
                safer_guidance=safer_guidance,
                example_command=example_command,
            )
        )
    return tuple(permissions)


def delegated_permission(
    extension_id: str,
    implementation_version: str,
    label: str,
    description: str,
    safer_guidance: tuple[str, ...],
    example_command: str | None = None,
) -> CommandPermissionSpec:
    return CommandPermissionSpec(
        permission_id=f"{extension_id}.permission.package-protection",
        schema_version=COMMAND_PERMISSION_SCHEMA_VERSION,
        extension_id=extension_id,
        implementation_version=implementation_version,
        label=label,
        description=description,
        risk_tier="high",
        baseline_floor="review",
        default_enabled=True,
        configurable=True,
        fixed_reason=None,
        typed_capabilities=(),
        action_classes=(),
        rule_ids=(),
        dependencies=(),
        conflicts=(),
        implied_permissions=(),
        introduced_version="2.2.0",
        deprecated=False,
        replacement_permission_id=None,
        safer_guidance=safer_guidance,
        example_command=example_command,
    )


def _validate_family_scope(permissions: tuple[CommandPermissionSpec, ...]) -> None:
    family_extensions: dict[str, str] = {}
    for permission in permissions:
        if permission.family is None:
            continue
        owner = family_extensions.setdefault(permission.family, permission.extension_id)
        if owner != permission.extension_id:
            raise ValueError(f"family {permission.family} spans extensions: {owner}, {permission.extension_id}")


def _validate_permission(permission: CommandPermissionSpec) -> None:
    if permission.schema_version != COMMAND_PERMISSION_SCHEMA_VERSION:
        raise ValueError(f"unsupported permission schema: {permission.schema_version}")
    if not _PERMISSION_ID_PATTERN.fullmatch(permission.permission_id):
        raise ValueError(f"invalid permission ID: {permission.permission_id}")
    if not permission.permission_id.startswith(f"{permission.extension_id}.permission."):
        raise ValueError(f"permission ID is outside extension namespace: {permission.permission_id}")
    if not permission.default_enabled:
        raise ValueError(f"built-in permission must preserve enabled behavior: {permission.permission_id}")
    if permission.configurable and permission.fixed_reason is not None:
        raise ValueError(f"configurable permission has fixed reason: {permission.permission_id}")
    if not permission.configurable and not permission.fixed_reason:
        raise ValueError(f"fixed permission lacks reason: {permission.permission_id}")
    if permission.configurable and not (permission.example_command or "").strip():
        raise ValueError(f"configurable permission requires an example command: {permission.permission_id}")
    if permission.example_command is not None:
        example = permission.example_command
        if not example.strip() or "\n" in example or "\r" in example or len(example) > _EXAMPLE_MAX_LENGTH:
            raise ValueError(f"invalid example command for {permission.permission_id}")
    if permission.family is not None and _FAMILY_PATTERN.fullmatch(permission.family) is None:
        raise ValueError(f"invalid family for {permission.permission_id}: {permission.family}")
    for field_name, values in (
        ("typed capability", permission.typed_capabilities),
        ("action class", permission.action_classes),
        ("rule ID", permission.rule_ids),
        ("dependency", permission.dependencies),
        ("conflict", permission.conflicts),
        ("implied permission", permission.implied_permissions),
    ):
        if len(values) != len(set(values)):
            raise ValueError(f"duplicate {field_name} in permission: {permission.permission_id}")


def _index_unique(
    index: dict[str, CommandPermissionSpec],
    values: tuple[str, ...],
    permission: CommandPermissionSpec,
    kind: str,
    *,
    normalize: bool = False,
) -> None:
    for value in values:
        key = value.strip().lower() if normalize else value
        existing = index.get(key)
        if existing is not None:
            message = f"{kind} {value} is mapped by multiple permissions: {existing.permission_id}"
            message += f", {permission.permission_id}"
            raise ValueError(message)
        index[key] = permission


def _index_first(
    index: dict[str, CommandPermissionSpec],
    values: tuple[str, ...],
    permission: CommandPermissionSpec,
    *,
    normalize: bool = False,
) -> None:
    for value in values:
        key = value.strip().lower() if normalize else value
        index.setdefault(key, permission)


def _validate_references(
    permissions: tuple[CommandPermissionSpec, ...],
    by_id: dict[str, CommandPermissionSpec],
) -> None:
    for permission in permissions:
        for kind, references in (
            ("dependency", permission.dependencies),
            ("conflict", permission.conflicts),
            ("implied permission", permission.implied_permissions),
        ):
            for reference in references:
                target = by_id.get(reference)
                if target is None:
                    raise ValueError(f"unknown {kind} {reference} for {permission.permission_id}")
                if target.extension_id != permission.extension_id:
                    raise ValueError(f"cross-extension {kind} {reference} for {permission.permission_id}")
                if target is permission:
                    raise ValueError(f"self-referential {kind} for {permission.permission_id}")
        replacement = permission.replacement_permission_id
        if replacement is not None:
            target = by_id.get(replacement)
            if target is None:
                raise ValueError(f"unknown replacement permission {replacement} for {permission.permission_id}")
            if target.extension_id != permission.extension_id:
                raise ValueError(f"cross-extension replacement {replacement} for {permission.permission_id}")
            if target is permission:
                raise ValueError(f"self-referential replacement for {permission.permission_id}")
            if target.deprecated:
                raise ValueError(f"replacement target is deprecated: {replacement}")
        if permission.deprecated != (replacement is not None):
            raise ValueError(f"deprecated permission replacement mismatch: {permission.permission_id}")


def _validate_dependency_cycles(
    permissions: tuple[CommandPermissionSpec, ...],
    by_id: dict[str, CommandPermissionSpec],
) -> None:
    visited: set[str] = set()
    visiting: set[str] = set()

    def visit(permission_id: str) -> None:
        if permission_id in visiting:
            raise ValueError(f"permission relationship cycle at {permission_id}")
        if permission_id in visited:
            return
        visiting.add(permission_id)
        permission = by_id[permission_id]
        related = (*permission.dependencies, *permission.implied_permissions)
        if permission.replacement_permission_id is not None:
            related = (*related, permission.replacement_permission_id)
        for relationship in related:
            visit(relationship)
        visiting.remove(permission_id)
        visited.add(permission_id)

    for permission in permissions:
        visit(permission.permission_id)
