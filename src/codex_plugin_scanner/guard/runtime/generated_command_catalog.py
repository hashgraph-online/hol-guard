"""Immutable metadata projected from the native command catalog artifact."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Literal, final

from .extension_control_limits import MAX_CATALOG_EXTENSIONS, MAX_PERMISSIONS_PER_EXTENSION

CommandRuleMode = Literal["required", "enforce", "review", "monitor", "disabled"]


@dataclass(frozen=True, slots=True)
class GeneratedCommandSafeVariant:
    variant_id: str
    title: str
    matcher_kind: str
    matcher_contract_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "variant_id": self.variant_id,
            "title": self.title,
            "matcher_kind": self.matcher_kind,
            "matcher_contract_digest": self.matcher_contract_digest,
        }


@dataclass(frozen=True, slots=True)
class GeneratedCommandRule:
    rule_id: str
    rule_version: str
    title: str
    description: str
    severity: str
    default_mode: CommandRuleMode
    action_classes: tuple[str, ...]
    risk_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]
    compatibility_fallback: bool
    matcher_kind: str
    matcher_contract_digest: str
    safe_variants: tuple[GeneratedCommandSafeVariant, ...]
    family: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "default_mode": self.default_mode,
            "action_classes": list(self.action_classes),
            "risk_classes": list(self.risk_classes),
            "safer_alternatives": list(self.safer_alternatives),
            "compatibility_fallback": self.compatibility_fallback,
            "matcher_kind": self.matcher_kind,
            "matcher_contract_digest": self.matcher_contract_digest,
            "safe_variants": [item.to_dict() for item in self.safe_variants],
            "family": self.family,
        }


@dataclass(frozen=True, slots=True)
class GeneratedCommandPermission:
    permission_id: str
    schema_version: int
    extension_id: str
    implementation_version: str
    label: str
    description: str
    risk_tier: str
    baseline_floor: str
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
    example_command: str | None
    family: str | None

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


@dataclass(frozen=True, slots=True)
class GeneratedCommandExtension:
    extension_id: str
    version: str
    name: str
    description: str
    action_classes: tuple[str, ...]
    risk_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]
    rules: tuple[GeneratedCommandRule, ...]
    required: bool
    source: str
    aliases: tuple[str, ...]
    dependencies: tuple[str, ...]
    conflicts: tuple[str, ...]
    delegated_protection: str | None
    ecosystem_ids: tuple[str, ...]
    executables: tuple[str, ...]
    project_markers: tuple[str, ...]
    reference_urls: tuple[str, ...]
    permissions: tuple[GeneratedCommandPermission, ...]
    schema_version: int
    activation: str
    enabled: bool
    trust_class: str
    icon: Mapping[str, object]
    publisher: Mapping[str, object]
    surface: str | None = None
    mcp_launch: Mapping[str, object] | None = None
    mcp_tools: tuple[Mapping[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "extension_id": self.extension_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "required": self.required,
            "source": self.source,
            "aliases": list(self.aliases),
            "dependencies": list(self.dependencies),
            "conflicts": list(self.conflicts),
            "delegated_protection": self.delegated_protection,
            "ecosystem_ids": list(self.ecosystem_ids),
            "executables": list(self.executables),
            "project_markers": list(self.project_markers),
            "reference_urls": list(self.reference_urls),
            "action_classes": list(self.action_classes),
            "risk_classes": list(self.risk_classes),
            "safer_alternatives": list(self.safer_alternatives),
            "rule_count": len(self.rules),
            "rules": [rule.to_dict() for rule in self.rules],
            "permission_count": len(self.permissions),
            "permissions": [permission.to_dict() for permission in self.permissions],
            "activation": self.activation,
            "enabled": self.enabled,
            "trust_class": self.trust_class,
            "icon": thaw_metadata(self.icon),
            "publisher": thaw_metadata(self.publisher),
        }
        if self.surface is not None:
            payload["surface"] = self.surface
        if self.mcp_launch is not None:
            payload["mcp_launch"] = thaw_metadata(self.mcp_launch)
            payload["mcp_tools"] = [thaw_metadata(item) for item in self.mcp_tools]
        return payload


def _validate_generated_extension(extension: GeneratedCommandExtension) -> None:
    if len(extension.permissions) > MAX_PERMISSIONS_PER_EXTENSION:
        raise ValueError(f"Generated command extension {extension.extension_id} exceeds permission limit")
    if extension.delegated_protection is not None:
        if extension.action_classes or extension.rules:
            raise ValueError(f"Delegated command safety extension {extension.extension_id} cannot own command rules")
        if not extension.ecosystem_ids or not extension.executables:
            raise ValueError(
                f"Delegated command safety extension {extension.extension_id} "
                "requires ecosystem and executable metadata"
            )
        if not extension.reference_urls or any(not value.startswith("https://") for value in extension.reference_urls):
            raise ValueError(f"Delegated command safety extension {extension.extension_id} requires HTTPS references")
    if any("/" in value or "\\" in value for value in extension.executables):
        raise ValueError(f"Command safety extension {extension.extension_id} executable metadata must use basenames")
    if any(
        PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts or "\\" in value
        for value in extension.project_markers
    ):
        raise ValueError(f"Command safety extension {extension.extension_id} has unsafe project marker metadata")


@final
class GeneratedCommandCatalog:
    """Read-only catalog metadata and deterministic relationship indexes."""

    def __init__(
        self,
        extensions: tuple[GeneratedCommandExtension, ...],
        *,
        catalog_digest: str | None = None,
        program_digest: str | None = None,
        source_digest: str | None = None,
        implementation_digest: str | None = None,
        candidate_executables: tuple[str, ...] = (),
    ) -> None:
        ordered = tuple(sorted(extensions, key=lambda item: item.extension_id))
        if len(ordered) > MAX_CATALOG_EXTENSIONS:
            raise ValueError("Generated command catalog exceeds catalog extension limit")
        for item in ordered:
            _validate_generated_extension(item)
        by_id = {item.extension_id: item for item in ordered}
        if len(by_id) != len(ordered):
            raise ValueError("Duplicate command safety extension ID")
        action_owners: dict[str, GeneratedCommandExtension] = {}
        for item in ordered:
            for action in item.action_classes:
                normalized = action.strip().lower()
                if normalized in action_owners:
                    raise ValueError(f"Duplicate command action class: {normalized}")
                action_owners[normalized] = item
        aliases = {alias: item.extension_id for item in ordered for alias in item.aliases}
        rules = {rule.rule_id: rule for item in ordered for rule in item.rules}
        permissions = {permission.permission_id: permission for item in ordered for permission in item.permissions}
        if len(permissions) != sum(len(item.permissions) for item in ordered):
            raise ValueError("Duplicate generated command permission ID")
        self._extensions = ordered
        executable_names = set(candidate_executables)
        executable_names.update(name for item in ordered for name in item.executables)
        self._owned_executables = frozenset(name.strip().lower() for name in executable_names if name.strip())
        self._permissions = tuple(sorted(permissions.values(), key=lambda item: item.permission_id))
        self._by_id = MappingProxyType(by_id)
        self._aliases = MappingProxyType(aliases)
        self._by_rule_id = MappingProxyType(rules)
        self._by_action_class = MappingProxyType(action_owners)
        self._by_action_rule = MappingProxyType(
            {
                action.strip().lower(): rule
                for item in ordered
                for rule in item.rules
                if rule.compatibility_fallback
                for action in rule.action_classes
            }
        )
        self._by_permission_id = MappingProxyType(permissions)
        self._permission_by_rule_id = MappingProxyType(
            {rule_id.strip().lower(): permission for permission in self._permissions for rule_id in permission.rule_ids}
        )
        self._permission_by_action_class = MappingProxyType(
            {
                action.strip().lower(): permission
                for permission in reversed(self._permissions)
                for action in permission.action_classes
            }
        )
        self._permission_by_capability = MappingProxyType(
            {
                capability.strip().lower(): permission
                for permission in self._permissions
                for capability in permission.typed_capabilities
            }
        )
        if catalog_digest is None:
            canonical = json.dumps(
                [item.to_dict() for item in ordered],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            catalog_digest = hashlib.sha256(canonical).hexdigest()
        self.catalog_digest = catalog_digest
        self.program_digest = program_digest
        self.source_digest = source_digest
        self.implementation_digest = implementation_digest

    @property
    def extensions(self) -> tuple[GeneratedCommandExtension, ...]:
        return self._extensions

    @property
    def permissions(self) -> tuple[GeneratedCommandPermission, ...]:
        return self._permissions

    @property
    def owned_executables(self) -> frozenset[str]:
        """Executable ownership metadata; command matching remains native."""

        return self._owned_executables

    def get(self, extension_id: str) -> GeneratedCommandExtension | None:
        normalized = extension_id.strip().lower()
        return self._by_id.get(self._aliases.get(normalized, normalized))

    def for_action_class(self, action_class: str) -> GeneratedCommandExtension | None:
        return self._by_action_class.get(action_class.strip().lower())

    def get_rule(self, rule_id: str) -> GeneratedCommandRule | None:
        return self._by_rule_id.get(rule_id.strip().lower())

    def rule_for_action_class(self, action_class: str) -> GeneratedCommandRule | None:
        return self._by_action_rule.get(action_class.strip().lower())

    def permission(self, permission_id: str) -> GeneratedCommandPermission | None:
        return self._by_permission_id.get(permission_id.strip().lower())

    def permission_for_rule_id(self, rule_id: str) -> GeneratedCommandPermission | None:
        return self._permission_by_rule_id.get(rule_id.strip().lower())

    def permission_for_action_class(self, action_class: str) -> GeneratedCommandPermission | None:
        return self._permission_by_action_class.get(action_class.strip().lower())

    def permission_for_typed_capability(self, capability: str) -> GeneratedCommandPermission | None:
        return self._permission_by_capability.get(capability.strip().lower())


def immutable_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType({key: freeze_metadata(item) for key, item in value.items()})


def freeze_metadata(value: object) -> object:
    if isinstance(value, Mapping):
        return immutable_mapping(value)
    if isinstance(value, list | tuple):
        return tuple(freeze_metadata(item) for item in value)
    return value


def thaw_metadata(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: thaw_metadata(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_metadata(item) for item in value]
    return value
