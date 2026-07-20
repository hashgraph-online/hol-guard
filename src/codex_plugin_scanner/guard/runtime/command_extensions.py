"""Versioned metadata for Guard's built-in command safety extensions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Literal, final

from .command_builtin_extension_registry import BUILT_IN_COMMAND_EXTENSION_VALUES
from .command_builtin_rules import COMMAND_ACTION_RISK_CLASSES
from .command_extension_observations import CommandExtensionObservation, observe_command_extensions
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_permission_catalog import (
    CommandPermissionCatalog,
    CommandPermissionSpec,
    delegated_permission,
    permissions_for_action_classes,
    permissions_for_rules,
)
from .command_rules import CommandSafetyRule, matcher_index_hints

COMMAND_EXTENSION_SCHEMA_VERSION = 2
_VERSION_PATTERN = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_EXTENSION_ID_PATTERN = re.compile(r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")

CommandExtensionSource = Literal["built-in", "local-admin", "signed-cloud"]
CommandExtensionDelegate = Literal["package-firewall"]
_VALID_EXTENSION_SOURCES = frozenset({"built-in", "local-admin", "signed-cloud"})
_VALID_EXTENSION_DELEGATES = frozenset({"package-firewall"})


def risk_classes_for_command_action(action_class: str) -> tuple[str, ...]:
    """Return the existing runtime risk classes for a command action class."""

    return COMMAND_ACTION_RISK_CLASSES.get(action_class.strip().lower(), ())


@dataclass(frozen=True, slots=True)
class CommandSafetyExtension:
    """An inspectable capability boundary over existing command detection."""

    extension_id: str
    version: str
    name: str
    description: str
    action_classes: tuple[str, ...]
    risk_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]
    rules: tuple[CommandSafetyRule, ...] = ()
    required: bool = False
    source: CommandExtensionSource = "built-in"
    aliases: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    delegated_protection: CommandExtensionDelegate | None = None
    ecosystem_ids: tuple[str, ...] = ()
    executables: tuple[str, ...] = ()
    project_markers: tuple[str, ...] = ()
    reference_urls: tuple[str, ...] = ()
    permissions: tuple[CommandPermissionSpec, ...] = ()

    def __post_init__(self) -> None:
        if self.permissions:
            return
        if self.rules:
            permissions = permissions_for_rules(
                self.extension_id,
                self.version,
                self.rules,
                configurable=not self.required,
            )
        elif self.delegated_protection is not None:
            permissions = (
                delegated_permission(
                    self.extension_id,
                    self.version,
                    self.name,
                    self.description,
                    self.safer_alternatives,
                ),
            )
        else:
            permissions = permissions_for_action_classes(
                self.extension_id,
                self.version,
                self.action_classes,
                self.safer_alternatives,
                configurable=not self.required,
            )
        object.__setattr__(self, "permissions", permissions)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
            "extension_id": self.extension_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "enabled": True,
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
        }


@final
class CommandSafetyExtensionRegistry:
    """Validated, deterministic registry of command safety extensions."""

    def __init__(self, extensions: tuple[CommandSafetyExtension, ...]) -> None:
        ordered = tuple(sorted(extensions, key=lambda extension: extension.extension_id))
        by_id: dict[str, CommandSafetyExtension] = {}
        by_action_class: dict[str, CommandSafetyExtension] = {}
        by_action_rule: dict[str, CommandSafetyRule] = {}
        by_rule_id: dict[str, CommandSafetyRule] = {}
        aliases: dict[str, str] = {}
        rule_records: list[tuple[CommandSafetyExtension, CommandSafetyRule]] = []
        executable_index: dict[str, set[str]] = {}
        keyword_index: dict[str, set[str]] = {}
        unindexed_rule_ids: set[str] = set()
        for extension in ordered:
            _validate_extension(extension)
            if extension.extension_id in by_id:
                raise ValueError(f"Duplicate command safety extension ID: {extension.extension_id}")
            by_id[extension.extension_id] = extension
            for alias in extension.aliases:
                if alias in by_id or alias in aliases:
                    raise ValueError(f"Duplicate command safety extension alias: {alias}")
                aliases[alias] = extension.extension_id
            for action_class in extension.action_classes:
                normalized_action_class = action_class.strip().lower()
                owner = by_action_class.get(normalized_action_class)
                if owner is not None:
                    ownership = f"{owner.extension_id} and {extension.extension_id}"
                    raise ValueError(f"Command action class {action_class!r} is owned by both {ownership}")
                by_action_class[normalized_action_class] = extension
                undeclared_risk_classes = set(risk_classes_for_command_action(action_class)).difference(
                    extension.risk_classes
                )
                if undeclared_risk_classes:
                    undeclared = ", ".join(sorted(undeclared_risk_classes))
                    message = " ".join(
                        (
                            f"Command safety extension {extension.extension_id} does not declare runtime",
                            f"risk classes for {action_class!r}: {undeclared}",
                        )
                    )
                    raise ValueError(message)
            for rule in extension.rules:
                if not rule.rule_id.startswith(f"{extension.extension_id}."):
                    raise ValueError(
                        f"Command safety rule {rule.rule_id} must use extension prefix {extension.extension_id}"
                    )
                if rule.rule_id in by_rule_id:
                    raise ValueError(f"Duplicate command safety rule ID: {rule.rule_id}")
                undeclared_rule_risks = set(rule.risk_classes).difference(extension.risk_classes)
                if undeclared_rule_risks:
                    undeclared = ", ".join(sorted(undeclared_rule_risks))
                    raise ValueError(
                        f"Command safety rule {rule.rule_id} declares risks outside its extension: {undeclared}"
                    )
                by_rule_id[rule.rule_id] = rule
                rule_records.append((extension, rule))
                if rule.matcher is not None:
                    hints = matcher_index_hints(rule.matcher)
                    if not hints.complete or (not hints.executables and not hints.keywords):
                        unindexed_rule_ids.add(rule.rule_id)
                    for executable in hints.executables:
                        executable_index.setdefault(executable, set()).add(rule.rule_id)
                    for keyword in hints.keywords:
                        keyword_index.setdefault(keyword, set()).add(rule.rule_id)
                for action_class in rule.action_classes:
                    normalized_action_class = action_class.strip().lower()
                    if normalized_action_class not in {item.strip().lower() for item in extension.action_classes}:
                        raise ValueError(
                            f"Command safety rule {rule.rule_id} owns undeclared action class {action_class!r}"
                        )
                    if rule.compatibility_fallback:
                        _ = by_action_rule.setdefault(normalized_action_class, rule)
            if extension.rules:
                rule_actions = {
                    action_class.strip().lower() for rule in extension.rules for action_class in rule.action_classes
                }
                extension_actions = {action_class.strip().lower() for action_class in extension.action_classes}
                if rule_actions != extension_actions:
                    raise ValueError(
                        f"Command safety extension {extension.extension_id} rules must own every action class"
                    )
        _validate_registry_relationships(ordered, by_id=by_id, aliases=aliases)
        permissions = tuple(permission for extension in ordered for permission in extension.permissions)
        permission_catalog = CommandPermissionCatalog(permissions)
        for extension in ordered:
            extension_permissions = tuple(
                permission
                for permission in permission_catalog.permissions
                if permission.extension_id == extension.extension_id
            )
            if extension_permissions != tuple(sorted(extension.permissions, key=lambda item: item.permission_id)):
                raise ValueError(f"Permission catalog ownership mismatch for {extension.extension_id}")
            permission_rule_ids = {rule_id for permission in extension.permissions for rule_id in permission.rule_ids}
            if permission_rule_ids != {rule.rule_id for rule in extension.rules}:
                raise ValueError(f"Permission catalog must map every rule for {extension.extension_id}")
            permission_action_classes = {
                action_class for permission in extension.permissions for action_class in permission.action_classes
            }
            if permission_action_classes != set(extension.action_classes):
                raise ValueError(f"Permission catalog must map every action class for {extension.extension_id}")
        catalog_payload = json.dumps(
            [extension.to_dict() for extension in ordered],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        catalog_digest = hashlib.sha256(catalog_payload).hexdigest()
        self._extensions = ordered
        self._by_id = MappingProxyType(by_id)
        self._aliases = MappingProxyType(aliases)
        self._by_action_class = MappingProxyType(by_action_class)
        self._by_action_rule = MappingProxyType(by_action_rule)
        self._by_rule_id = MappingProxyType(by_rule_id)
        self._rule_records = tuple(rule_records)
        self._executable_index = MappingProxyType({key: frozenset(value) for key, value in executable_index.items()})
        self._keyword_index = MappingProxyType({key: frozenset(value) for key, value in keyword_index.items()})
        self._unindexed_rule_ids = frozenset(unindexed_rule_ids)
        self._permission_catalog = permission_catalog
        self._catalog_digest = catalog_digest

    @property
    def extensions(self) -> tuple[CommandSafetyExtension, ...]:
        return self._extensions

    @property
    def permissions(self) -> tuple[CommandPermissionSpec, ...]:
        return self._permission_catalog.permissions

    @property
    def catalog_digest(self) -> str:
        return self._catalog_digest

    def permission(self, permission_id: str) -> CommandPermissionSpec | None:
        return self._permission_catalog.get(permission_id.strip().lower())

    def permission_for_rule_id(self, rule_id: str) -> CommandPermissionSpec | None:
        return self._permission_catalog.for_rule_id(rule_id.strip().lower())

    def permission_for_action_class(self, action_class: str) -> CommandPermissionSpec | None:
        return self._permission_catalog.for_action_class(action_class)

    def permission_for_typed_capability(self, capability: str) -> CommandPermissionSpec | None:
        return self._permission_catalog.for_typed_capability(capability.strip().lower())

    def get(self, extension_id: str) -> CommandSafetyExtension | None:
        normalized = extension_id.strip().lower()
        return self._by_id.get(self._aliases.get(normalized, normalized))

    def for_action_class(self, action_class: str) -> CommandSafetyExtension | None:
        return self._by_action_class.get(action_class.strip().lower())

    def get_rule(self, rule_id: str) -> CommandSafetyRule | None:
        return self._by_rule_id.get(rule_id.strip().lower())

    def rule_for_action_class(self, action_class: str) -> CommandSafetyRule | None:
        return self._by_action_rule.get(action_class.strip().lower())

    def candidate_rule_ids(self, command: CanonicalCommand) -> tuple[str, ...]:
        """Return deterministic rule candidates from conservative registry indexes."""

        candidate_rule_ids = set(self._unindexed_rule_ids)
        command_executables = {
            segment.executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
            for segment in command.segments
            if segment.executable is not None
        }
        command_keywords = {token.lower() for segment in command.segments for token in segment.tokens}
        for executable in command_executables:
            candidate_rule_ids.update(self._executable_index.get(executable, ()))
        for keyword in command_keywords:
            candidate_rule_ids.update(self._keyword_index.get(keyword, ()))
        return tuple(rule.rule_id for _extension, rule in self._rule_records if rule.rule_id in candidate_rule_ids)

    def matching_rules(
        self,
        command: CanonicalCommand,
    ) -> tuple[tuple[CommandSafetyExtension, CommandSafetyRule, tuple[MatcherEvidence, ...]], ...]:
        """Return the effective compatibility projection of lossless observations."""

        observations = self.observations(command)
        if any(item.uncertainty_reasons for item in observations):
            raise RuntimeError("command extension matcher boundary failure")
        return tuple(
            (item.extension, item.rule, item.effective_evidence) for item in observations if item.effective_evidence
        )

    def observations(
        self,
        command: CanonicalCommand,
    ) -> tuple[CommandExtensionObservation[CommandSafetyExtension], ...]:
        """Return lossless base, safe-variant, and uncertainty evidence."""

        return observe_command_extensions(command, self.extensions, self.candidate_rule_ids(command))


def _validate_extension(extension: CommandSafetyExtension) -> None:
    if not _EXTENSION_ID_PATTERN.fullmatch(extension.extension_id):
        raise ValueError("Command safety extension IDs must be lowercase and start with 'command.'")
    if not _VERSION_PATTERN.fullmatch(extension.version):
        raise ValueError(f"Invalid command safety extension version: {extension.version}")
    if not extension.name.strip() or not extension.description.strip():
        raise ValueError(f"Command safety extension {extension.extension_id} requires a name and description")
    if not extension.action_classes and not extension.rules and extension.delegated_protection is None:
        raise ValueError(
            f"Command safety extension {extension.extension_id} must own an action class, rule, or delegated protection"
        )
    if len(set(extension.action_classes)) != len(extension.action_classes):
        raise ValueError(f"Command safety extension {extension.extension_id} has duplicate action classes")
    if not extension.risk_classes:
        raise ValueError(f"Command safety extension {extension.extension_id} must declare a risk class")
    if len(set(extension.risk_classes)) != len(extension.risk_classes):
        raise ValueError(f"Command safety extension {extension.extension_id} has duplicate risk classes")
    if not extension.safer_alternatives:
        raise ValueError(f"Command safety extension {extension.extension_id} requires safer alternatives")
    if extension.source not in _VALID_EXTENSION_SOURCES:
        raise ValueError(f"Command safety extension {extension.extension_id} has invalid source")
    if extension.delegated_protection is not None:
        if extension.delegated_protection not in _VALID_EXTENSION_DELEGATES:
            raise ValueError(f"Command safety extension {extension.extension_id} has invalid delegated protection")
        if extension.action_classes or extension.rules:
            raise ValueError(f"Delegated command safety extension {extension.extension_id} cannot own command rules")
    if extension.required and extension.source != "built-in":
        raise ValueError(f"Required command safety extension {extension.extension_id} must be built-in")
    for field_name, values in (
        ("aliases", extension.aliases),
        ("dependencies", extension.dependencies),
        ("conflicts", extension.conflicts),
    ):
        if len(set(values)) != len(values) or any(not _EXTENSION_ID_PATTERN.fullmatch(value) for value in values):
            raise ValueError(f"Command safety extension {extension.extension_id} has invalid {field_name}")
    for field_name, values in (
        ("ecosystem IDs", extension.ecosystem_ids),
        ("executables", extension.executables),
        ("project markers", extension.project_markers),
        ("reference URLs", extension.reference_urls),
    ):
        if len(set(values)) != len(values) or any(not value or value != value.strip() for value in values):
            raise ValueError(f"Command safety extension {extension.extension_id} has invalid {field_name}")
    if extension.delegated_protection is not None and (not extension.ecosystem_ids or not extension.executables):
        raise ValueError(
            f"Delegated command safety extension {extension.extension_id} requires ecosystem and executable metadata"
        )
    if extension.delegated_protection is not None and (
        not extension.reference_urls or any(not value.startswith("https://") for value in extension.reference_urls)
    ):
        raise ValueError(f"Delegated command safety extension {extension.extension_id} requires HTTPS references")
    if any("/" in value or "\\" in value for value in extension.executables):
        raise ValueError(f"Command safety extension {extension.extension_id} executable metadata must use basenames")
    if any(not _safe_project_marker(value) for value in extension.project_markers):
        raise ValueError(f"Command safety extension {extension.extension_id} has unsafe project marker metadata")


def _safe_project_marker(value: str) -> bool:
    marker = PurePosixPath(value)
    return not marker.is_absolute() and ".." not in marker.parts and "\\" not in value


def _validate_registry_relationships(
    extensions: tuple[CommandSafetyExtension, ...],
    *,
    by_id: dict[str, CommandSafetyExtension],
    aliases: dict[str, str],
) -> None:
    for alias in aliases:
        if alias in by_id:
            raise ValueError(f"Command safety extension alias shadows an extension ID: {alias}")
    for extension in extensions:
        for dependency in extension.dependencies:
            if dependency not in by_id:
                raise ValueError(
                    f"Command safety extension {extension.extension_id} has unknown dependency {dependency}"
                )
        for conflict in extension.conflicts:
            if conflict not in by_id:
                raise ValueError(f"Command safety extension {extension.extension_id} has unknown conflict {conflict}")
            raise ValueError(f"Command safety extension {extension.extension_id} conflicts with {conflict}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(extension_id: str) -> None:
        if extension_id in visiting:
            raise ValueError(f"Command safety extension dependency cycle includes {extension_id}")
        if extension_id in visited:
            return
        visiting.add(extension_id)
        for dependency in by_id[extension_id].dependencies:
            visit(dependency)
        visiting.remove(extension_id)
        visited.add(extension_id)

    for extension in extensions:
        visit(extension.extension_id)


_BUILT_IN_EXTENSIONS = tuple(CommandSafetyExtension(**values) for values in BUILT_IN_COMMAND_EXTENSION_VALUES)

BUILT_IN_COMMAND_EXTENSION_REGISTRY = CommandSafetyExtensionRegistry(_BUILT_IN_EXTENSIONS)
