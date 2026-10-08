"""Strict packaged-resource loader for generated command catalog metadata."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from importlib import resources
from typing import cast

from ..native_command_control_binding import _metadata_from_bytes
from .extension_control_limits import MAX_CATALOG_EXTENSIONS, MAX_CATALOG_PAYLOAD_BYTES, MAX_PERMISSIONS_PER_EXTENSION
from .generated_command_catalog import (
    CommandRuleMode,
    GeneratedCommandCatalog,
    GeneratedCommandExtension,
    GeneratedCommandPermission,
    GeneratedCommandRule,
    GeneratedCommandSafeVariant,
    immutable_mapping,
)

_COMMAND_RULE_MODES = frozenset({"required", "enforce", "review", "monitor", "disabled"})

_CATALOG_RESOURCE = "contracts/data/extensions/command-catalog.v1.json"
_PROGRAM_RESOURCE = "contracts/data/extensions/native-command-program.v1.json"
_CATALOG_SCHEMA = "guard.command-catalog.v1"
_ENVELOPE_FIELDS = frozenset(
    {"schema", "catalog", "catalog_digest", "program_digest", "source_digest", "implementation_digest"}
)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_EXTENSION_ID = re.compile(r"command\.[a-z0-9]+(?:[.-][a-z0-9]+)*")


class GeneratedCommandCatalogError(RuntimeError):
    """The packaged generated catalog is absent, stale, or malformed."""


def _no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GeneratedCommandCatalogError("generated_command_catalog_duplicate_key")
        result[key] = value
    return result


def _decode(content: bytes, *, maximum: int) -> object:
    if not content or len(content) > maximum:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    try:
        return json.loads(content, object_pairs_hook=_no_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid") from error


def _mapping(value: object, fields: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    return value


def _string(value: object, *, maximum: int = 4_096) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    return value


def _optional_string(value: object, *, maximum: int = 4_096) -> str | None:
    return None if value is None else _string(value, maximum=maximum)


def _strings(value: object, *, maximum: int = 2_048) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    result = tuple(_string(item) for item in value)
    if len(set(result)) != len(result):
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    return result


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    return cast(bool, value)


def _integer(value: object, expected: int | None = None) -> int:
    if type(value) is not int or value < 0 or (expected is not None and value != expected):
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    return cast(int, value)


def _digest(value: object) -> str:
    result = _string(value, maximum=64)
    if _DIGEST.fullmatch(result) is None:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    return result


_SAFE_VARIANT_FIELDS = frozenset({"variant_id", "title", "matcher_kind", "matcher_contract_digest"})
_RULE_FIELDS = frozenset(
    {
        "rule_id",
        "rule_version",
        "title",
        "description",
        "severity",
        "default_mode",
        "action_classes",
        "risk_classes",
        "safer_alternatives",
        "compatibility_fallback",
        "matcher_kind",
        "matcher_contract_digest",
        "safe_variants",
        "family",
    }
)
_PERMISSION_FIELDS = frozenset(
    {
        "permission_id",
        "schema_version",
        "extension_id",
        "implementation_version",
        "label",
        "description",
        "risk_tier",
        "baseline_floor",
        "default_enabled",
        "configurable",
        "fixed_reason",
        "typed_capabilities",
        "action_classes",
        "rule_ids",
        "dependencies",
        "conflicts",
        "implied_permissions",
        "introduced_version",
        "deprecated",
        "replacement_permission_id",
        "safer_guidance",
        "example_command",
        "family",
    }
)
_EXTENSION_FIELDS = frozenset(
    {
        "schema_version",
        "extension_id",
        "version",
        "name",
        "description",
        "required",
        "source",
        "aliases",
        "dependencies",
        "conflicts",
        "delegated_protection",
        "ecosystem_ids",
        "executables",
        "project_markers",
        "reference_urls",
        "action_classes",
        "risk_classes",
        "safer_alternatives",
        "rule_count",
        "rules",
        "permission_count",
        "permissions",
        "activation",
        "enabled",
        "trust_class",
        "icon",
        "publisher",
    }
)
_MCP_EXTENSION_FIELDS = _EXTENSION_FIELDS | {"surface", "mcp_launch", "mcp_tools"}


def _safe_variant(value: object) -> GeneratedCommandSafeVariant:
    raw = _mapping(value, _SAFE_VARIANT_FIELDS)
    return GeneratedCommandSafeVariant(
        _string(raw["variant_id"]),
        _string(raw["title"]),
        _string(raw["matcher_kind"]),
        _digest(raw["matcher_contract_digest"]),
    )


def _rule(value: object, extension_id: str) -> GeneratedCommandRule:
    raw = _mapping(value, _RULE_FIELDS)
    rule_id = _string(raw["rule_id"], maximum=256)
    if not rule_id.startswith(f"{extension_id}.") or _EXTENSION_ID.fullmatch(rule_id) is None:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    variants = raw["safe_variants"]
    if not isinstance(variants, list) or len(variants) > 64:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    default_mode = _string(raw["default_mode"], maximum=32)
    if default_mode not in _COMMAND_RULE_MODES:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    return GeneratedCommandRule(
        rule_id,
        _string(raw["rule_version"], maximum=64),
        _string(raw["title"]),
        _string(raw["description"]),
        _string(raw["severity"], maximum=32),
        cast(CommandRuleMode, default_mode),
        _strings(raw["action_classes"]),
        _strings(raw["risk_classes"]),
        _strings(raw["safer_alternatives"]),
        _boolean(raw["compatibility_fallback"]),
        _string(raw["matcher_kind"], maximum=64),
        _digest(raw["matcher_contract_digest"]),
        tuple(_safe_variant(item) for item in variants),
        _optional_string(raw["family"], maximum=128),
    )


def _permission(value: object, extension_id: str) -> GeneratedCommandPermission:
    raw = _mapping(value, _PERMISSION_FIELDS)
    permission_id = _string(raw["permission_id"], maximum=256)
    if raw["extension_id"] != extension_id or not permission_id.startswith(f"{extension_id}.permission."):
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    return GeneratedCommandPermission(
        permission_id,
        _integer(raw["schema_version"], 1),
        extension_id,
        _string(raw["implementation_version"], maximum=64),
        _string(raw["label"]),
        _string(raw["description"]),
        _string(raw["risk_tier"], maximum=32),
        _string(raw["baseline_floor"], maximum=32),
        _boolean(raw["default_enabled"]),
        _boolean(raw["configurable"]),
        _optional_string(raw["fixed_reason"]),
        _strings(raw["typed_capabilities"]),
        _strings(raw["action_classes"]),
        _strings(raw["rule_ids"]),
        _strings(raw["dependencies"]),
        _strings(raw["conflicts"]),
        _strings(raw["implied_permissions"]),
        _string(raw["introduced_version"], maximum=64),
        _boolean(raw["deprecated"]),
        _optional_string(raw["replacement_permission_id"], maximum=256),
        _strings(raw["safer_guidance"]),
        _optional_string(raw["example_command"]),
        _optional_string(raw["family"], maximum=128),
    )


def _extension(value: object) -> GeneratedCommandExtension:
    if not isinstance(value, dict) or set(value) not in (_EXTENSION_FIELDS, _MCP_EXTENSION_FIELDS):
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    raw = value
    extension_id = _string(raw["extension_id"], maximum=256)
    if _EXTENSION_ID.fullmatch(extension_id) is None:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    raw_rules = raw["rules"]
    raw_permissions = raw["permissions"]
    if not isinstance(raw_rules, list) or not isinstance(raw_permissions, list):
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    rules = tuple(_rule(item, extension_id) for item in raw_rules)
    permissions = tuple(_permission(item, extension_id) for item in raw_permissions)
    if (
        _integer(raw["rule_count"], len(rules)) != len(rules)
        or _integer(raw["permission_count"], len(permissions)) != len(permissions)
        or len(permissions) > MAX_PERMISSIONS_PER_EXTENSION
    ):
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    icon = raw["icon"]
    publisher = raw["publisher"]
    if not isinstance(icon, dict) or not isinstance(publisher, dict):
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    surface: str | None = None
    mcp_launch: Mapping[str, object] | None = None
    mcp_tools: tuple[Mapping[str, object], ...] = ()
    if set(raw) == _MCP_EXTENSION_FIELDS:
        surface = _string(raw["surface"], maximum=32)
        launch = raw["mcp_launch"]
        tools = raw["mcp_tools"]
        if surface != "mcp" or not isinstance(launch, dict) or not isinstance(tools, list) or len(tools) > 2_048:
            raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
        if any(not isinstance(item, dict) for item in tools):
            raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
        mcp_launch = immutable_mapping(launch)
        mcp_tools = tuple(immutable_mapping(item) for item in cast(list[dict[str, object]], tools))
    return GeneratedCommandExtension(
        extension_id,
        _string(raw["version"], maximum=64),
        _string(raw["name"]),
        _string(raw["description"]),
        _strings(raw["action_classes"]),
        _strings(raw["risk_classes"]),
        _strings(raw["safer_alternatives"]),
        rules,
        _boolean(raw["required"]),
        _string(raw["source"], maximum=32),
        _strings(raw["aliases"]),
        _strings(raw["dependencies"]),
        _strings(raw["conflicts"]),
        _optional_string(raw["delegated_protection"], maximum=64),
        _strings(raw["ecosystem_ids"]),
        _strings(raw["executables"]),
        _strings(raw["project_markers"]),
        _strings(raw["reference_urls"]),
        permissions,
        _integer(raw["schema_version"], 2),
        _string(raw["activation"], maximum=32),
        _boolean(raw["enabled"]),
        _string(raw["trust_class"], maximum=64),
        immutable_mapping(icon),
        immutable_mapping(publisher),
        surface,
        mcp_launch,
        mcp_tools,
    )


def load_generated_command_catalog_bytes(catalog_content: bytes, program_content: bytes) -> GeneratedCommandCatalog:
    raw = _mapping(_decode(catalog_content, maximum=MAX_CATALOG_PAYLOAD_BYTES), _ENVELOPE_FIELDS)
    if raw["schema"] != _CATALOG_SCHEMA:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    catalog = raw["catalog"]
    if not isinstance(catalog, list) or not catalog or len(catalog) > MAX_CATALOG_EXTENSIONS:
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    canonical = json.dumps(catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )
    catalog_digest = _digest(raw["catalog_digest"])
    if hashlib.sha256(canonical).hexdigest() != catalog_digest:
        raise GeneratedCommandCatalogError("generated_command_catalog_digest_mismatch")
    try:
        program = _metadata_from_bytes(program_content)
    except Exception as error:
        raise GeneratedCommandCatalogError("generated_command_program_invalid") from error
    program_digest = _digest(raw["program_digest"])
    if program.program_digest != program_digest or program.catalog_digest != catalog_digest:
        raise GeneratedCommandCatalogError("generated_command_catalog_program_mismatch")
    extensions = tuple(_extension(item) for item in catalog)
    extension_ids = [item.extension_id for item in extensions]
    if len(set(extension_ids)) != len(extension_ids):
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    rule_ids = [rule.rule_id for item in extensions for rule in item.rules]
    permission_ids = [permission.permission_id for item in extensions for permission in item.permissions]
    if len(set(rule_ids)) != len(rule_ids) or len(set(permission_ids)) != len(permission_ids):
        raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    known_extensions = set(extension_ids)
    known_rules = set(rule_ids)
    known_permissions = set(permission_ids)
    for extension in extensions:
        if not set(extension.dependencies + extension.conflicts) <= known_extensions:
            raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
        if {rule_id for permission in extension.permissions for rule_id in permission.rule_ids} != {
            rule.rule_id for rule in extension.rules
        }:
            raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
        for permission in extension.permissions:
            references = permission.dependencies + permission.conflicts + permission.implied_permissions
            if not set(references) <= known_permissions or not set(permission.rule_ids) <= known_rules:
                raise GeneratedCommandCatalogError("generated_command_catalog_invalid")
    program_raw = _decode(program_content, maximum=4 * 1024 * 1024)
    if not isinstance(program_raw, dict):
        raise GeneratedCommandCatalogError("generated_command_program_invalid")
    source_digest = _digest(raw["source_digest"])
    implementation_digest = _digest(raw["implementation_digest"])
    provenance = {
        "source_schema": "guard.command-extension-source.v1",
        "source_digest": source_digest,
        "implementation_digest": implementation_digest,
    }
    provenance_bytes = json.dumps(
        provenance, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    expected_authoring_digest = hashlib.sha256(
        b"hol-guard.native-authoring-semantics.v1\0" + provenance_bytes
    ).hexdigest()
    if program_raw.get("authoring_semantics_digest") != expected_authoring_digest:
        raise GeneratedCommandCatalogError("generated_command_catalog_provenance_mismatch")
    native_extensions = program_raw.get("extensions")
    native_rules = program_raw.get("rules")
    if not isinstance(native_extensions, list) or not isinstance(native_rules, list):
        raise GeneratedCommandCatalogError("generated_command_program_invalid")
    native_extension_ids = {item.get("extension_id") for item in native_extensions if isinstance(item, dict)}
    native_rule_by_id = {
        item.get("rule_id"): item
        for item in native_rules
        if isinstance(item, dict) and isinstance(item.get("rule_id"), str)
    }
    if native_extension_ids != known_extensions or set(native_rule_by_id) != known_rules:
        raise GeneratedCommandCatalogError("generated_command_catalog_program_ownership_mismatch")
    candidate_executables: set[str] = set()
    for extension in extensions:
        for rule in extension.rules:
            native_rule = native_rule_by_id[rule.rule_id]
            if (
                native_rule.get("extension_id") != extension.extension_id
                or (
                    native_rule.get("matcher") is not None
                    and native_rule.get("matcher") != rule.matcher_contract_digest
                )
                or (native_rule.get("matcher") is None and not rule.compatibility_fallback)
                or native_rule.get("permission_id")
                != next(
                    (
                        permission.permission_id
                        for permission in extension.permissions
                        if rule.rule_id in permission.rule_ids
                    ),
                    None,
                )
            ):
                raise GeneratedCommandCatalogError("generated_command_catalog_program_ownership_mismatch")
            names = _strings(native_rule.get("candidate_executables"))
            if any("/" in name or "\\" in name for name in names):
                raise GeneratedCommandCatalogError("generated_command_program_invalid")
            candidate_executables.update(names)
    return GeneratedCommandCatalog(
        extensions,
        catalog_digest=catalog_digest,
        program_digest=program_digest,
        source_digest=source_digest,
        implementation_digest=implementation_digest,
        candidate_executables=tuple(sorted(candidate_executables)),
    )


def load_generated_command_catalog() -> GeneratedCommandCatalog:
    """Load only release-packaged artifacts; invalid or absent resources fail closed."""

    try:
        package = resources.files("codex_plugin_scanner.guard")
        catalog_content = package.joinpath(_CATALOG_RESOURCE).read_bytes()
        program_content = package.joinpath(_PROGRAM_RESOURCE).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError) as error:
        raise GeneratedCommandCatalogError("generated_command_catalog_unavailable") from error
    return load_generated_command_catalog_bytes(catalog_content, program_content)
