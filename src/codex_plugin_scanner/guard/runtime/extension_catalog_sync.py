"""Privacy-safe Local-to-Cloud Extension catalog wire projection."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Protocol, TypedDict

from .extension_control_limits import (
    MAX_CATALOG_EXTENSIONS,
    MAX_CATALOG_PAYLOAD_BYTES,
    MAX_INPUT_TEXT_LENGTH,
    MAX_PERMISSIONS_PER_EXTENSION,
)

EXTENSION_CATALOG_SCHEMA_VERSION = "guard.extension-catalog.v1"
EXTENSION_CONTROL_WIRE_SCHEMA_VERSION = "guard.extension-controls.v1"
MANAGED_CONTROLS_RUNTIME_CAPABILITIES = (
    "extension-catalog.v1",
    "extension-control-layer.v1",
    "policy-extension-targets.v1",
    "managed-controls-atomic-apply.v1",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WIRE_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_EXTENSION_ID_PATTERN = re.compile(r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_PERMISSION_ID_PATTERN = re.compile(r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_FORBIDDEN_WIRE_KEYS = frozenset(
    {
        "actionclasses",
        "commandhistory",
        "description",
        "environment",
        "examplecommand",
        "filecontents",
        "projectmarkers",
        "referenceurls",
        "ruleids",
        "rules",
        "saferalternatives",
        "secrets",
        "sourcepath",
        "workingdirectory",
    }
)


class ExtensionCatalogPermissionWire(TypedDict):
    id: str
    name: str
    configurable: bool
    required: bool
    riskClasses: list[str]
    typedCapabilities: list[str]


class ExtensionCatalogEntryWire(TypedDict):
    id: str
    version: str
    name: str
    source: str
    executables: list[str]
    ecosystemIds: list[str]
    riskClasses: list[str]
    delegatedProtection: str | None
    deprecated: bool
    replacementId: str | None
    permissions: list[ExtensionCatalogPermissionWire]


class ExtensionCatalogWire(TypedDict):
    schemaVersion: str
    catalogDigest: str
    guardVersion: str
    controlSchemaVersion: str
    generatedAt: str
    limits: dict[str, int]
    extensions: list[ExtensionCatalogEntryWire]


class ManagedControlsRuntimePostureWire(TypedDict):
    extensionCatalogDigest: str
    extensionControlSchemaVersions: list[str]
    extensionAuthorityRevision: int | None
    effectiveProjectionDigest: str | None
    managedControlsCapabilities: list[str]


class PermissionLike(Protocol):
    @property
    def permission_id(self) -> str: ...

    @property
    def label(self) -> str: ...

    @property
    def configurable(self) -> bool: ...

    @property
    def risk_tier(self) -> str: ...

    @property
    def typed_capabilities(self) -> tuple[str, ...]: ...


class ExtensionLike(Protocol):
    @property
    def extension_id(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def name(self) -> str: ...

    @property
    def source(self) -> str: ...

    @property
    def executables(self) -> tuple[str, ...]: ...

    @property
    def ecosystem_ids(self) -> tuple[str, ...]: ...

    @property
    def risk_classes(self) -> tuple[str, ...]: ...

    @property
    def delegated_protection(self) -> str | None: ...

    @property
    def permissions(self) -> tuple[PermissionLike, ...]: ...


class RegistryLike(Protocol):
    @property
    def extensions(self) -> tuple[ExtensionLike, ...]: ...


def _code_unit_sorted(values: Iterable[str]) -> list[str]:
    return sorted(set(values))


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _permission_wire(permission: PermissionLike) -> ExtensionCatalogPermissionWire:
    return {
        "id": permission.permission_id,
        "name": permission.label,
        "configurable": permission.configurable,
        "required": not permission.configurable,
        "riskClasses": [permission.risk_tier],
        "typedCapabilities": _code_unit_sorted(permission.typed_capabilities),
    }


def _extension_wire(extension: ExtensionLike) -> ExtensionCatalogEntryWire:
    permissions = sorted(
        (_permission_wire(permission) for permission in extension.permissions),
        key=lambda permission: permission["id"],
    )
    if len(permissions) > MAX_PERMISSIONS_PER_EXTENSION:
        raise ValueError("Extension catalog permission limit exceeded")
    return {
        "id": extension.extension_id,
        "version": extension.version,
        "name": extension.name,
        "source": extension.source,
        "executables": _code_unit_sorted(extension.executables),
        "ecosystemIds": _code_unit_sorted(extension.ecosystem_ids),
        "riskClasses": _code_unit_sorted(extension.risk_classes),
        "delegatedProtection": extension.delegated_protection,
        "deprecated": False,
        "replacementId": None,
        "permissions": permissions,
    }


def canonical_extension_catalog_json(extensions: list[ExtensionCatalogEntryWire]) -> str:
    """Return the shared canonical JSON for an Extension projection."""

    canonical_extensions = sorted(
        (_canonical_extension(extension) for extension in extensions),
        key=_extension_wire_id,
    )
    return _canonical_json(canonical_extensions)


def _permission_wire_id(permission: ExtensionCatalogPermissionWire) -> str:
    return permission["id"]


def _extension_wire_id(extension: ExtensionCatalogEntryWire) -> str:
    return extension["id"]


def _canonical_extension(extension: ExtensionCatalogEntryWire) -> ExtensionCatalogEntryWire:
    return {
        **extension,
        "permissions": sorted(extension["permissions"], key=_permission_wire_id),
    }


def catalog_digest_for_extensions(extensions: list[ExtensionCatalogEntryWire]) -> str:
    """Return the cross-language SHA-256 digest over canonical projected Extensions."""

    return hashlib.sha256(canonical_extension_catalog_json(extensions).encode("utf-8")).hexdigest()


def _is_rfc3339_datetime(value: str) -> bool:
    if _RFC3339.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else ""))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def validate_extension_catalog_wire(payload: object) -> ExtensionCatalogWire:
    """Execute the shared catalog's bounded shape, privacy, identity, and digest contract."""

    encoded = _canonical_json(payload).encode("utf-8")
    if len(encoded) > MAX_CATALOG_PAYLOAD_BYTES:
        raise ValueError("Extension catalog payload limit exceeded")
    if not isinstance(payload, dict):
        raise ValueError("Extension catalog must be an object")
    expected_top_level = {
        "schemaVersion",
        "catalogDigest",
        "guardVersion",
        "controlSchemaVersion",
        "generatedAt",
        "limits",
        "extensions",
    }
    if set(payload) != expected_top_level:
        _reject_private_wire_keys(payload)
        raise ValueError("Extension catalog contains unknown fields")
    _reject_private_wire_keys(payload)
    if payload.get("schemaVersion") != EXTENSION_CATALOG_SCHEMA_VERSION:
        raise ValueError("Unsupported Extension catalog schema")
    catalog_digest = payload.get("catalogDigest")
    if not isinstance(catalog_digest, str) or _SHA256.fullmatch(catalog_digest) is None:
        raise ValueError("Invalid Extension catalog digest")
    guard_version = _required_catalog_string(payload, "guardVersion", maximum=128)
    control_schema_version = _required_catalog_string(payload, "controlSchemaVersion", maximum=128)
    generated_at = _required_catalog_string(payload, "generatedAt", maximum=128)
    if not _is_rfc3339_datetime(generated_at):
        raise ValueError("Invalid Extension catalog generatedAt")
    expected_limits = {
        "maxExtensions": MAX_CATALOG_EXTENSIONS,
        "maxPermissionsPerExtension": MAX_PERMISSIONS_PER_EXTENSION,
        "maxPayloadBytes": MAX_CATALOG_PAYLOAD_BYTES,
        "maxStringLength": 8_192,
    }
    if payload.get("limits") != expected_limits:
        raise ValueError("Extension catalog limits do not match runtime limits")
    raw_extensions = payload.get("extensions")
    if not isinstance(raw_extensions, list) or len(raw_extensions) > MAX_CATALOG_EXTENSIONS:
        raise ValueError("Extension catalog limit exceeded")
    parsed_extensions = [_parse_extension(item) for item in raw_extensions]
    extension_ids = _unique_ids((_extension_wire_id(item) for item in parsed_extensions), "Extension catalog")
    _unique_ids(
        (permission["id"] for extension in parsed_extensions for permission in extension["permissions"]),
        "Extension permission",
    )
    for extension in parsed_extensions:
        replacement_id = extension["replacementId"]
        if replacement_id is not None and replacement_id not in extension_ids:
            raise ValueError("Extension replacement is not present in the catalog")
    if catalog_digest_for_extensions(parsed_extensions) != catalog_digest:
        raise ValueError("Extension catalog digest does not match canonical bytes")
    return {
        "schemaVersion": EXTENSION_CATALOG_SCHEMA_VERSION,
        "catalogDigest": catalog_digest,
        "guardVersion": guard_version,
        "controlSchemaVersion": control_schema_version,
        "generatedAt": generated_at,
        "limits": expected_limits,
        "extensions": parsed_extensions,
    }


def _required_catalog_string(payload: Mapping[object, object], field: str, *, maximum: int) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"Invalid Extension catalog {field}")
    return value


def _unique_ids(values: Iterable[str], label: str) -> set[str]:
    identifiers = list(values)
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"Duplicate {label} identity")
    return set(identifiers)


def _parse_extension(value: object) -> ExtensionCatalogEntryWire:
    fields = {
        "id",
        "version",
        "name",
        "source",
        "executables",
        "ecosystemIds",
        "riskClasses",
        "delegatedProtection",
        "deprecated",
        "replacementId",
        "permissions",
    }
    if not isinstance(value, dict) or set(value) != fields:
        _reject_private_wire_keys(value)
        raise ValueError("Extension catalog entry contains unknown fields")
    extension_id = _extension_identity(value.get("id"))
    source = value.get("source")
    if not isinstance(source, str) or source not in {"built-in", "local-admin", "signed-cloud", "custom"}:
        raise ValueError("Invalid Extension catalog source")
    delegated = value.get("delegatedProtection")
    if delegated is not None and delegated != "package-firewall":
        raise ValueError("Invalid Extension delegated protection")
    deprecated = value.get("deprecated")
    if not isinstance(deprecated, bool):
        raise ValueError("Invalid Extension deprecation state")
    replacement = value.get("replacementId")
    if replacement is not None and (
        not isinstance(replacement, str)
        or _EXTENSION_ID_PATTERN.fullmatch(replacement) is None
        or replacement == extension_id
        or not deprecated
    ):
        raise ValueError("Invalid Extension replacement")
    permissions_value = value.get("permissions")
    if not isinstance(permissions_value, list) or len(permissions_value) > MAX_PERMISSIONS_PER_EXTENSION:
        raise ValueError("Extension catalog permission limit exceeded")
    permissions = [_parse_permission(item, extension_id=extension_id) for item in permissions_value]
    return {
        "id": extension_id,
        "version": _required_catalog_string(value, "version", maximum=128),
        "name": _required_catalog_string(value, "name", maximum=8_192),
        "source": source,
        "executables": _validate_bounded_string_array(value.get("executables"), label="executables"),
        "ecosystemIds": _validate_bounded_string_array(value.get("ecosystemIds"), label="ecosystemIds"),
        "riskClasses": _validate_bounded_string_array(value.get("riskClasses"), label="riskClasses"),
        "delegatedProtection": delegated,
        "deprecated": deprecated,
        "replacementId": replacement,
        "permissions": permissions,
    }


def _extension_identity(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_INPUT_TEXT_LENGTH
        or _EXTENSION_ID_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("Invalid Extension catalog identity")
    return value


def _parse_permission(value: object, *, extension_id: str) -> ExtensionCatalogPermissionWire:
    fields = {"id", "name", "configurable", "required", "riskClasses", "typedCapabilities"}
    if not isinstance(value, dict) or set(value) != fields:
        _reject_private_wire_keys(value)
        raise ValueError("Extension catalog permission contains unknown fields")
    permission_id = value.get("id")
    if (
        not isinstance(permission_id, str)
        or len(permission_id) > MAX_INPUT_TEXT_LENGTH
        or _PERMISSION_ID_PATTERN.fullmatch(permission_id) is None
        or not permission_id.startswith(f"{extension_id}.permission.")
    ):
        raise ValueError("Invalid Extension permission identity")
    configurable = value.get("configurable")
    required = value.get("required")
    if not isinstance(configurable, bool) or not isinstance(required, bool):
        raise ValueError("Invalid Extension permission state")
    return {
        "id": permission_id,
        "name": _required_catalog_string(value, "name", maximum=8_192),
        "configurable": configurable,
        "required": required,
        "riskClasses": _validate_bounded_string_array(value.get("riskClasses"), label="permission riskClasses"),
        "typedCapabilities": _validate_bounded_string_array(
            value.get("typedCapabilities"), label="permission typedCapabilities"
        ),
    }


def _validate_bounded_string_array(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 128:
        raise ValueError(f"Invalid Extension catalog {label}")
    if any(not isinstance(item, str) or not item or len(item) > 8_192 for item in value):
        raise ValueError(f"Invalid Extension catalog {label}")
    if len(value) != len(set(value)):
        raise ValueError(f"Duplicate Extension catalog {label}")
    return value


def _reject_private_wire_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized_key = str(key).replace("_", "").replace("-", "").lower()
            if normalized_key in _FORBIDDEN_WIRE_KEYS:
                raise ValueError(f"private Extension catalog field: {key}")
            _reject_private_wire_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_private_wire_keys(child)


def build_extension_catalog_wire(
    registry: RegistryLike,
    *,
    guard_version: str,
    generated_at: str,
) -> ExtensionCatalogWire:
    """Project the runtime registry without detector, command, path, or secret data."""

    if not guard_version.strip() or not generated_at.strip():
        raise ValueError("guard_version and generated_at are required")
    extensions = sorted(
        (_extension_wire(extension) for extension in registry.extensions),
        key=lambda extension: extension["id"],
    )
    if len(extensions) > MAX_CATALOG_EXTENSIONS:
        raise ValueError("Extension catalog limit exceeded")
    payload: ExtensionCatalogWire = {
        "schemaVersion": EXTENSION_CATALOG_SCHEMA_VERSION,
        "catalogDigest": catalog_digest_for_extensions(extensions),
        "guardVersion": guard_version,
        "controlSchemaVersion": EXTENSION_CONTROL_WIRE_SCHEMA_VERSION,
        "generatedAt": generated_at,
        "limits": {
            "maxExtensions": MAX_CATALOG_EXTENSIONS,
            "maxPermissionsPerExtension": MAX_PERMISSIONS_PER_EXTENSION,
            "maxPayloadBytes": MAX_CATALOG_PAYLOAD_BYTES,
            "maxStringLength": 8_192,
        },
        "extensions": extensions,
    }
    _reject_private_wire_keys(payload)
    if len(_canonical_json(payload).encode("utf-8")) > MAX_CATALOG_PAYLOAD_BYTES:
        raise ValueError("Extension catalog payload limit exceeded")
    return validate_extension_catalog_wire(payload)


def build_builtin_extension_catalog_wire(
    *,
    guard_version: str,
    generated_at: str,
) -> ExtensionCatalogWire:
    """Build the wire projection from the actual built-in command Extension registry."""

    from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    return build_extension_catalog_wire(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        guard_version=guard_version,
        generated_at=generated_at,
    )


def build_managed_controls_runtime_posture(
    *,
    catalog_digest: str,
    extension_authority_revision: int | None = None,
    effective_projection_digest: str | None = None,
    capabilities: Iterable[str] = MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
) -> ManagedControlsRuntimePostureWire:
    """Build bounded runtime posture for the existing runtime-session sync channel."""

    if _SHA256.fullmatch(catalog_digest) is None:
        raise ValueError("catalog_digest must be a lowercase SHA-256 digest")
    if extension_authority_revision is not None and extension_authority_revision < 0:
        raise ValueError("extension_authority_revision cannot be negative")
    if effective_projection_digest is not None and _WIRE_SHA256.fullmatch(effective_projection_digest) is None:
        raise ValueError("effective_projection_digest must be a sha256-prefixed lowercase digest")
    requested = frozenset(capabilities)
    return {
        "extensionCatalogDigest": catalog_digest,
        "extensionControlSchemaVersions": [EXTENSION_CONTROL_WIRE_SCHEMA_VERSION],
        "extensionAuthorityRevision": extension_authority_revision,
        "effectiveProjectionDigest": effective_projection_digest,
        "managedControlsCapabilities": [
            capability for capability in MANAGED_CONTROLS_RUNTIME_CAPABILITIES if capability in requested
        ],
    }
