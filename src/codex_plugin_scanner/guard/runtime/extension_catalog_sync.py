"""Privacy-safe Local-to-Cloud Extension catalog wire projection."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Protocol, TypedDict

from .extension_control_contract import CONTROL_SCHEMA_VERSION
from .extension_control_limits import (
    MAX_CATALOG_EXTENSIONS,
    MAX_CATALOG_PAYLOAD_BYTES,
    MAX_PERMISSIONS_PER_EXTENSION,
)

EXTENSION_CATALOG_SCHEMA_VERSION = "guard.extension-catalog.v1"
MANAGED_CONTROLS_RUNTIME_CAPABILITIES = (
    "extension-catalog.v1",
    "extension-control-layer.v1",
    "policy-extension-targets.v1",
    "managed-controls-atomic-apply.v1",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_WIRE_KEYS = frozenset(
    {
        "action_classes",
        "command_history",
        "description",
        "environment",
        "example_command",
        "file_contents",
        "project_markers",
        "reference_urls",
        "rule_ids",
        "rules",
        "safer_alternatives",
        "secrets",
        "source_path",
        "working_directory",
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
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


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


def catalog_digest_for_extensions(extensions: list[ExtensionCatalogEntryWire]) -> str:
    """Return the cross-language SHA-256 digest over canonical projected Extensions."""

    return hashlib.sha256(_canonical_json(extensions).encode("utf-8")).hexdigest()


def _reject_private_wire_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in _FORBIDDEN_WIRE_KEYS:
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
        "controlSchemaVersion": CONTROL_SCHEMA_VERSION,
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
    return payload


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
    if effective_projection_digest is not None and _SHA256.fullmatch(effective_projection_digest) is None:
        raise ValueError("effective_projection_digest must be a lowercase SHA-256 digest")
    requested = frozenset(capabilities)
    return {
        "extensionCatalogDigest": catalog_digest,
        "extensionControlSchemaVersions": [CONTROL_SCHEMA_VERSION],
        "extensionAuthorityRevision": extension_authority_revision,
        "effectiveProjectionDigest": effective_projection_digest,
        "managedControlsCapabilities": [
            capability for capability in MANAGED_CONTROLS_RUNTIME_CAPABILITIES if capability in requested
        ],
    }
