"""Privacy-safe Local-to-Cloud Extension catalog wire projection.

The native runtime owns the v1 catalog projection, bounded shape and privacy
validation, and the cross-language canonical digest. This module only gathers
registry values, calls the resident ``cloud_catalog`` operation, and renders
its answer in the stable wire field order. There is no Python fallback: an
unavailable runtime raises and callers fail closed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol, TypedDict

from .managed_controls_posture_wire import (
    EXTENSION_CONTROL_WIRE_SCHEMA_VERSION as EXTENSION_CONTROL_WIRE_SCHEMA_VERSION,
)
from .managed_controls_posture_wire import (
    MANAGED_CONTROLS_RUNTIME_CAPABILITIES as MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
)
from .managed_controls_posture_wire import (
    ManagedControlsRuntimePostureWire as ManagedControlsRuntimePostureWire,
)
from .managed_controls_posture_wire import (
    build_managed_controls_runtime_posture as build_managed_controls_runtime_posture,
)

EXTENSION_CATALOG_SCHEMA_VERSION = "guard.extension-catalog.v1"

# Stable wire field order; the native answer is re-keyed into it so upload
# bodies stay byte-identical regardless of the runtime's map ordering.
_TOP_FIELDS = (
    "schemaVersion",
    "catalogDigest",
    "guardVersion",
    "controlSchemaVersion",
    "generatedAt",
    "limits",
    "extensions",
)
_LIMIT_FIELDS = ("maxExtensions", "maxPermissionsPerExtension", "maxPayloadBytes", "maxStringLength")
_ENTRY_FIELDS = (
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
)
# The resident request cap is 4 MiB; keep room for the envelope around the fields.
_NATIVE_FIELDS_MAX_BYTES = 4 * 1024 * 1024 - 64 * 1024
_PERMISSION_FIELDS = ("id", "name", "configurable", "required", "riskClasses", "typedCapabilities")


class ExtensionCatalogLimitError(ValueError):
    """A catalog exceeds a Cloud v1 count or byte limit."""


class ExtensionCatalogUnavailableError(RuntimeError):
    """The resident runtime could not answer, so no catalog exists to send."""


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


def _ordered(value: object, fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise RuntimeError("Native Extension catalog answer is malformed")
    return {field: value[field] for field in fields}


def _render(value: object) -> ExtensionCatalogWire:
    wire: Any = _ordered(value, _TOP_FIELDS)
    extensions = wire["extensions"]
    if not isinstance(extensions, list):
        raise RuntimeError("Native Extension catalog answer is malformed")
    rendered = []
    for extension in extensions:
        entry = _ordered(extension, _ENTRY_FIELDS)
        permissions = entry["permissions"]
        if not isinstance(permissions, list):
            raise RuntimeError("Native Extension catalog answer is malformed")
        entry["permissions"] = [_ordered(permission, _PERMISSION_FIELDS) for permission in permissions]
        rendered.append(entry)
    wire["limits"] = _ordered(wire["limits"], _LIMIT_FIELDS)
    wire["extensions"] = rendered
    return wire


def native_wire_call(action: str, *, guard_home: Path | None = None, **fields: object) -> dict[str, Any]:
    """Run one v1 wire action in the resident and raise its stable refusal."""

    from ..native_context import _resolve_digest_home, ensure_resident_prerequisite
    from . import extension_catalog_pages as pages

    # Measure the way the resident transport encodes: default separators, ASCII escapes.
    encoded = json.dumps(fields, allow_nan=False).encode("utf-8")
    if len(encoded) > _NATIVE_FIELDS_MAX_BYTES:
        raise ExtensionCatalogLimitError("Extension catalog exceeds native wire limits")
    home = _resolve_digest_home(guard_home)
    if not ensure_resident_prerequisite(home):
        raise ExtensionCatalogUnavailableError("Native Extension catalog runtime unavailable")
    payload = pages.native_call(home, action=action, **fields)
    refusal = payload.get("v1_error")
    if refusal is None:
        return payload
    message = payload.get("message")
    if refusal == "limit" and isinstance(message, str):
        raise ExtensionCatalogLimitError(message)
    if refusal == "invalid" and isinstance(message, str):
        raise ValueError(message)
    if refusal == "protocol" and isinstance(message, str):
        raise RuntimeError(message)
    raise RuntimeError("Native Extension catalog answer is malformed")


def canonical_extension_catalog_json(
    extensions: list[ExtensionCatalogEntryWire], *, guard_home: Path | None = None
) -> str:
    """Return the shared canonical JSON for an Extension projection."""

    text = native_wire_call("v1_canonical", guard_home=guard_home, extensions=extensions).get("canonical_json")
    if not isinstance(text, str):
        raise RuntimeError("Native Extension catalog answer is malformed")
    return text


def catalog_digest_for_extensions(
    extensions: list[ExtensionCatalogEntryWire], *, guard_home: Path | None = None
) -> str:
    """Return the cross-language SHA-256 digest over canonical projected Extensions."""

    digest = native_wire_call("v1_canonical", guard_home=guard_home, extensions=extensions).get("catalog_digest")
    if not isinstance(digest, str):
        raise RuntimeError("Native Extension catalog answer is malformed")
    return digest


def validate_extension_catalog_wire(payload: object, *, guard_home: Path | None = None) -> ExtensionCatalogWire:
    """Execute the shared catalog's bounded shape, privacy, identity, and digest contract."""

    return _render(native_wire_call("v1_validate", guard_home=guard_home, payload=payload).get("catalog"))


def build_extension_catalog_wire(
    registry: RegistryLike,
    *,
    guard_version: str,
    generated_at: str,
    guard_home: Path | None = None,
) -> ExtensionCatalogWire:
    """Project the runtime registry without detector, command, path, or secret data."""

    from .extension_catalog_pages import _raw_extension

    if not guard_version.strip() or not generated_at.strip():
        raise ValueError("guard_version and generated_at are required")
    answer = native_wire_call(
        "v1_build",
        guard_home=guard_home,
        extensions=[_raw_extension(extension) for extension in registry.extensions],
        guard_version=guard_version,
        generated_at=generated_at,
    )
    return _render(answer.get("catalog"))


def build_builtin_extension_catalog_wire(
    *,
    guard_version: str,
    generated_at: str,
    guard_home: Path | None = None,
) -> ExtensionCatalogWire:
    """Build the wire projection from the actual built-in command Extension registry."""

    from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    return build_extension_catalog_wire(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        guard_version=guard_version,
        generated_at=generated_at,
        guard_home=guard_home,
    )


def build_v1_catalog_from_view(view: object) -> ExtensionCatalogWire:
    """Native bounded compatibility projection of the complete observed view."""
    from .extension_catalog_pages import PreparedCatalogView

    if not isinstance(view, PreparedCatalogView):
        raise ValueError("A prepared complete catalog view is required")
    return view.legacy()
