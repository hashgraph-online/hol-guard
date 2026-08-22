"""Canonical, bounded, privacy-safe Extension catalog projection."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import cast

from ..runtime.extension_control_limits import (
    MAX_CATALOG_EXTENSIONS,
    MAX_CATALOG_PAYLOAD_BYTES,
    MAX_PERMISSIONS_PER_EXTENSION,
)

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class CatalogValidationError(ValueError):
    """Raised when a catalog cannot be trusted or represented."""


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise CatalogValidationError(f"invalid {label}")
    return value


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogValidationError(f"{label} is required")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise CatalogValidationError(f"{label} must be a boolean")
    return cast(bool, value)


@dataclass(frozen=True, slots=True)
class CatalogPermission:
    permission_id: str
    name: str
    configurable: bool
    required: bool = False
    delegated_protection: str | None = None

    def __post_init__(self) -> None:
        _identity(self.permission_id, "permission id")
        _required_text(self.name, "permission name")
        _boolean(self.configurable, "permission configurable")
        _boolean(self.required, "permission required")
        if self.delegated_protection is not None:
            _identity(self.delegated_protection, "delegated protection")
        if self.required and self.configurable:
            raise CatalogValidationError("required permissions cannot be configurable")

    def to_dict(self) -> dict[str, object]:
        return {
            "permission_id": self.permission_id,
            "name": self.name,
            "configurable": self.configurable,
            "required": self.required,
            "delegated_protection": self.delegated_protection,
        }


@dataclass(frozen=True, slots=True)
class CatalogExtension:
    extension_id: str
    name: str
    version: str
    permissions: tuple[CatalogPermission, ...]
    required: bool = False
    custom: bool = False

    def __post_init__(self) -> None:
        _identity(self.extension_id, "extension id")
        _required_text(self.name, "extension name")
        _required_text(self.version, "extension version")
        _boolean(self.required, "extension required")
        _boolean(self.custom, "extension custom")
        if not isinstance(self.permissions, tuple) or not all(
            isinstance(item, CatalogPermission) for item in self.permissions
        ):
            raise CatalogValidationError("permissions must be a permission tuple")
        if len(self.permissions) > MAX_PERMISSIONS_PER_EXTENSION:
            raise CatalogValidationError("permission limit exceeded")
        permission_ids = [item.permission_id for item in self.permissions]
        if len(permission_ids) != len(set(permission_ids)):
            raise CatalogValidationError("duplicate permission id")

    def to_dict(self) -> dict[str, object]:
        ordered_permissions = sorted(
            self.permissions,
            key=lambda item: item.permission_id,
        )
        return {
            "extension_id": self.extension_id,
            "name": self.name,
            "version": self.version,
            "required": self.required,
            "custom": self.custom,
            "permissions": [item.to_dict() for item in ordered_permissions],
        }


@dataclass(frozen=True, slots=True)
class CatalogProjection:
    schema_version: int
    extensions: tuple[CatalogExtension, ...]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise CatalogValidationError("unsupported catalog schema")
        if not isinstance(self.extensions, tuple) or not all(
            isinstance(item, CatalogExtension) for item in self.extensions
        ):
            raise CatalogValidationError("extensions must be an extension tuple")
        if len(self.extensions) > MAX_CATALOG_EXTENSIONS:
            raise CatalogValidationError("extension limit exceeded")
        extension_ids = [item.extension_id for item in self.extensions]
        if len(extension_ids) != len(set(extension_ids)):
            raise CatalogValidationError("duplicate extension id")
        if len(self.canonical_bytes()) > MAX_CATALOG_PAYLOAD_BYTES:
            raise CatalogValidationError("catalog payload limit exceeded")

    def payload(self) -> dict[str, object]:
        ordered = sorted(self.extensions, key=lambda item: item.extension_id)
        return {
            "schema_version": self.schema_version,
            "extensions": [item.to_dict() for item in ordered],
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def permission(self, extension_id: str, permission_id: str) -> CatalogPermission:
        for extension in self.extensions:
            if extension.extension_id != extension_id:
                continue
            for permission in extension.permissions:
                if permission.permission_id == permission_id:
                    return permission
            raise CatalogValidationError("unknown permission target")
        raise CatalogValidationError("unknown extension target")
