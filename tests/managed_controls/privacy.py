"""Privacy boundaries for Local-to-Cloud catalog continuity."""

from __future__ import annotations

import re
from collections.abc import Mapping

from codex_plugin_scanner.guard.redaction import redact_local_path, redact_sensitive_text, redact_text

_ALLOWED_EXTENSION_FIELDS = frozenset({"extension_id", "name", "version", "required", "custom", "permissions"})
_ALLOWED_PERMISSION_FIELDS = frozenset(
    {
        "permission_id",
        "name",
        "configurable",
        "required",
        "delegated_protection",
    }
)
_FORBIDDEN_MARKERS = (
    "command",
    "raw_command",
    "source_path",
    "working_directory",
    "secret",
    "token",
    "environment",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CatalogPrivacyError(ValueError):
    """Raised when a projection crosses the catalog privacy boundary."""


def _reject_forbidden_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower()
            if any(marker in normalized for marker in _FORBIDDEN_MARKERS):
                raise CatalogPrivacyError(f"forbidden catalog field: {key}")
            _reject_forbidden_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden_keys(child)


def _safe_text(value: object, *, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CatalogPrivacyError(f"{label} must be bounded text")
    redacted = redact_text(redact_sensitive_text(redact_local_path(value))).text
    if redacted != value:
        raise CatalogPrivacyError(f"{label} contains sensitive material")
    return value


def _safe_boolean(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise CatalogPrivacyError(f"{label} must be a boolean")
    return value


def _safe_permission(permission: object) -> dict[str, object]:
    if not isinstance(permission, Mapping):
        raise CatalogPrivacyError("permission entry must be an object")
    unknown = set(permission) - _ALLOWED_PERMISSION_FIELDS
    if unknown:
        raise CatalogPrivacyError("permission entry contains unsupported fields")
    safe: dict[str, object] = {
        "permission_id": _safe_text(
            permission.get("permission_id"),
            label="permission id",
        ),
        "name": _safe_text(permission.get("name"), label="permission name"),
        "configurable": _safe_boolean(
            permission.get("configurable"),
            label="permission configurable",
        ),
        "required": _safe_boolean(
            permission.get("required"),
            label="permission required",
        ),
    }
    delegated = permission.get("delegated_protection")
    if delegated is not None:
        safe["delegated_protection"] = _safe_text(
            delegated,
            label="delegated protection",
        )
    elif "delegated_protection" in permission:
        safe["delegated_protection"] = None
    return safe


def privacy_safe_catalog_payload(payload: Mapping[str, object]) -> dict[str, object]:
    _reject_forbidden_keys(payload)
    if payload.get("schema_version") != 1:
        raise CatalogPrivacyError("unsupported catalog schema")
    digest = payload.get("catalog_digest")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise CatalogPrivacyError("catalog digest must be a lowercase SHA-256 digest")
    extensions = payload.get("extensions")
    if not isinstance(extensions, list):
        raise CatalogPrivacyError("extensions must be a list")
    safe_extensions: list[dict[str, object]] = []
    for extension in extensions:
        if not isinstance(extension, Mapping):
            raise CatalogPrivacyError("extension entry must be an object")
        unknown = set(extension) - _ALLOWED_EXTENSION_FIELDS
        if unknown:
            raise CatalogPrivacyError("extension entry contains unsupported fields")
        safe: dict[str, object] = {
            "extension_id": _safe_text(
                extension.get("extension_id"),
                label="extension id",
            ),
            "name": _safe_text(extension.get("name"), label="extension name"),
            "version": _safe_text(
                extension.get("version"),
                label="extension version",
            ),
        }
        for key in ("required", "custom"):
            if key in extension:
                safe[key] = _safe_boolean(extension[key], label=f"extension {key}")
        permissions = extension.get("permissions", [])
        if not isinstance(permissions, list):
            raise CatalogPrivacyError("permissions must be a list")
        safe["permissions"] = [_safe_permission(permission) for permission in permissions]
        safe_extensions.append(safe)
    return {
        "schema_version": 1,
        "catalog_digest": digest,
        "extensions": safe_extensions,
    }
