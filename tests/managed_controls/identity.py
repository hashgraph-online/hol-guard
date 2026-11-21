"""Stable identity and catalog compatibility helpers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CatalogIdentityState(str, Enum):
    EXACT = "exact"
    VERSION_DIFFERENT = "version_different"
    MISSING = "missing"
    CUSTOM_LOCAL_ONLY = "custom_local_only"


@dataclass(frozen=True, slots=True)
class ExtensionIdentity:
    extension_id: str
    version: str
    custom: bool = False


def compare_extension_identity(
    local: ExtensionIdentity,
    cloud: ExtensionIdentity | None,
) -> CatalogIdentityState:
    if cloud is None:
        if local.custom:
            return CatalogIdentityState.CUSTOM_LOCAL_ONLY
        return CatalogIdentityState.MISSING
    if local.extension_id != cloud.extension_id:
        return CatalogIdentityState.MISSING
    if local.version != cloud.version:
        return CatalogIdentityState.VERSION_DIFFERENT
    return CatalogIdentityState.EXACT
