"""Device compatibility decisions for safe rollout."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .capabilities import MANAGED_CONTROL_CAPABILITIES


class CompatibilityState(str, Enum):
    COMPATIBLE = "compatible"
    MISSING_CAPABILITY = "missing_capability"
    CATALOG_MISMATCH = "catalog_mismatch"
    SCHEMA_UNSUPPORTED = "schema_unsupported"


@dataclass(frozen=True, slots=True)
class DeviceCompatibility:
    capabilities: frozenset[str]
    catalog_digest: str
    catalog_schema_version: int
    extension_control_schema_version: int = 1


def evaluate_compatibility(
    device: DeviceCompatibility,
    *,
    required_catalog_digest: str,
    required_schema_version: int = 1,
    required_control_schema_version: int = 1,
) -> CompatibilityState:
    if not device.capabilities >= MANAGED_CONTROL_CAPABILITIES:
        return CompatibilityState.MISSING_CAPABILITY
    if device.catalog_schema_version != required_schema_version:
        return CompatibilityState.SCHEMA_UNSUPPORTED
    if device.extension_control_schema_version != required_control_schema_version:
        return CompatibilityState.SCHEMA_UNSUPPORTED
    if device.catalog_digest != required_catalog_digest:
        return CompatibilityState.CATALOG_MISMATCH
    return CompatibilityState.COMPATIBLE
