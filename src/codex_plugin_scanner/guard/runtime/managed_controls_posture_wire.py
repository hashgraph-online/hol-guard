"""Bounded managed-control posture on the runtime-session wire."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TypedDict

from typing_extensions import NotRequired

EXTENSION_CONTROL_WIRE_SCHEMA_VERSION = "guard.extension-controls.v1"
MANAGED_CONTROLS_RUNTIME_CAPABILITIES = (
    "extension-catalog.v1",
    "extension-control-layer.v1",
    "policy-extension-targets.v1",
    "managed-controls-atomic-apply.v1",
    "custom-extension-continuity.v2",
)


class ManagedControlsRuntimePostureWire(TypedDict):
    extensionCatalogDigest: str
    extensionControlSchemaVersions: list[str]
    extensionAuthorityRevision: int | None
    managedExtensionAuthorityRevision: NotRequired[int]
    effectiveProjectionDigest: str | None
    managedControlsCapabilities: list[str]


def build_managed_controls_runtime_posture(
    *,
    catalog_digest: str,
    extension_authority_revision: int | None = None,
    managed_extension_authority_revision: int | None = None,
    effective_projection_digest: str | None = None,
    capabilities: Iterable[str] = MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
) -> ManagedControlsRuntimePostureWire:
    """Keep observed local and managed counters independent; omit unknown state."""

    if re.fullmatch(r"[0-9a-f]{64}", catalog_digest) is None:
        raise ValueError("catalog_digest must be a lowercase SHA-256 digest")
    if extension_authority_revision is not None and extension_authority_revision < 0:
        raise ValueError("extension_authority_revision cannot be negative")
    if managed_extension_authority_revision is not None and (
        type(managed_extension_authority_revision) is not int
        or not 0 <= managed_extension_authority_revision <= 2**53 - 1
    ):
        raise ValueError("managed_extension_authority_revision must be a nonnegative safe integer")
    if (
        effective_projection_digest is not None
        and re.fullmatch(r"sha256:[0-9a-f]{64}", effective_projection_digest) is None
    ):
        raise ValueError("effective_projection_digest must be a sha256-prefixed lowercase digest")
    requested = frozenset(capabilities)
    posture: ManagedControlsRuntimePostureWire = {
        "extensionCatalogDigest": catalog_digest,
        "extensionControlSchemaVersions": [EXTENSION_CONTROL_WIRE_SCHEMA_VERSION],
        "extensionAuthorityRevision": extension_authority_revision,
        "effectiveProjectionDigest": effective_projection_digest,
        "managedControlsCapabilities": [
            capability for capability in MANAGED_CONTROLS_RUNTIME_CAPABILITIES if capability in requested
        ],
    }
    if managed_extension_authority_revision is not None:
        posture["managedExtensionAuthorityRevision"] = managed_extension_authority_revision
    return posture
