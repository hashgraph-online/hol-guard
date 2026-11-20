"""Drift classification for Local and Guard Cloud posture."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .acknowledgement import ManagedControlsAcknowledgement


class DriftState(str, Enum):
    CURRENT = "current"
    PENDING = "pending"
    CATALOG_MISMATCH = "catalog_mismatch"
    EFFECTIVE_MISMATCH = "effective_mismatch"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ExpectedManagedControlsState:
    revision: int
    bundle_hash: str
    catalog_digest: str
    effective_digest: str
    extension_authority_revision: int


def classify_drift(
    expected: ExpectedManagedControlsState,
    acknowledgement: ManagedControlsAcknowledgement | None,
    *,
    supported: bool = True,
) -> DriftState:
    if not supported:
        return DriftState.UNSUPPORTED
    if acknowledgement is None or acknowledgement.revision < expected.revision:
        return DriftState.PENDING
    if acknowledgement.bundle_hash != expected.bundle_hash:
        return DriftState.PENDING
    if acknowledgement.extension_authority_revision != expected.extension_authority_revision:
        return DriftState.PENDING
    if acknowledgement.catalog_digest != expected.catalog_digest:
        return DriftState.CATALOG_MISMATCH
    if acknowledgement.effective_digest != expected.effective_digest:
        return DriftState.EFFECTIVE_MISMATCH
    return DriftState.CURRENT
