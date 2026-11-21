"""Monotonic, idempotent acknowledgement contract."""

from __future__ import annotations

from dataclasses import dataclass


class AcknowledgementError(ValueError):
    """Raised when acknowledgement evidence is stale or incomplete."""


@dataclass(frozen=True, slots=True)
class ManagedControlsAcknowledgement:
    revision: int
    bundle_hash: str
    catalog_digest: str
    effective_digest: str
    extension_authority_revision: int

    def __post_init__(self) -> None:
        if self.revision < 0 or self.extension_authority_revision < 0:
            raise AcknowledgementError("acknowledgement revision cannot be negative")
        for value in (self.bundle_hash, self.catalog_digest, self.effective_digest):
            if not value:
                raise AcknowledgementError("acknowledgement digest is required")


def accept_acknowledgement(
    previous: ManagedControlsAcknowledgement | None,
    candidate: ManagedControlsAcknowledgement,
) -> ManagedControlsAcknowledgement:
    if previous is None:
        return candidate
    if candidate == previous:
        return previous
    if candidate.revision < previous.revision:
        raise AcknowledgementError("acknowledgement revision moved backwards")
    if candidate.extension_authority_revision < previous.extension_authority_revision:
        raise AcknowledgementError("extension authority revision moved backwards")
    if candidate.revision == previous.revision:
        raise AcknowledgementError("same revision has conflicting evidence")
    return candidate
