"""Operational health and performance budgets for Managed Controls."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ManagedControlsHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RECOVERY_REQUIRED = "recovery_required"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ManagedControlsPerformanceBudget:
    catalog_projection_ms: int = 100
    compatibility_evaluation_ms: int = 50
    atomic_apply_ms: int = 500
    acknowledgement_ms: int = 250

    def assert_within(self, operation: str, elapsed_ms: float) -> None:
        limit = {
            "catalog_projection": self.catalog_projection_ms,
            "compatibility_evaluation": self.compatibility_evaluation_ms,
            "atomic_apply": self.atomic_apply_ms,
            "acknowledgement": self.acknowledgement_ms,
        }.get(operation)
        if limit is None:
            raise ValueError("unknown performance operation")
        if elapsed_ms > limit:
            raise ValueError(f"{operation} exceeded performance budget")


@dataclass(frozen=True, slots=True)
class OperationalSnapshot:
    health: ManagedControlsHealth
    last_successful_revision: int | None
    catalog_digest: str | None
    recovery_action: str | None


def health_snapshot(
    *,
    authority_valid: bool,
    supported: bool,
    last_successful_revision: int | None,
    catalog_digest: str | None,
) -> OperationalSnapshot:
    if not supported:
        return OperationalSnapshot(
            ManagedControlsHealth.UNSUPPORTED,
            last_successful_revision,
            catalog_digest,
            "update_guard",
        )
    if not authority_valid:
        return OperationalSnapshot(
            ManagedControlsHealth.RECOVERY_REQUIRED,
            last_successful_revision,
            catalog_digest,
            "repair_protection",
        )
    return OperationalSnapshot(
        ManagedControlsHealth.HEALTHY,
        last_successful_revision,
        catalog_digest,
        None,
    )
