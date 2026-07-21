"""Pure monotonic-time validation for workflow-capability control."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

from .workflow_capabilities import WorkflowCapabilityError, parse_utc_timestamp


def validate_monotonic_workflow_capability_time(*, now: str, observed_at: str) -> bool:
    """Reject rollback and report whether the external high-water must advance."""
    current = parse_utc_timestamp(now)
    observed = parse_utc_timestamp(observed_at)
    if current < observed:
        raise WorkflowCapabilityError("capability_clock_rollback")
    return current > observed
