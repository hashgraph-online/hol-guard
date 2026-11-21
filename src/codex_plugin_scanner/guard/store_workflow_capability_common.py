"""Clock seam shared by the workflow-capability store boundary."""

from __future__ import annotations

from datetime import datetime, timezone

from .workflow_capabilities import format_utc_timestamp


class WorkflowCapabilityStoreClock:
    def now(self) -> str:
        return format_utc_timestamp(datetime.now(timezone.utc))


WORKFLOW_CAPABILITY_STORE_CLOCK = WorkflowCapabilityStoreClock()
