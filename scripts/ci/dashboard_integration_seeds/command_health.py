"""Leave command-activity evidence health degraded, the way a failed hook write does.

``record_command_activity_persistence_failure`` is the call a hook makes when it
cannot save a command check. The flag it sets used to stay on until the next
successful write, so a machine whose hooks went quiet showed a warning the user
could not clear. This seed runs after every other seed, so no later write clears
the flag, and the specs check that the daemon repairs it on its own.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from . import SeedContext

ERROR_CLASS = "pre_record_failed"


def seed(context: SeedContext) -> dict[str, Any]:
    context.store.record_command_activity_persistence_failure(
        error_code=ERROR_CLASS,
        occurred_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    health = context.store.get_command_activity_persistence_health()
    return {"error_class": ERROR_CLASS, "active_errors_after_seed": health.active_error_count}
