"""Seed data for the dashboard settings integration specs.

The integration home starts with Guard's default settings, and the server has
already turned the approval gate on. Nothing needs writing: the seed reads the
settings Guard actually loaded so the specs assert against the daemon's own
baseline instead of a hard-coded copy of it.
"""

from __future__ import annotations

from typing import Any

from codex_plugin_scanner.guard.config import load_guard_config

from . import SeedContext

# The mutating spec raises the approval wait by this much, then puts it back.
_TIMEOUT_STEP_SECONDS = 30


def seed(context: SeedContext) -> dict[str, Any]:
    config = load_guard_config(context.guard_home, create_home=False)
    baseline = config.approval_wait_timeout_seconds
    return {
        "approvalWaitTimeoutSeconds": baseline,
        "changedApprovalWaitTimeoutSeconds": baseline + _TIMEOUT_STEP_SECONDS,
    }
