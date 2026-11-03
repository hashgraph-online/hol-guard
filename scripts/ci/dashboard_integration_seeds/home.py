"""Seed data for the dashboard home integration specs.

Home reads the runtime snapshot, so this seed gives it what a machine that has
been using Guard looks like: connected apps (two protected, one that still
needs setup) and a few recorded decisions. Records go through the same store
calls the CLI and hooks use.

Home also sums every other area's records (pending reviews, receipts), so the
specs compare the page with the live daemon and use these facts only for the
rows this seed owns.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from codex_plugin_scanner.guard.models import GuardReceipt

from . import SeedContext

# Connectable apps only: Home hides managed installs for anything else.
_INSTALLS: tuple[tuple[str, bool], ...] = (
    ("claude-code", True),
    ("cursor", True),
    ("copilot", False),
)

# (key, harness, decision, artifact_name)
_RECEIPTS: tuple[tuple[str, str, str, str], ...] = (
    ("allowed", "claude-code", "allow", "Home e2e read config"),
    ("blocked", "cursor", "block", "Home e2e delete build"),
    ("paused", "claude-code", "review", "Home e2e network call"),
)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_clear_of_midnight() -> datetime:
    # Receipts are stamped up to len(_RECEIPTS) seconds back. Just after
    # midnight, UTC or local, that would put them on yesterday, so wait until
    # every stamp lands on the current day in both.
    now = datetime.now(UTC)
    local_midnight = now.astimezone().replace(hour=0, minute=0, second=0, microsecond=0)
    utc_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    day_start = max(local_midnight.astimezone(UTC), utc_midnight)
    earliest_safe = day_start + timedelta(seconds=len(_RECEIPTS) + 1)
    if now < earliest_safe:
        time.sleep((earliest_safe - now).total_seconds())
        now = datetime.now(UTC)
    return now


def seed(context: SeedContext) -> dict[str, Any]:
    workspace = str(context.workspace)
    # Recent stamps keep the receipts inside "today" and the latest-activity
    # window whenever the suite runs.
    now = _now_clear_of_midnight()
    for harness, active in _INSTALLS:
        context.store.set_managed_install(
            harness,
            active,
            workspace,
            {"managed_hooks_path": f"{workspace}/.{harness}/hooks"},
            _stamp(now - timedelta(minutes=10)),
        )
    receipts: dict[str, dict[str, str]] = {}
    for index, (key, harness, decision, name) in enumerate(_RECEIPTS):
        receipt_id = f"home-e2e-receipt-{key}"
        context.store.add_receipt(
            GuardReceipt(
                receipt_id=receipt_id,
                timestamp=_stamp(now - timedelta(seconds=len(_RECEIPTS) - index)),
                harness=harness,
                artifact_id=f"{harness}:project:tool-action:home-e2e-{key}",
                artifact_hash=f"hash-home-e2e-{key}",
                policy_decision=decision,
                capabilities_summary="shell command",
                changed_capabilities=("command",),
                provenance_summary="local project",
                artifact_name=name,
                source_scope="project",
            )
        )
        receipts[key] = {"id": receipt_id, "harness": harness, "decision": decision, "name": name}
    return {
        "workspace": workspace,
        "activeApps": [harness for harness, active in _INSTALLS if active],
        "inactiveApps": [harness for harness, active in _INSTALLS if not active],
        "receipts": receipts,
    }
