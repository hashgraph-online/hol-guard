"""Source-bound entry for the Cloud Review owner fixtures.

Puts this worktree's src on sys.path, then runs the named fixtures through
pytest. The shell command does not prefix an environment assignment.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pytest  # noqa: E402 -- deliberate sys.path shim before pytest import

NODES = (
    "tests/test_guard_review_event_outbox_delivery.py::test_unconnected_store_is_not_enrolled_and_does_not_deliver",
    "tests/test_guard_review_event_outbox_delivery.py::test_invalid_claim_is_quarantined_without_starving_a_later_neighbor",
    "tests/test_guard_review_event_outbox_delivery.py::test_source_gap_snapshot_acks_neighbor_without_acknowledging_poison",
    "tests/test_guard_review_event_outbox_delivery.py::test_watch_only_snapshot_projects_schema_two_observation",
    "tests/test_native_workspace_review_receipts.py::test_held_native_activity_page_does_not_block_a_later_receipt",
)


if __name__ == "__main__":
    os.chdir(ROOT)
    raise SystemExit(
        pytest.main(
            [
                "-q",
                "--tb=short",
                f"--rootdir={ROOT}",
                *NODES,
            ]
        )
    )
