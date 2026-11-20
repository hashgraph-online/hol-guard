"""Three-minute source-change acceptance through five real paired MCP clients.

The unchanged short case also covers capacity, revoke/reuse and global Stop.
Observed RSS is diagnostic; no matched memory or latency improvement is claimed.
"""

from __future__ import annotations

import os

import pytest

from tests.test_context_concurrency_installed import (
    test_five_shared_clients_source_churn_and_twelve_attempts_obey_native_limits as _exercise,
)


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1"
    or not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the approved installed CIGAR candidate and an explicit three-minute source-change soak",
)
def test_five_paired_clients_follow_twelve_source_updates_over_three_minutes(native_hook_force, tmp_path):
    _exercise(native_hook_force, tmp_path, source_update_rounds=12, source_update_interval=15)
