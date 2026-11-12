"""Real execution after the private SDK client's initial five-minute lease."""

from __future__ import annotations

import os
import sys

import pytest

from tests.test_context_execution_sink_installed import (
    test_installed_execution_context_preserves_consent_replay_restart_and_opt_out as _execution_case,
)


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    sys.platform != "darwin"
    or os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1"
    or not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the approved installed macOS/CIGAR candidate and an actual five-minute lease wait",
)
def test_background_renewal_preserves_actual_execution_after_initial_lease(
    native_context_digest, tmp_path, monkeypatch
):
    _execution_case(native_context_digest, tmp_path, monkeypatch, True, lease_wait_seconds=310)
