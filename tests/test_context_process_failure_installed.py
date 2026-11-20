"""Actual private SDK/bridge interruption between consent and native dispatch."""

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
    reason="requires the approved installed macOS/CIGAR candidate and owned process identities",
)
@pytest.mark.parametrize("fault_kind", ["bridge-crash", "sdk-crash", "bridge-stall"])
@pytest.mark.parametrize("persistent", [False, True], ids=["allow-once", "always-allow"])
def test_actual_optional_process_failure_preserves_pending_native_approval(
    native_context_digest, tmp_path, monkeypatch, persistent, fault_kind
):
    _execution_case(native_context_digest, tmp_path, monkeypatch, persistent, fault_kind=fault_kind)
