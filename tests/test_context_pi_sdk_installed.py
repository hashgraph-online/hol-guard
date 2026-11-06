"""Actual pinned Pi/OMP SDK tool delivery with optional CIGAR execution context.

No model, account, interactive CLI or live application configuration is used.
The existing SDK fixture still owns consent, dispatch and replay assertions.
"""

from __future__ import annotations

import os
import sys

import pytest

from tests.test_omp_bound_bash_sdk import (
    test_pinned_sdk_bash_tool_delivers_consent_and_preserves_execution_cwd as _run_sdk_case,
)


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    sys.platform != "darwin"
    or os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1"
    or not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the explicitly approved installed macOS/CIGAR candidate and locked Pi SDK packages",
)
@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize("duration", ["once", "persistent"])
def test_actual_sdk_tool_delivery_preserves_approvals_with_cigar_execution_context(
    native_context_digest, tmp_path, monkeypatch, harness, duration
):
    _run_sdk_case(
        native_context_digest,
        tmp_path,
        monkeypatch,
        duration,
        harness,
        None,
        cigar_execution=True,
    )
