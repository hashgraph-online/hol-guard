"""Reconcile completed and active native effects after delivery-host loss."""

from __future__ import annotations

import json
import os
import sys
import time
from contextlib import nullcontext
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_resident_client import close_native_resident_clients
from scripts.cigar_benchmark_processes import ProcessSampler
from tests.context_execution_barrier import NativeEffectBarrier
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
    reason="requires the approved installed macOS/CIGAR candidate and owned delivery host",
)
@pytest.mark.parametrize("persistent", [False, True], ids=["allow-once", "always-allow"])
@pytest.mark.parametrize("phase", ["completed", "running"])
def test_native_effect_is_reconciled_after_delivery_host_loss(
    native_context_digest, tmp_path, monkeypatch, persistent, phase
):
    selection = json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())
    report = {"schema": "guard-cigar-native-response-loss-resources.v1", "phase": phase, "completed": False}
    with (
        NativeEffectBarrier() if phase == "running" else nullcontext(None) as barrier,
        ProcessSampler(Path(selection["python"])) as sampler,
    ):
        before, baseline = sampler.sample_with_identities()
        report["before"] = before
        try:
            _execution_case(
                native_context_digest,
                tmp_path,
                monkeypatch,
                persistent,
                lose_completed_response=phase == "completed",
                lose_running_response=phase == "running",
                effect_barrier=barrier,
            )
            report["completed"] = True
        finally:
            try:
                assert close_native_resident_clients(tmp_path / "guard", deadline_monotonic=time.monotonic() + 10)
                deadline = time.monotonic() + 5
                after, remaining = sampler.sample_with_identities()
                while remaining.keys() - baseline.keys() and time.monotonic() < deadline:
                    time.sleep(0.05)
                    after, remaining = sampler.sample_with_identities()
                report.update(after=after, new_live_descendants_remaining=len(remaining.keys() - baseline.keys()))
                report["resources"] = sampler.summary()
                assert report["new_live_descendants_remaining"] == 0
                assert report["resources"]["sampling_errors"] == 0
                assert report["resources"]["maximum_counts"].get("sdk_worker", 0) >= 1
                assert report["resources"]["maximum_counts"].get("python_bridge", 0) >= 1
            finally:
                with (tmp_path / "response-loss-resources.json").open("x") as output:
                    json.dump(report, output, indent=2)
                    output.write("\n")
