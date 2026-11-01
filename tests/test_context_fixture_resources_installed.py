"""Verify the process baseline around one private off-state native fixture."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_context_assistance import control
from codex_plugin_scanner.guard.native_resident_client import close_native_resident_clients
from scripts.cigar_benchmark_processes import ProcessSampler
from tests.context_persistence_installed_support import stop_resident


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1", reason="requires the pinned installed runtime"
)
def test_private_native_fixture_closes_new_processes_without_excluding_baseline_rss(native_hook_force, tmp_path):
    guard = tmp_path / "guard"
    guard.mkdir(mode=0o700)
    report = {}
    try:
        with ProcessSampler(Path(sys.executable)) as sampler:
            before, baseline = sampler.sample_with_identities()
            report["before"] = before
            try:
                state = control("status", guard_home=guard)
                assert not state["effective_enabled"] and state["runtime"] is None
            finally:
                stop_resident(native_hook_force, guard)
                assert close_native_resident_clients(guard, deadline_monotonic=time.monotonic() + 10)
            deadline = time.monotonic() + 5
            after, current = sampler.sample_with_identities()
            while current.keys() - baseline.keys() and time.monotonic() < deadline:
                time.sleep(0.1)
                after, current = sampler.sample_with_identities()
            report["after"] = after
            report["new_processes_remaining"] = len(current.keys() - baseline.keys())
            assert report["new_processes_remaining"] == 0
    finally:
        with (tmp_path / "resource-profile.json").open("x") as out:
            json.dump(report, out, indent=2)
