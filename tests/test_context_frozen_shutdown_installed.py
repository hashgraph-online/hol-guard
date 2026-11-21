"""Actual frozen foreground shutdown with the optional feature left off."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

from scripts.cigar_benchmark_processes import ProcessSampler
from tests.context_frozen_daemon import FrozenDaemon


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    sys.platform != "darwin" or not os.environ.get("GUARD_CIGAR_TEST_FROZEN_ROOT"),
    reason="requires the exact local macOS frozen bundle",
)
def test_frozen_foreground_sigint_is_graceful_without_optional_workers(tmp_path: Path) -> None:
    executable = Path(os.environ["GUARD_CIGAR_TEST_FROZEN_ROOT"]) / "hol-guard"
    root = tmp_path.resolve()
    guard, profile, temporary, project = (root / name for name in ("guard", "profile", "tmp", "project"))
    for path in (guard, profile, temporary, project):
        path.mkdir(mode=0o700)
    environment = {
        "HOME": str(profile),
        "TMPDIR": str(temporary),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        "LANG": "en_US.UTF-8",
    }
    report = {
        "schema": "guard-cigar-frozen-foreground-shutdown.v1",
        "completed": False,
        "entry_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "application_environment_keys": sorted(environment),
        "CIGAR_enrollment_or_activation_requested": False,
    }
    with ProcessSampler(Path(sys.executable)) as sampler:
        _, baseline = sampler.sample_with_identities()
        daemon = FrozenDaemon(executable, root, guard, project, environment)
        try:
            try:
                daemon.wait_ready()
                report["public_health_ready"] = True
            finally:
                try:
                    daemon.stop()
                finally:
                    report["daemon_exit"] = daemon.exit_metadata()
                    deadline = time.monotonic() + 5
                    _, remaining = sampler.sample_with_identities()
                    while remaining.keys() - baseline.keys() and time.monotonic() < deadline:
                        time.sleep(0.05)
                        _, remaining = sampler.sample_with_identities()
                    report["new_processes_remaining"] = len(remaining.keys() - baseline.keys())
                    report["resources"] = sampler.summary()
            assert report["daemon_exit"]["graceful_zero_exit"] and not daemon.fallback_used
            assert report["daemon_exit"]["requested_signal"] == "SIGINT"
            assert report["daemon_exit"]["exception_types"] == []
            assert report["new_processes_remaining"] == report["resources"]["sampling_errors"] == 0
            maximum = report["resources"]["maximum_counts"]
            assert maximum.get("native_runtime", 0) >= 1
            assert maximum.get("sdk_worker", 0) == maximum.get("python_bridge", 0) == 0
            report["completed"] = True
        finally:
            with (root / "frozen-shutdown-report.json").open("x") as output:
                json.dump(report, output, indent=2)
                output.write("\n")
