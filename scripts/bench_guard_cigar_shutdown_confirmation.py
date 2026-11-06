"""Explicit post-join confirmation experiment; never cohort qualification.

One additional lifecycle confirmation may use only the remainder of five
seconds measured from the original daemon Stop entry. All native/request
deadlines and the focused benchmark gates remain unchanged. Persist only
fixed labels, numeric times, booleans and source fingerprints.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
import time
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import bench_guard_cigar_cleanup_diagnostic as diagnostic  # noqa: E402


def main():
    # The delegated parser validates the same fixed runtime/root/mode options.
    root = Path(sys.argv[sys.argv.index("--root") + 1])
    original_install = diagnostic.install
    observations = []

    def install(stack, observer):
        original_install(stack, observer)
        server = importlib.import_module("codex_plugin_scanner.guard.daemon.server")
        original = server.GuardDaemonServer.stop

        def stop(daemon):
            started = time.monotonic()
            result = original(daemon)
            before = getattr(daemon, "_finish_service_completed", False) is True
            remaining = max(0.0, started + 5.0 - time.monotonic())
            attempted = not before and remaining > 0 and daemon._thread is None
            acknowledged = daemon._finish_service() if attempted else None
            elapsed = time.monotonic() - started
            observations.append(
                {
                    "original_finish_completed": before,
                    "serving_thread_joined": daemon._thread is None,
                    "remaining_budget_before_confirmation_ms": remaining * 1000,
                    "attempted": attempted,
                    "acknowledged": acknowledged is True,
                    "final_finish_completed": getattr(daemon, "_finish_service_completed", False) is True,
                    "elapsed_total_ms": elapsed * 1000,
                    "within_five_seconds_from_original_stop": elapsed <= 5.0,
                }
            )
            return result

        stack.enter_context(patch.object(server.GuardDaemonServer, "stop", stop))

    try:
        with patch.object(diagnostic, "install", install):
            outcome = diagnostic.main()
        valid = len(observations) == 1 and all(
            row["attempted"]
            and row["acknowledged"]
            and row["final_finish_completed"]
            and row["serving_thread_joined"]
            and row["within_five_seconds_from_original_stop"]
            for row in observations
        )
        return outcome if valid else 1
    finally:
        if root.is_dir():
            with (root / "shutdown-confirmation.json").open("x") as output:
                json.dump(
                    {
                        "schema": "guard-cigar-post-join-confirmation-diagnostic.v1",
                        "diagnostic_only": True,
                        "not_matched_cohort_qualification": True,
                        "explicit_cleanup_intervention": True,
                        "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "observations": observations,
                    },
                    output,
                    indent=2,
                )
                output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
