"""Record bounded writer counters around the explicit confirmation experiment.

This adds native stats RPCs during cleanup. It is diagnostic instrumentation,
never an installed SLO or matched-cohort qualification.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import bench_guard_cigar_shutdown_confirmation as confirmation  # noqa: E402

COUNTERS = frozenset(
    {
        "queued",
        "queued_bytes",
        "accepted",
        "processed",
        "dropped",
        "failures",
        "recovered",
        "durable_pending",
        "receipt_accepted",
        "receipt_processed",
        "receipt_deduped",
        "receipt_dropped",
        "receipt_failures",
        "receipt_durable_pending",
        "degraded",
        "running",
        "started",
    }
)
STOP_FIELDS = frozenset(
    {
        "status",
        "error",
        "process_outcome",
        "process_returncode",
        "acknowledged",
        "authenticated",
        "generation_present",
        "owner_lock",
        "marker_lock",
        "endpoint",
        "serving_shutdown",
    }
)


def main():
    root = Path(sys.argv[sys.argv.index("--root") + 1])
    original_install = confirmation.diagnostic.install
    observations = []

    def install(stack, observer):
        original_install(stack, observer)
        writer = importlib.import_module("codex_plugin_scanner.guard.native_hook_evidence_writer")
        session = importlib.import_module("scripts.native_slo_session")
        original_stop = writer.NativeHookEvidenceWriter.stop
        native_stop = session.stop_native_resident

        def stats(instance):
            try:
                values = instance.stats()
                return {k: v for k, v in values.items() if k in COUNTERS and type(v) in (int, bool)}
            except Exception:
                return {"stats_unavailable": True}

        def stop(instance, **kwargs):
            before = stats(instance)
            try:
                return original_stop(instance, **kwargs)
            finally:
                observations.append({"kind": "writer_stop", "before": before, "after": stats(instance)})

        def stop_resident(*args, **kwargs):
            result = native_stop(*args, **kwargs)
            observations.append(
                {
                    "kind": "resident_stop",
                    "diagnostic": {k: v for k, v in result.diagnostic.items() if k in STOP_FIELDS},
                }
            )
            return result

        stack.enter_context(patch.object(writer.NativeHookEvidenceWriter, "stop", stop))
        stack.enter_context(patch.object(session, "stop_native_resident", stop_resident))

    try:
        with patch.object(confirmation.diagnostic, "install", install):
            return confirmation.main()
    finally:
        if root.is_dir():
            with (root / "evidence-queue.json").open("x") as output:
                json.dump(
                    {
                        "schema": "guard-cigar-evidence-queue-diagnostic.v1",
                        "diagnostic_only": True,
                        "extra_stats_rpcs_during_cleanup": True,
                        "not_matched_cohort_qualification": True,
                        "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "observations": observations,
                    },
                    output,
                    indent=2,
                )
                output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
