"""Explicit lower-priority optional workers; never product qualification.

Only verified descendants of this disposable fixture may have their CPU nice
value increased. Native authority, the driver, workloads, gates and deadlines
remain unchanged. No shell, sudo, process-group signal or live profile is used.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import bench_guard_cigar_contention as benchmark  # noqa: E402
from scripts.cigar_benchmark_processes import ProcessSampler, kernel_image  # noqa: E402

NICE_FLOOR = 10


def main():
    root = Path(sys.argv[sys.argv.index("--root") + 1]).resolve()
    binary = Path(sys.argv[sys.argv.index("--runtime") + 1]).resolve(strict=True)
    mode = sys.argv[sys.argv.index("--mode") + 1]
    observations = []
    original_enter = ProcessSampler.__enter__
    installed = False

    with ExitStack() as stack:

        def enter(sampler):
            nonlocal installed
            if installed:
                raise RuntimeError("priority diagnostic permits one fixture")
            assert Path(os.environ["HOME"]) == root / "profile"
            workload = importlib.import_module("scripts.cigar_benchmark_workload")
            faults = importlib.import_module("tests.context_process_fault")
            original_init = workload.ContextWorkload.__init__

            def initialize(instance, *args, **kwargs):
                original_init(instance, *args, **kwargs)
                selection = json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())
                approval = json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text())
                owned = faults.OwnedOptionalProcesses.capture(binary, selection, approval)
                driver_priority = os.getpriority(os.PRIO_PROCESS, os.getpid())
                native_priority = os.getpriority(os.PRIO_PROCESS, owned.native)
                before, after = [], []
                for pid in [owned.bridge, *owned.workers]:
                    rows = faults._snapshot()
                    if any(not row.same(rows.get(member)) for member, row in owned.lineage.items()):
                        raise RuntimeError("owned optional lineage changed before priority mutation")
                    if any(kernel_image(member) != image for member, image in owned.images.items()):
                        raise RuntimeError("owned optional image changed before priority mutation")
                    previous = os.getpriority(os.PRIO_PROCESS, pid)
                    target = max(previous, NICE_FLOOR)
                    os.setpriority(os.PRIO_PROCESS, pid, target)
                    current = os.getpriority(os.PRIO_PROCESS, pid)
                    if current != target:
                        raise RuntimeError("kernel did not confirm optional worker priority")
                    before.append(previous)
                    after.append(current)
                native_unchanged = os.getpriority(os.PRIO_PROCESS, owned.native) == native_priority
                driver_unchanged = os.getpriority(os.PRIO_PROCESS, os.getpid()) == driver_priority
                observations.append(
                    {
                        "verified_optional_processes": len(after),
                        "before_nice": before,
                        "after_nice": after,
                        "native_priority": native_priority,
                        "driver_priority": driver_priority,
                        "native_priority_unchanged": native_unchanged,
                        "driver_priority_unchanged": driver_unchanged,
                        "artifact_and_ancestry_verified": True,
                    }
                )
                assert native_unchanged and driver_unchanged

            stack.enter_context(patch.object(workload.ContextWorkload, "__init__", initialize))
            installed = True
            return original_enter(sampler)

        stack.enter_context(patch.object(ProcessSampler, "__enter__", enter))
        try:
            result = benchmark.main()
            valid = (mode == "off" and not observations) or (
                mode == "on"
                and len(observations) == 1
                and observations[0]["verified_optional_processes"] == 3
                and any(
                    after > before
                    for before, after in zip(observations[0]["before_nice"], observations[0]["after_nice"], strict=True)
                )
            )
            return result if installed and valid else 1
        finally:
            if root.is_dir():
                with (root / "priority-diagnostic.json").open("x") as output:
                    json.dump(
                        {
                            "schema": "guard-cigar-worker-priority-diagnostic.v1",
                            "diagnostic_only": True,
                            "not_product_qualification": True,
                            "explicit_optional_cpu_priority_mutation": mode == "on",
                            "nice_floor": NICE_FLOOR,
                            "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                            "observations": observations,
                        },
                        output,
                        indent=2,
                    )
                    output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
