"""Profile context-thread elapsed costs and total CPU; never qualification."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
import sysconfig
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import bench_guard_cigar_contention as benchmark  # noqa: E402
from scripts.cigar_benchmark_processes import ProcessSampler  # noqa: E402
from scripts.cigar_thread_profile import ThreadProfile  # noqa: E402

SAMPLE_EVERY = 16


def main():
    root = Path(sys.argv[sys.argv.index("--root") + 1]).resolve()
    mode = sys.argv[sys.argv.index("--mode") + 1]
    runtime = Path(sys.argv[sys.argv.index("--runtime") + 1]).resolve(strict=True)
    observations = []
    original_enter = ProcessSampler.__enter__
    installed = False
    with ExitStack() as stack:

        def enter(sampler):
            nonlocal installed
            if installed:
                raise RuntimeError("CPU diagnostic permits one fixture")
            workload = importlib.import_module("scripts.cigar_benchmark_workload")
            original = workload.ContextWorkload._run
            original_compile = workload.ContextWorkload.compile

            def compile_context(instance):
                if not hasattr(instance, "_context_profile"):
                    return original_compile(instance)  # Preserve the initial main-thread retrieval check.
                instance._context_profile_calls += 1
                if instance._context_profile_calls % SAMPLE_EVERY == 0:
                    return instance._context_profile.call(original_compile, instance)
                return original_compile(instance)

            def run(instance):
                profiler = ThreadProfile()
                instance._context_profile = profiler
                instance._context_profile_calls = 0
                started, cpu_started = time.monotonic(), time.thread_time()
                try:
                    return original(instance)
                finally:
                    cpu, elapsed = time.thread_time() - cpu_started, time.monotonic() - started
                    observations.append(
                        {
                            "thread_cpu_seconds": cpu,
                            "thread_elapsed_seconds": elapsed,
                            "successful_context_compiles": instance.successes,
                            "profile": profiler.summary(
                                {
                                    "installed": runtime.parents[2],
                                    "tooling": REPO,
                                    "dependencies": Path(sysconfig.get_path("purelib")),
                                    "stdlib": Path(sysconfig.get_path("stdlib")),
                                },
                            ),
                        }
                    )

            stack.enter_context(patch.object(workload.ContextWorkload, "_run", run))
            stack.enter_context(patch.object(workload.ContextWorkload, "compile", compile_context))
            installed = True
            return original_enter(sampler)

        stack.enter_context(patch.object(ProcessSampler, "__enter__", enter))
        try:
            result = benchmark.main()
            valid = (mode == "off" and not observations) or (
                mode == "on" and len(observations) == 1 and observations[0]["profile"]["profile_complete"]
            )
            return result if installed and valid else 1
        finally:
            if root.is_dir():
                with (root / "context-cpu.json").open("x") as output:
                    json.dump(
                        {
                            "schema": "guard-cigar-context-thread-profile-diagnostic.v2",
                            "diagnostic_only": True,
                            "not_product_qualification": True,
                            "instrumentation_changes_workload_timing": True,
                            "profile_hook": "thread-specific sys.setprofile, Python call/return only",
                            "profile_clocks": ["time.monotonic_ns", "time.thread_time_ns"],
                            "sample_every_nth_compile": SAMPLE_EVERY,
                            "separate_total_cpu_clock": "time.thread_time",
                            "scope": "context load thread only",
                            "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                            "observations": observations,
                        },
                        output,
                        indent=2,
                    )
                    output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
