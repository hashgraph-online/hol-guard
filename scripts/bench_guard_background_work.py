#!/usr/bin/env python3
"""Compare isolated submission and policy work with a trusted repository revision.

This diagnostic does not qualify installed hook latency. Persistence is paused
for submission measurements; SQLite and journal changes have separate fault and
batching tests. Only synthetic aggregate observations are exported.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore


def _baseline_module(ref: str, path: str, name: str) -> types.ModuleType:
    # Explicit developer benchmark input: execute the pinned, trusted source in
    # its original package, sharing this environment's locked dependencies.
    source = subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True)
    module = types.ModuleType(name)
    module.__package__ = name.rsplit(".", 1)[0]
    sys.modules[name] = module
    exec(compile(source, f"{ref}:{path}", "exec"), module.__dict__)
    return module


def _summary(values: list[float]) -> dict[str, float | int]:
    ordered = sorted(values)
    return {
        "samples": len(values),
        "p50_ms": statistics.median(ordered),
        "p95_ms": ordered[math.ceil(len(ordered) * 0.95) - 1],
    }


def _receipt_fixture() -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "request_id": "synthetic-receipt",
        "request_digest": "a" * 64,
        "harness": "pi",
        "event_name": "PostToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": "b" * 64,
        "rule_digest": "c" * 64,
        "runtime_identity": "d" * 64,
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "native_clean_output",
        "workspace_bound": False,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 750,
    }
    identity = {
        "schema": "guard-native-hook-decision-identity.v1",
        "version": 1,
        **{key: value for key, value in receipt.items() if key not in {"schema", "version", "authority"}},
    }
    receipt["decision_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return receipt


def _paired_samples(baseline: object, candidate: object, samples: int) -> dict[str, object]:
    elapsed = {"baseline": [], "candidate": []}
    cpu = {"baseline": [], "candidate": []}
    for index in range(samples + 3):
        arms = (("baseline", baseline), ("candidate", candidate))
        if index % 2:
            arms = arms[::-1]
        for name, callback in arms:
            assert callable(callback)
            started_cpu, started = time.process_time_ns(), time.perf_counter_ns()
            callback()
            duration = (time.perf_counter_ns() - started) / 1e6
            cpu_duration = (time.process_time_ns() - started_cpu) / 1e6
            if index >= 3:
                elapsed[name].append(duration)
                cpu[name].append(cpu_duration)
    return {name: {"wall": _summary(elapsed[name]), "cpu": _summary(cpu[name])} for name in elapsed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", default="2e672d2d950c6ec471005ddba46e49bba16dc23b")
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 10 <= args.samples <= 1_000:
        parser.error("--samples must be between 10 and 1000")
    baseline_writer = _baseline_module(
        args.baseline_ref,
        "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py",
        "codex_plugin_scanner.guard.daemon._benchmark_baseline_writer",
    ).RuntimeHookEvidenceWriter
    baseline_inputs = _baseline_module(
        args.baseline_ref,
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py",
        "codex_plugin_scanner.guard._benchmark_baseline_policy_inputs",
    ).NativePolicySnapshotPublisherInputs

    class BaselinePublisher(NativePolicySnapshotPublisher):
        _compiled_effective_policy = baseline_inputs._compiled_effective_policy

    report: dict[str, object] = {
        "schema": "guard-background-work-diagnostic.v1",
        "qualification": False,
        "baseline_ref": args.baseline_ref,
        "candidate_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "candidate_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], text=True)),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "power_mode": "uncontrolled shared worker",
        "python": platform.python_version(),
        "boundaries": {
            "EVIDENCE_SUBMISSION": "memory acceptance only; persistence paused; excludes decision/HTTP/launcher",
            "POLICY_COMPILATION": "one managed-authority pass plus home/workspace projection and merge",
        },
        "order": "alternating baseline/candidate; 3 warmups per arm",
    }
    with tempfile.TemporaryDirectory(prefix="guard-background-bench-") as temporary:
        root = Path(temporary)
        store = GuardStore(root / "guard-home")
        writers = []
        for implementation in (baseline_writer, RuntimeHookEvidenceWriter):
            with patch.object(implementation, "_run", lambda _self: None):
                writers.append(implementation(store=store, max_bytes=32 * 1024 * 1024))
        submissions = []
        try:
            for size in (1_024, 16_384, 262_144, 1_048_576, 5_242_880, 16_777_216):
                payload = {"command": "echo safe", "tool_call_id": "synthetic-attempt", "output": "x" * size}

                def submit(writer: object, payload: dict[str, object] = payload) -> None:
                    assert writer.submit_command_activity(
                        harness="pi", event="PostToolUse", payload=payload, succeeded=True
                    )
                    with writer._condition:
                        writer._records.clear()
                        writer._queued_bytes = 0

                submissions.append(
                    {
                        "synthetic_output_bytes": size,
                        **_paired_samples(lambda: submit(writers[0]), lambda: submit(writers[1]), args.samples),
                    }
                )
            report["submission"] = submissions
            receipt = _receipt_fixture()

            def submit_receipt(writer: object) -> None:
                assert writer.submit_native_decision_receipt(receipt)
                with writer._condition:
                    writer._records.clear()
                    writer._receipt_seen.clear()
                    writer._queued_bytes = 0

            report["native_receipt_validation_and_admission"] = _paired_samples(
                lambda: submit_receipt(writers[0]), lambda: submit_receipt(writers[1]), args.samples
            )
            for writer in writers:
                writer._max_records = 1
                assert writer.submit_native_decision_receipt(receipt)
            maximum_payload = {"command": "echo safe", "output": "x" * 16_777_216}

            def reject_command(writer: object) -> None:
                assert not writer.submit_command_activity(
                    harness="pi", event="PostToolUse", payload=maximum_payload, succeeded=True
                )

            report["queue_rejected_submission_16_mib"] = _paired_samples(
                lambda: reject_command(writers[0]), lambda: reject_command(writers[1]), args.samples
            )
        finally:
            for writer in writers:
                writer.stop()
        compilation = []
        for count in (1, 10, 100):
            baseline, candidate = BaselinePublisher(store=store), NativePolicySnapshotPublisher(store=store)
            try:
                for index in range(count):
                    workspace = root / f"workspace-{index}"
                    workspace.mkdir(exist_ok=True)
                    (workspace / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
                    baseline.register_workspace(workspace)
                    candidate.register_workspace(workspace)
                baseline_policy = baseline._compiled_effective_policy()
                started = time.perf_counter_ns()
                candidate_policy = candidate._compiled_effective_policy()
                cold_ms = (time.perf_counter_ns() - started) / 1e6
                assert baseline_policy == candidate_policy, "policy parity failed"
                compilation.append(
                    {
                        "workspaces": count,
                        "candidate_first_compilation_ms": cold_ms,
                        **_paired_samples(
                            baseline._compiled_effective_policy, candidate._compiled_effective_policy, args.samples
                        ),
                    }
                )
            finally:
                baseline.close()
                candidate.close()
        report["policy_compilation"] = compilation
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "qualification": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
