"""Observe native teardown roles without changing the focused benchmark gates."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import bench_guard_cigar_contention as benchmark  # noqa: E402
from scripts.cigar_benchmark_processes import ProcessSampler  # noqa: E402
from scripts.cigar_cleanup_observer import CleanupObserver  # noqa: E402
from scripts.native_slo_contract import clear_proof_environment  # noqa: E402


def install(stack, observer):
    # The benchmark has already selected its private HOME before importing Guard.
    pools = importlib.import_module("codex_plugin_scanner.guard.native_resident_client")
    stream = importlib.import_module("codex_plugin_scanner.guard.native_resident_stream")
    daemon = importlib.import_module("codex_plugin_scanner.guard.daemon.server")
    session = importlib.import_module("scripts.native_slo_session")
    stack.enter_context(
        patch.object(
            stream._PersistentNativeClient, "_start", observer.client_start(stream._PersistentNativeClient._start)
        )
    )
    stack.enter_context(
        patch.object(
            stream._PersistentNativeClient,
            "close",
            observer.observe(stream._PersistentNativeClient.close, "client_close"),
        )
    )
    stack.enter_context(
        patch.object(
            pools._PersistentNativeClientPool,
            "close",
            observer.observe(pools._PersistentNativeClientPool.close, "pool_close"),
        )
    )
    for module in (pools, session):
        original = module.close_native_resident_clients
        stack.enter_context(
            patch.object(module, "close_native_resident_clients", observer.observe(original, "stop_clients"))
        )
    stack.enter_context(
        patch.object(session, "stop_native_resident", observer.observe(session.stop_native_resident, "stop_resident"))
    )
    stack.enter_context(
        patch.object(
            session.AdapterSession,
            "_close",
            observer.observe(session.AdapterSession._close, "session_close", phase="session_close"),
        )
    )
    stack.enter_context(
        patch.object(
            daemon.GuardDaemonServer,
            "stop",
            observer.observe(
                daemon.GuardDaemonServer.stop,
                "daemon_stop",
                after=lambda _args: observer.snapshot("after_daemon_stop", pools),
            ),
        )
    )
    stack.enter_context(
        patch.object(
            benchmark,
            "finish_cleanup",
            observer.observe(
                benchmark.finish_cleanup,
                "finish_cleanup",
                phase="finish_cleanup",
                after=lambda args: observer.snapshot("after_finish_cleanup", pools, args[2]),
            ),
        )
    )

    writer = importlib.import_module("codex_plugin_scanner.guard.native_hook_evidence_writer")
    publisher = importlib.import_module("codex_plugin_scanner.guard.native_policy_snapshot_publisher")
    dispatch = importlib.import_module("codex_plugin_scanner.guard.daemon.hook_evidence_dispatch")
    heartbeat = importlib.import_module("codex_plugin_scanner.guard.daemon.runtime_heartbeat")
    worker = importlib.import_module("codex_plugin_scanner.guard.daemon.hook_worker")
    local_cli = importlib.import_module("codex_plugin_scanner.guard.daemon.local_cli_api")
    components = (
        (daemon._GuardDaemonHTTPServer, "_stop_request_executors", "request_executors_stop"),
        (daemon._GuardDaemonHTTPServer, "stop_unclassified_watchdog", "header_watchdog_stop"),
        (daemon.GuardDaemonServer, "_join_service_background_threads", "service_background_join"),
        (daemon.ApprovalAttentionCoordinator, "stop", "approval_attention_stop"),
        (daemon, "stop_command_queue_worker", "command_queue_stop"),
        (daemon, "stop_cloud_sync_sync_worker", "cloud_sync_stop"),
        (writer.NativeHookEvidenceWriter, "stop", "writer_stop"),
        (publisher.NativePolicySnapshotPublisher, "close_contained", "publisher_close"),
        (dispatch.HookEvidenceDispatch, "stop", "dispatch_stop"),
        (heartbeat.RuntimeHeartbeatWriter, "stop", "heartbeat_stop"),
        (worker.HookWorker, "close_contained", "hook_worker_close"),
        (local_cli.LocalCliApiService, "close_discovery", "discovery_close"),
    )
    for host, method, label in components:
        stack.enter_context(patch.object(host, method, observer.observe(getattr(host, method), label)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("off", "on"), required=True)
    parser.add_argument("--expected-build-sha", required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    installed = runtime.parents[2]
    origin = importlib.util.find_spec("codex_plugin_scanner")
    if origin is None or Path(origin.origin).resolve() != installed / "codex_plugin_scanner/__init__.py":
        raise RuntimeError("cleanup diagnostic requires the selected installed package")
    clear_proof_environment()
    for key in ("HOL_GUARD_HOME", "HOL_GUARD_RESIDENT_TEST_SEAMS", "NATIVE_STOP_DIAGNOSTIC_PATH"):
        os.environ.pop(key, None)
    os.environ["PYTHONPATH"] = os.pathsep.join((str(installed), str(REPO)))
    observer = CleanupObserver(installed, REPO)
    measured = {
        "schema": "guard-cigar-cleanup-diagnostic.v1",
        "mode": args.mode,
        "diagnostic_only": True,
        "not_matched_cohort_qualification": True,
        "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    original_enter = ProcessSampler.__enter__
    installed_observer = False
    with ExitStack() as stack:

        def enter(sampler):
            nonlocal installed_observer
            if installed_observer:
                raise RuntimeError("cleanup diagnostic supports one sampler")
            install(stack, observer)
            installed_observer = True
            return original_enter(sampler)

        stack.enter_context(patch.object(ProcessSampler, "__enter__", enter))
        stack.enter_context(
            patch.object(
                sys,
                "argv",
                [
                    str(REPO / "scripts/bench_guard_cigar_contention.py"),
                    "--runtime",
                    str(runtime),
                    "--root",
                    str(args.root),
                    "--mode",
                    args.mode,
                    "--expected-build-sha",
                    args.expected_build_sha,
                    "--warm-iterations",
                    "200",
                    "--waves",
                    "5",
                ],
            )
        )
        try:
            result = benchmark.main()
            measured["underlying_returncode"] = result
            return result if observer.report()["profile_complete"] else 1
        finally:
            measured["observer"] = observer.report()
            if args.root.is_dir():
                with (args.root / "cleanup-diagnostic.json").open("x") as output:
                    json.dump(measured, output, indent=2)
                    output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
