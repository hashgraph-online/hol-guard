"""Explicit phase timings for the installed focused CIGAR contention workload.

This observer changes scheduling/cost and cannot replace or qualify the frozen
matched cohort. Production authentication, source checks, native policy, SDK
load, deadlines, resource accounting and cleanup remain unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
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
from scripts.cigar_http_phase_observer import PhaseObserver  # noqa: E402
from scripts.native_slo_contract import clear_proof_environment  # noqa: E402


def install(stack, observer, poll_ms=None):
    # Called only after the benchmark creates its private HOME and imports the
    # selected installed Guard. Never import Guard during wrapper bootstrap.
    claude = importlib.import_module("codex_plugin_scanner.guard.adapters._modules.claude.claude_daemon_hook_transport")
    server = importlib.import_module("codex_plugin_scanner.guard.daemon.server")
    if poll_ms is not None:
        stack.enter_context(patch.object(server, "_DAEMON_UNCLASSIFIED_WATCHDOG_POLL_SECONDS", poll_ms / 1000))
    session = importlib.import_module("scripts.native_slo_session")
    client = observer.client(claude.authenticated_claude_hook_response)
    stack.enter_context(patch.object(claude, "authenticated_claude_hook_response", client))
    stack.enter_context(patch.object(session, "authenticated_claude_hook_response", client))
    for name, label in (
        ("_authenticated_state", "state"),
        ("_request_identity_challenge", "client_challenge"),
        ("_verify_challenge_response", "client_verify"),
        ("_read_hook_response", "client_hook_body"),
    ):
        stack.enter_context(patch.object(claude, name, observer.client_phase(getattr(claude, name), label)))
    connection = http.client.HTTPConnection
    stack.enter_context(patch.object(connection, "connect", observer.connect(connection.connect)))
    for name, label in (("request", "send"), ("getresponse", "headers")):
        stack.enter_context(patch.object(connection, name, observer.client_phase(getattr(connection, name), label)))
    handler = server._GuardDaemonHandler
    http_server = server._GuardDaemonHTTPServer
    stack.enter_context(
        patch.object(
            http_server, "_submit_transport_request", observer.server_submit(http_server._submit_transport_request)
        )
    )
    stack.enter_context(
        patch.object(
            http_server, "_process_request_worker", observer.server_worker(http_server._process_request_worker)
        )
    )
    for name, label in (
        ("do_POST", "post"),
        ("_handle_daemon_identity_challenge", "server_challenge"),
        ("_handle_runtime_hook", "server_hook"),
        ("_execute_runtime_hook", "server_execute"),
        ("_handle_runtime_hook_fast", "server_native"),
        ("_settled_hook_directories", "server_directories"),
        ("_write_json", "write"),
    ):
        stack.enter_context(patch.object(handler, name, observer.server_phase(getattr(handler, name), label)))
    for name, label in (
        ("_touch_runtime_heartbeat", "heartbeat"),
        ("_origin_is_allowed_for_request", "origin"),
        ("_header_token_is_valid", "header_auth"),
        ("_load_request_body", "body"),
    ):
        stack.enter_context(patch.object(handler, name, observer.server_context_phase(getattr(handler, name), label)))
    stack.enter_context(
        patch.object(server, "native_route_facts", observer.server_context_phase(server.native_route_facts, "route"))
    )
    stack.enter_context(
        patch.object(
            server,
            "prepare_native_hook_policy",
            observer.server_phase(server.prepare_native_hook_policy, "server_policy"),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("off", "on"), required=True)
    parser.add_argument("--expected-build-sha", required=True)
    parser.add_argument("--watchdog-poll-ms", type=int, choices=(1, 25))
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    installed = runtime.parents[2]
    origin = importlib.util.find_spec("codex_plugin_scanner")
    if origin is None or Path(origin.origin).resolve() != installed / "codex_plugin_scanner/__init__.py":
        raise RuntimeError("HTTP diagnostic must import the selected installed package")
    clear_proof_environment()
    for key in ("HOL_GUARD_HOME", "HOL_GUARD_RESIDENT_TEST_SEAMS", "NATIVE_STOP_DIAGNOSTIC_PATH"):
        os.environ.pop(key, None)
    os.environ["PYTHONPATH"] = os.pathsep.join((str(installed), str(REPO)))
    observer = PhaseObserver()
    measured = {
        "schema": "guard-cigar-http-phase-diagnostic.v1",
        "mode": args.mode,
        "diagnostic_only": True,
        "not_matched_cohort_qualification": True,
        "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "watchdog_poll_ms_intervention": args.watchdog_poll_ms,
    }
    original_enter, original_checkpoint, original_summary = (
        ProcessSampler.__enter__,
        ProcessSampler.checkpoint,
        ProcessSampler.summary,
    )
    installed_observer = False
    with ExitStack() as stack:

        def enter(sampler):
            nonlocal installed_observer
            if installed_observer:
                raise RuntimeError("HTTP diagnostic supports exactly one process sampler")
            install(stack, observer, args.watchdog_poll_ms)
            installed_observer = True
            return original_enter(sampler)

        def checkpoint(sampler):
            observer.checkpoint()
            return original_checkpoint(sampler)

        def summary(sampler, *values, **options):
            result = original_summary(sampler, *values, **options)
            observer.after_summary()
            return result

        arguments = [
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
        ]
        stack.enter_context(patch.object(ProcessSampler, "__enter__", enter))
        stack.enter_context(patch.object(ProcessSampler, "checkpoint", checkpoint))
        stack.enter_context(patch.object(ProcessSampler, "summary", summary))
        stack.enter_context(patch.object(sys, "argv", arguments))
        try:
            result = benchmark.main()
            measured["underlying_returncode"] = result
            report = observer.report()
            serial = report["summaries"].get("http_1", {}).get("requests", 0)
            return result if report["profile_complete"] and serial == 200 else 1
        finally:
            measured["observer"] = observer.report()
            if args.root.is_dir():
                with (args.root / "http-diagnostic.json").open("x") as output:
                    json.dump(measured, output, indent=2)
                    output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
