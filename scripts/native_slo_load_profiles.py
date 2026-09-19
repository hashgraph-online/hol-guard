"""Bounded concurrent/offered-rate diagnostics on the isolated daemon tree."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_batch import apply_offered_route_evidence, validate_batch_routes
from scripts.native_slo_capacity import _prime_load_executor, _run_concurrent
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_offered_load import run_offered_load
from scripts.native_slo_qualification import confidence_summary
from scripts.native_slo_resources import ResourceSampler


def measure_load_profiles(
    session: DaemonFixture, routes: tuple[tuple[str, str], ...]
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    concurrent: dict[str, object] = {}
    offered: dict[str, object] = {}
    with ResourceSampler(pid=session.pid) as resources:
        for concurrency in (1, 4, 16, 64):
            metrics = session.daemon._server.hook_worker.metrics
            before = route_counts(metrics.snapshot())
            executor = ThreadPoolExecutor(max_workers=concurrency)
            try:
                _prime_load_executor(executor, concurrency)
                observations, errors = _run_concurrent(
                    SimpleNamespace(observe=session.observe_unattributed), routes, concurrency, executor
                )
            except BaseException:
                executor.shutdown(wait=False, cancel_futures=True)
                raise
            else:
                executor.shutdown(wait=True)
            expected_routes = sum(before.values()) + sum(item.allowed and not item.overloaded for item in observations)
            after = route_counts(wait_for_route_corpus(metrics, expected=max(1, expected_routes)))
            observations, witnessed = validate_batch_routes(observations, before, after)
            concurrent[str(concurrency)] = {
                "route_attribution": "isolated_batch_counter_conservation",
                "routes": witnessed,
                "latency": confidence_summary([item.latency_ms for item in observations]),
                "attempted": concurrency,
                "completed": len(observations),
                "errors": errors,
                "delivered_allowed": sum(item.allowed for item in observations),
                "evaluated_allowed": sum(item.allowed and item.route == "native_resident" for item in observations),
                "overloaded": sum(item.overloaded for item in observations),
                "resident": sum(item.route == "native_resident" for item in observations),
                "tail_qualified": False,
            }
            offered_observations = []
            before = route_counts(metrics.snapshot())
            offered[str(concurrency)] = run_offered_load(
                lambda index: session.observe_unattributed(*routes[index % len(routes)], "1k"),
                rate=float(concurrency * 20),
                duration_seconds=1.0,
                concurrency=concurrency,
                observations_sink=offered_observations,
            )
            expected_routes = sum(before.values()) + sum(
                item.allowed and not item.overloaded for item in offered_observations
            )
            after = route_counts(wait_for_route_corpus(metrics, expected=max(1, expected_routes)))
            apply_offered_route_evidence(offered[str(concurrency)], offered_observations, before, after)
    attempts = sum(report["attempted"] for report in concurrent.values()) + sum(
        report["attempted"] for report in offered.values()
    )
    return concurrent, offered, resources.report(attempted=attempts)
