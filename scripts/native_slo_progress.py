"""Bounded progress and failure accounting for the installed SLO proof."""

from __future__ import annotations

import http.client
import math
from collections.abc import Mapping
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field, replace
from threading import RLock
from typing import TYPE_CHECKING

from scripts.native_slo_contract import (
    MAX_COLD_P95_MS,
    MAX_INSTALLED_ADAPTER_P95_MS,
    MAX_INSTALLED_ADAPTER_P99_MS,
    MAX_READINESS_P95_MS,
    SAFE_EVENT_NAMES,
    SAFE_FAILURE_STAGE_NAMES,
    SAFE_FAILURE_WAVE_NAMES,
    SAFE_HARNESS_NAMES,
    SAFE_SIZE_CLASS_NAMES,
    SLO_SCHEMA,
    assert_privacy_safe,
    gate_results,
    summarize,
)

if TYPE_CHECKING:
    from scripts.native_slo_adapter import Observation


@dataclass
class SloProgressStage:
    """Counters for one bounded benchmark stage."""

    planned: int | None = None
    submitted: int = 0
    started: int = 0
    attempted: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    skipped: bool = False

    def snapshot(self) -> dict[str, object]:
        missing = None if self.planned is None else max(0, self.planned - self.completed - self.failed - self.cancelled)
        return {
            "planned": self.planned,
            "submitted": self.submitted,
            "started": self.started,
            "attempted": self.attempted,
            "completed": self.completed,
            "failed": self.failed,
            "cancelled": self.cancelled,
            "missing": missing,
            "skipped": self.skipped,
        }


_OBSERVATION_PROGRESS_STAGES = frozenset({"warm", "size_250k", "size_1m", "size_5m", "concurrent_16", "concurrent_64"})


def classify_benchmark_error(error: BaseException) -> str:
    """Map failures to bounded categories without retaining exception text."""

    chain: list[BaseException] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(chain) < 8:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__

    if any(
        isinstance(item, (TimeoutError, FutureTimeoutError)) or type(item).__name__ == "TimeoutExpired"
        for item in chain
    ):
        return "transport_timeout"
    # A typed HTTP/transport cause takes precedence over a wrapper such as
    # ``adapter request failed``.  This keeps loopback status-line failures in
    # the incomplete transport bucket while preserving a cause-less status
    # wrapper as response_status.
    if any(isinstance(item, (ConnectionError, http.client.HTTPException)) for item in chain):
        return "transport_error"
    if any(isinstance(item, OSError) for item in chain):
        return "environment_error"

    # Only the exact built-in RuntimeError with one bounded built-in string
    # argument can carry one of the canonical internal categories.  In
    # particular, do not call ``str(item)``: custom exception formatters may
    # execute arbitrary code or raise while the CLI is constructing its safe
    # failed artifact.
    canonical_messages = tuple(
        item.args[0]
        for item in chain
        if type(item) is RuntimeError and len(item.args) == 1 and type(item.args[0]) is str and len(item.args[0]) <= 256
    )
    if any(
        message
        in {
            "concurrent capacity wave timed out",
            "native_installed_slo_failed: concurrent capacity wave timed out",
        }
        for message in canonical_messages
    ):
        return "capacity_wave_timeout"
    if "adapter response exceeded bound" in canonical_messages:
        return "response_oversize"
    if any(
        message in {"adapter response was not JSON", "adapter response was not an object"}
        or message == "native_installed_slo_failed: adapter response was not an object"
        for message in canonical_messages
    ):
        return "response_invalid"
    if "adapter request failed" in canonical_messages:
        return "response_status"
    if any(message.startswith("native_installed_slo_failed:") for message in canonical_messages):
        return "benchmark_contract"
    return "benchmark_internal_failure"


@dataclass
class SloProgress:
    """Thread-safe aggregate-only progress for a run that may fail early."""

    stages: dict[str, SloProgressStage] = field(default_factory=dict)
    routes: tuple[tuple[str, str], ...] | None = None
    runtime_summary: dict[str, object] | None = None
    installed_corpus: dict[str, int] | None = None
    active_stage: str | None = None
    active_labels: dict[str, str] = field(default_factory=dict)
    failure: dict[str, object] | None = None
    timings: dict[str, dict[str, list[float]]] = field(default_factory=dict)
    _warm_iterations: int = field(default=0, init=False, repr=False, compare=False)
    _lock: RLock = field(default_factory=RLock, repr=False)

    def configure_invocation(
        self,
        *,
        warm_iterations: int,
        cold_iterations: int,
        recovery_iterations: int,
        readiness_samples: int,
        include_capacity: bool,
    ) -> None:
        """Plan invocation-known work before cleanup, status, or route discovery."""

        with self._lock:
            self._warm_iterations = warm_iterations
            for stage in ("cleanup", "runtime", "routes"):
                self._plan(stage, 1)
            self._plan("cold", cold_iterations)
            self._plan("recovery_precondition", recovery_iterations)
            self._plan("recovery_stop", recovery_iterations)
            self._plan("recovery", recovery_iterations)
            self._plan("readiness", readiness_samples)
            self._plan("capacity_stabilization", 1)
            self._plan("capacity_prewarm", 16 if include_capacity else 0, skipped=not include_capacity)
            self._plan("capacity_prewarm_ready", 1 if include_capacity else 0, skipped=not include_capacity)
            self._plan("concurrent_16", 16 if include_capacity else 0, skipped=not include_capacity)
            self._plan("concurrent_64", 64 if include_capacity else 0, skipped=not include_capacity)
            self._plan("rss_baseline", 1)
            self._plan("rss_baseline_requests", None)
            # Route-dependent denominators are intentionally unknown until the
            # validated route contract has been read.
            for name in ("installed_corpus", "installed_corpus_routes", "warm_precondition", "warm"):
                self._plan(name, None)
            for size_class in ("250k", "1m", "5m"):
                self._plan(f"size_{size_class}", None)
            self._plan("serialized_warmup", None)

    def configure_routes(self, routes: tuple[tuple[str, str], ...]) -> None:
        """Fill route-dependent denominators after route discovery succeeds."""

        post_routes = sum(event == "PostToolUse" for _, event in routes)
        selected_size_routes = post_routes or (1 if routes else 0)
        with self._lock:
            self.routes = routes
            self._plan("installed_corpus", 1)
            self._plan("installed_corpus_routes", len(routes))
            self._plan("warm_precondition", len(routes))
            # The invocation plan stores iterations separately so a repeated
            # route configuration cannot manufacture a denominator.
            iterations = getattr(self, "_warm_iterations", 0)
            self._plan("warm", len(routes) * iterations)
            for size_class in ("250k", "1m", "5m"):
                self._plan(f"size_{size_class}", selected_size_routes)
            self._plan("serialized_warmup", 1)

    def configure(
        self,
        routes: tuple[tuple[str, str], ...],
        *,
        warm_iterations: int,
        cold_iterations: int,
        recovery_iterations: int,
        readiness_samples: int,
        include_capacity: bool,
    ) -> None:
        """Compatibility helper for callers that already know the routes."""

        self._warm_iterations = warm_iterations
        self.configure_invocation(
            warm_iterations=warm_iterations,
            cold_iterations=cold_iterations,
            recovery_iterations=recovery_iterations,
            readiness_samples=readiness_samples,
            include_capacity=include_capacity,
        )
        self.configure_routes(routes)

    def set_warm_iterations(self, iterations: int) -> None:
        with self._lock:
            self._warm_iterations = iterations
            if self.routes is not None:
                self._plan("warm", len(self.routes) * iterations)

    def _plan(self, name: str, planned: int | None, *, skipped: bool = False) -> None:
        current = self.stages.get(name)
        if current is None:
            self.stages[name] = SloProgressStage(planned=planned, skipped=skipped)
        else:
            current.planned = planned
            current.skipped = skipped

    def activate(self, stage: str, **labels: str) -> None:
        with self._lock:
            self.active_stage = stage if stage in SAFE_FAILURE_STAGE_NAMES else "unknown"
            self.active_labels = {key: value for key, value in labels.items() if isinstance(value, str)}

    def plan_operation(self, stage: str) -> None:
        with self._lock:
            if stage not in self.stages or self.stages[stage].planned is None:
                self._plan(stage, 1)

    def _counter(self, stage: str) -> SloProgressStage:
        return self.stages.setdefault(stage, SloProgressStage())

    def submit(self, stage: str, count: int = 1) -> None:
        with self._lock:
            self._counter(stage).submitted += max(0, count)

    def attempt(self, stage: str, count: int = 1) -> None:
        with self._lock:
            current = self._counter(stage)
            count = max(0, count)
            current.started += count
            current.attempted += count

    def complete(self, stage: str, count: int = 1) -> None:
        with self._lock:
            self._counter(stage).completed += max(0, count)

    def fail_request(self, stage: str, count: int = 1) -> None:
        with self._lock:
            self._counter(stage).failed += max(0, count)

    def cancel(self, stage: str, count: int = 1) -> None:
        with self._lock:
            self._counter(stage).cancelled += max(0, count)

    def record_timing(
        self,
        stage: str,
        adapter_ms: float | None,
        enclosing_ms: float | None,
    ) -> None:
        with self._lock:
            values = self.timings.setdefault(stage, {"adapter": [], "enclosing": []})
            for name, value in (("adapter", adapter_ms), ("enclosing", enclosing_ms)):
                if value is None:
                    continue
                value = float(value)
                if math.isfinite(value) and value >= 0 and len(values[name]) < 512:
                    values[name].append(value)

    def record_observation(self, stage: str, observation: Observation, *, enclosing_ms: float | None = None) -> None:
        adapter_ms = getattr(observation, "latency_ms", None)
        explicit_enclosing = getattr(observation, "enclosing_latency_ms", None)
        self.record_timing(stage, adapter_ms, enclosing_ms if enclosing_ms is not None else explicit_enclosing)

    def record_failure(
        self,
        error: BaseException,
        *,
        stage: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> None:
        with self._lock:
            if self.failure is not None:
                return
            selected_stage = stage or self.active_stage or "unknown"
            selected_labels = dict(self.active_labels if labels is None else labels)
            failure: dict[str, object] = {
                "stage": selected_stage if selected_stage in SAFE_FAILURE_STAGE_NAMES else "unknown",
                "category": classify_benchmark_error(error),
            }
            allowlists = {
                "harness": SAFE_HARNESS_NAMES,
                "event": SAFE_EVENT_NAMES,
                "size_class": SAFE_SIZE_CLASS_NAMES,
                "wave": SAFE_FAILURE_WAVE_NAMES,
            }
            for key, allowed in allowlists.items():
                value = selected_labels.get(key)
                if isinstance(value, str):
                    failure[key] = value if value in allowed else "unknown"
            self.failure = failure

    def frozen_copy(self) -> SloProgress:
        """Capture one report boundary while requests may still be running."""
        with self._lock:
            snapshot = SloProgress(
                stages={name: replace(stage) for name, stage in self.stages.items()},
                routes=self.routes,
                runtime_summary=None if self.runtime_summary is None else dict(self.runtime_summary),
                installed_corpus=None if self.installed_corpus is None else dict(self.installed_corpus),
                active_stage=self.active_stage,
                active_labels=dict(self.active_labels),
                failure=None if self.failure is None else dict(self.failure),
                timings={
                    stage: {name: list(samples) for name, samples in values.items()}
                    for stage, values in self.timings.items()
                },
            )
            snapshot._warm_iterations = self._warm_iterations
            return snapshot

    def stage_snapshot(self) -> dict[str, dict[str, object]]:
        with self._lock:
            return {name: stage.snapshot() for name, stage in sorted(self.stages.items())}

    def completed_observations(self) -> int:
        with self._lock:
            return sum(self.stages.get(name, SloProgressStage()).completed for name in _OBSERVATION_PROGRESS_STAGES)

    def observation_snapshot(self) -> dict[str, object]:
        with self._lock:
            stages = [self.stages.get(name, SloProgressStage()) for name in _OBSERVATION_PROGRESS_STAGES]
            planned_values = [stage.planned for stage in stages]
            planned = (
                sum(value for value in planned_values if value is not None)
                if all(value is not None for value in planned_values)
                else None
            )
            completed = sum(stage.completed for stage in stages)
            failed = sum(stage.failed for stage in stages)
            cancelled = sum(stage.cancelled for stage in stages)
            return {
                "planned": planned,
                "submitted": sum(stage.submitted for stage in stages),
                "started": sum(stage.started for stage in stages),
                "attempted": sum(stage.attempted for stage in stages),
                "completed": completed,
                "failed": failed,
                "cancelled": cancelled,
                "missing": None if planned is None else max(0, planned - completed - failed - cancelled),
            }

    def completed_error_count(self, stage: str) -> int | None:
        with self._lock:
            current = self.stages.get(stage)
            if current is None or current.planned in (None, 0):
                return None
            if current.cancelled or current.completed + current.failed < current.planned:
                return None
            return current.failed

    def timing_snapshot(self) -> dict[str, object] | None:
        with self._lock:
            output: dict[str, object] = {}
            for stage, values in sorted(self.timings.items()):
                stage_output = {name: summarize(samples) if samples else None for name, samples in values.items()}
                if any(value is not None for value in stage_output.values()):
                    output[stage] = stage_output
            return output or None

    def snapshot_failure(self) -> dict[str, object]:
        with self._lock:
            return dict(
                self.failure or {"stage": self.active_stage or "unknown", "category": "benchmark_internal_failure"}
            )


def incomplete_slo_result(progress: SloProgress, *, include_capacity: bool) -> dict[str, object]:
    """Render a failed run with explicit unknown and incomplete accounting."""

    progress = progress.frozen_copy()
    gate_seed = gate_results(
        resident_share=0.0,
        safe_fail_rate=1.0,
        warm_p95_ms=float("inf"),
        size_p95_ms={},
        cold_p95_ms=float("inf"),
        readiness_p95_ms=float("inf"),
        concurrent_p99_ms=float("inf"),
        rss_growth=1.0,
        rss_baseline_bytes=0,
        errors=1,
        errors_64=1,
        python_fallback_decisions=1,
        installed_python_fallback_decisions=1,
    )
    gates = {name: False for name in gate_seed}
    gates.update({"recovery_latency": False, "concurrency_64_bounded": False, "installed_corpus": False})
    stages = progress.stage_snapshot()
    observations = progress.observation_snapshot()
    routes = progress.routes
    route_count = len(routes) if routes is not None else None
    harness_count = len({harness for harness, _ in routes}) if routes is not None else None
    errors_16 = progress.completed_error_count("concurrent_16")
    errors_64 = progress.completed_error_count("concurrent_64")
    result: dict[str, object] = {
        "schema": SLO_SCHEMA,
        "scope": "installed_adapter_to_decision",
        "status": "failed",
        "complete": False,
        "evaluation": "incomplete",
        "runtime": progress.runtime_summary,
        "routes": None if routes is None else {"declared": route_count},
        "corpus": {
            "harnesses": harness_count,
            "routes": route_count,
            "observations": observations["completed"],
            "planned": observations["planned"],
            "submitted": observations["submitted"],
            "started": observations["started"],
            "attempted": observations["attempted"],
            "completed": observations["completed"],
            "failed": observations["failed"],
            "cancelled": observations["cancelled"],
            "missing": observations["missing"],
            "corpus_origin": "installed_wheel_ownership_contract",
            "route_corpus": "installed_routes",
            "safe_failures": None,
            "security_denials": None,
            "safe_failure_rate": None,
            "fail_safe_decisions": None,
            "fail_safe_rate": None,
            "resident_share": None,
            "python_fallback_decisions": None,
            "python_semantic_decisions": None,
            "oneshot_decisions": None,
            "rss_baseline_bytes": None,
            "rss_peak_bytes": None,
            "rss_growth": None,
            "installed": progress.installed_corpus,
            "denominators": stages,
        },
        "failure": progress.snapshot_failure(),
        "errors_16": errors_16,
        "errors_64": errors_64,
        "latency": {
            "warm_all_harnesses": None,
            "warm_by_event": {},
            "size_classes": {},
            "cold_native_oneshot": None,
            "resident_recovery": None,
            "readiness": None,
        },
        "timing": progress.timing_snapshot(),
        "thresholds": {
            "installed_adapter_p95_ms": MAX_INSTALLED_ADAPTER_P95_MS,
            "installed_adapter_concurrent_p99_ms": MAX_INSTALLED_ADAPTER_P99_MS,
            "direct_cold_p95_ms": MAX_COLD_P95_MS,
            "readiness_p95_ms": MAX_READINESS_P95_MS,
        },
        "concurrency": {
            "sixteen": {
                "latency": None,
                "errors": errors_16,
                "overloaded": None,
                "deadline_ms": MAX_INSTALLED_ADAPTER_P99_MS,
                "denominators": stages.get("concurrent_16"),
            },
            "sixty_four": {
                "latency": None,
                "errors": errors_64,
                "overloaded": None,
                "fail_safe": None,
                "latency_ceiling_ms": None,
                "bounded": False,
                "denominators": stages.get("concurrent_64"),
            },
            "skipped": not include_capacity,
        },
        "gates": gates,
        "passed": False,
    }
    return assert_privacy_safe(result)


__all__ = [
    "SloProgress",
    "SloProgressStage",
    "classify_benchmark_error",
    "incomplete_slo_result",
]
