"""Opt-in Python phase/work attribution for an isolated diagnostic daemon.

No production module imports this helper. Timings include instrumentation and
must never enter headline SLO samples. Arguments, bodies, paths and digests are
not retained. Unobserved native/OS/VFS work is not represented by a zero.
"""

from __future__ import annotations

import contextvars
import functools
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch
from urllib.parse import urlparse

from scripts.native_slo_adapter import route_matrix
from scripts.native_slo_contract import summarize
from scripts.native_slo_phase_io import install_io_probes
from scripts.native_slo_phase_waits import install_wait_probes

_MAX_SAMPLES_PER_SPAN = 100_000
_MAX_TOTAL_SAMPLES = 100_000
_MAX_SERIES = 512
_ROUTE = contextvars.ContextVar[tuple[str, str] | None]("native_benchmark_route", default=None)
_INSTALL_LOCK = threading.Lock()


class PhaseProfiler:
    """Measure callable boundaries; never infer a substage by subtraction."""

    def __init__(self) -> None:
        self._stack = ExitStack()
        self._lock = threading.Lock()
        self._samples: dict[tuple[str, str, str], list[float]] = {}
        self._outcomes: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
        self._all_outcomes: Counter[str] = Counter()
        self._work: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
        self._discarded_samples = 0
        self._discarded_series_updates = 0
        self._total_samples = 0
        self._active = False
        self._allowed = frozenset(route_matrix())
        self._harnesses = frozenset(pair[0] for pair in self._allowed)

    def _admit_key(self, key: tuple[str, str, str]) -> bool:
        if key in self._samples:
            return True
        if len(self._samples) >= _MAX_SERIES:
            self._discarded_series_updates += 1
            return False
        self._samples[key] = []
        return True

    def _record(self, name: str, elapsed_ms: float, route: tuple[str, str], outcome: str = "observed") -> None:
        with self._lock:
            self._all_outcomes[outcome] += 1
            key = (*route, name)
            if not self._admit_key(key):
                self._discarded_samples += 1
                return
            self._outcomes[key][outcome] += 1
            values = self._samples[key]
            if len(values) < _MAX_SAMPLES_PER_SPAN and self._total_samples < _MAX_TOTAL_SAMPLES:
                values.append(elapsed_ms)
                self._total_samples += 1
            else:
                self._discarded_samples += 1

    def duration(self, name: str, elapsed_ms: float) -> None:
        route = _ROUTE.get()
        if route is not None:
            self._record(name, elapsed_ms, route)

    def work(self, name: str, unit: str, count: int) -> None:
        route = _ROUTE.get()
        if route is None or type(count) is not int or count < 0:
            return
        with self._lock:
            key = (*route, name)
            if self._admit_key(key):
                self._work[key][unit] += count

    def call(self, function: Callable[..., Any], name: str, *args: Any, **kwargs: Any) -> Any:
        route = _ROUTE.get()
        if route is None:
            return function(*args, **kwargs)
        started = time.perf_counter()
        outcome = "raised"
        try:
            result = function(*args, **kwargs)
            outcome = (
                "returned_none"
                if result is None
                else "returned_false"
                if result is False
                else "returned_true"
                if result is True
                else "returned_value"
            )
            return result
        finally:
            self._record(name, (time.perf_counter() - started) * 1000, route, outcome)

    def reader_call(self, function: Callable[..., Any], name: str, *args: Any, **kwargs: Any) -> Any:
        token = _ROUTE.set(("unattributed", "native_stream_reader"))
        try:
            if len(args) > 1 and isinstance(args[1], bytes):
                self.work(name, "attempted_header_bytes", len(args[1]))
            return self.call(function, name, *args, **kwargs)
        finally:
            _ROUTE.reset(token)

    def _wrap(self, function: Callable[..., Any], name: str, *, root: bool = False) -> Callable[..., Any]:
        @functools.wraps(function)
        def measured(*args: Any, **kwargs: Any) -> Any:
            token = None
            if root:
                payload = args[1] if len(args) > 1 else kwargs.get("payload")
                harness = kwargs.get("default_harness")
                event = payload.get("hook_event_name") if isinstance(payload, dict) else None
                pair = (str(harness), str(event))
                token = _ROUTE.set(pair if pair in self._allowed else ("other", "other"))
            try:
                return self.call(function, name, *args, **kwargs)
            finally:
                if token is not None:
                    _ROUTE.reset(token)

        return measured

    def _http_root(self, function: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(function)
        def measured(handler: Any) -> Any:
            parts = [part for part in urlparse(handler.path).path.split("/") if part]
            if len(parts) != 3 or parts[:2] != ["v1", "hooks"]:
                return function(handler)
            harness = parts[2] if parts[2] in self._harnesses else "other"
            # Input parsing precedes a trusted event. Do not parse again to
            # invent attribution; keep transport failures in this bucket too.
            token = _ROUTE.set((harness, "transport_unclassified"))
            try:
                return self.call(function, "http_post_inclusive", handler)
            finally:
                _ROUTE.reset(token)

        return measured

    def __enter__(self) -> PhaseProfiler:
        if self._active or not _INSTALL_LOCK.acquire(blocking=False):
            raise RuntimeError("phase instrumentation is already active in this process")
        self._active = True
        try:
            from codex_plugin_scanner.guard import config, native_hook_edge, native_runtime
            from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
            from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

            targets = (
                (_GuardDaemonHandler, "_handle_runtime_hook", "daemon_hook_inclusive", True),
                (native_runtime, "_validate_binary", "runtime_identity_including_hash", False),
                (config, "load_guard_config", "config_lookup", False),
                (native_hook_edge, "_decode_edge", "response_decode_validate", False),
                (native_hook_edge, "native_resident_client_request", "native_client_inclusive", False),
                (RuntimeHookEvidenceWriter, "submit_command_activity", "activity_submission", False),
                (RuntimeHookEvidenceWriter, "submit_native_decision_receipt", "receipt_submission", False),
            )
            for owner, name, label, root in targets:
                self._stack.enter_context(patch.object(owner, name, self._wrap(getattr(owner, name), label, root=root)))
            self._stack.enter_context(
                patch.object(_GuardDaemonHandler, "do_POST", self._http_root(_GuardDaemonHandler.do_POST))
            )
            install_wait_probes(self._stack, self)
            install_io_probes(self._stack, self)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_args: object) -> None:
        try:
            self._stack.close()
        finally:
            if self._active:
                self._active = False
                _INSTALL_LOCK.release()

    def report(self) -> dict[str, object]:
        with self._lock:
            return {
                "schema": "hol-guard-python-phase-diagnostics.v2",
                "scope": "diagnostic_instrumented_run",
                "span_semantics": "inclusive_do_not_sum",
                "headline_timing_eligible": False,
                "by_route": {
                    f"{harness}.{event}": {
                        phase: {
                            **(summarize(values) if values else {"count": 0, "timing": "not_retained"}),
                            "outcomes": dict(self._outcomes[key]),
                            "work": dict(self._work[key]),
                        }
                        for key, values in sorted(self._samples.items())
                        for candidate_harness, candidate_event, phase in [key]
                        if (candidate_harness, candidate_event) == (harness, event)
                    }
                    for harness, event in sorted({key[:2] for key in self._samples})
                },
                "discarded_samples": self._discarded_samples,
                "discarded_series_updates": self._discarded_series_updates,
                "all_span_outcomes_including_discarded_series": dict(self._all_outcomes),
                "bounds": {"series": _MAX_SERIES, "total_timing_samples": _MAX_TOTAL_SAMPLES},
                "separate_hash_only": "sha256_callable_only_in_runtime_and_runtime_manifest_modules",
                "separate_queue_only": "scheduler_admitted_timestamps_and_scoped_condition_waits",
                "native_connection_only": "not_measured_rust_owned",
                "native_evaluation_only": "not_measured_rust_owned",
                "inbound_json_only": "daemon_and_edge_json_loads_callables",
                "not_measured": [
                    "os_read_write_syscalls_and_physical_disk_bytes",
                    "sqlite_vfs_reads_writes_busy_wait_and_locks",
                    "rust_socket_connect_authentication_and_evaluation",
                    "rust_timeout_protocol_shutdown_parse_and_edge_allocations",
                    "python_utf8_encoding_and_frame_body_copy_time_in_isolation",
                    "background_receipt_persistence_and_native_receipt_construction",
                    "hashing_outside_the_two_instrumented_runtime_modules",
                ],
                "attribution_notes": [
                    "missing_phase_means_not_observed_not_zero_cost",
                    "returned_none_false_true_value_and_raised_are_callable_outcomes_not_policy_decisions",
                    "condition_wait_includes_mutex_reacquisition_and_may_repeat_per_request",
                    "unadmitted_queue_span_ends_at_acquire_return_not_exact_dequeue",
                    "client_response_wait_includes_native_work_transport_and_reader_delivery",
                    "http_transport_has_no_event_until_hook_dispatch_reader_headers_are_unattributed",
                    "byte_counts_are_boundary_work_and_overlap_do_not_sum_as_unique_bytes_or_allocations",
                    "frame_write_false_has_unknown_partial_bytes_http_write_exceptions_may_also_be_partial",
                    "receipt_submission_success_does_not_prove_unique_enqueue_or_durable_persistence",
                ],
            }
