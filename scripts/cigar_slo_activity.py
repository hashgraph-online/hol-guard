"""Explicit fixture-owned CIGAR activity around the unchanged installed SLO."""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from functools import partial
from pathlib import Path

from codex_plugin_scanner.guard.native_context_assistance import ContextAssistanceError, control, workspace
from scripts.cigar_benchmark_workload import ContextWorkload, activate, configure
from scripts.native_slo_session import AdapterSession

_LOAD_PHASES = {"installed_corpus", "warm", "sizes", "capacity"}
_PHASES = _LOAD_PHASES | {"cold_precondition", "recovery_precondition", "readiness"}


class _ObservedSession(AdapterSession):
    def __init__(self, runtime: Path, *, on_cleanup, **kwargs):
        super().__init__(runtime, **kwargs)
        self._on_cleanup = on_cleanup

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._on_cleanup(
                getattr(self, "final_stop_diagnostic", None),
                getattr(self, "last_stop_diagnostic", None),
                getattr(self, "recovery_cleanup", None),
                daemon_stop_contained=getattr(self, "daemon_stop_contained", False),
            )


class CigarSloActivity:
    def __init__(
        self, runtime: Path, *, enabled: bool, sampler, settle_seconds: int = 5, diagnostics_dir: Path | None = None
    ) -> None:
        if type(settle_seconds) is not int or not 0 <= settle_seconds <= 30:
            raise ValueError("fixture settling interval is outside its bounded range")
        self.runtime, self.enabled, self.sampler = runtime, enabled, sampler
        self.settle_seconds = settle_seconds
        self.scopes: dict[Path, str] = {}
        self.phases: list[dict] = []
        self.restarts: list[dict] = []
        self.activation_ms: list[float] = []
        self.diagnostics_dir = diagnostics_dir
        self.session_count = 0
        self.cleanups: list[dict] = []
        self.rss_reads: list[dict] = []
        if diagnostics_dir is not None:
            diagnostics_dir.mkdir(mode=0o700)
            os.environ["NATIVE_STOP_DIAGNOSTIC_PATH"] = str(diagnostics_dir / "stop-corpus.json")

    def record_rss(self, aggregate: dict[str, int]) -> None:
        if len(self.rss_reads) >= 512:
            raise RuntimeError("context SLO RSS diagnostic budget exceeded")
        self.rss_reads.append({"phase": self.phases[-1]["phase"] if self.phases else "startup", **aggregate})

    def prepare(self, guard: Path, workspace_path: Path) -> None:
        # Both callers create fresh private fixtures. This is explicit native
        # enrollment/settings setup, never a live installation or default mode.
        if not guard.is_dir() or not workspace_path.is_dir():
            raise RuntimeError("context SLO preparation needs an existing private fixture")
        configure(self.runtime, guard, self.enabled)

    def session(self, runtime: Path) -> AdapterSession:
        if runtime != self.runtime:
            raise RuntimeError("context SLO session selected a different artifact")
        self.session_count += 1
        options = {}
        if self.diagnostics_dir is not None:
            options["diagnostics_dir"] = self.diagnostics_dir / f"session-{self.session_count}"
            os.environ["NATIVE_STOP_DIAGNOSTIC_PATH"] = str(
                self.diagnostics_dir / f"stop-session-{self.session_count}.json"
            )
        session = _ObservedSession(
            runtime, on_cleanup=partial(self.contained, f"session_{self.session_count}"), **options
        )
        try:
            self.prepare(session.guard_home, session.workspace)
        except BaseException:
            session.close()
            raise
        return session

    def contained(
        self,
        label: str,
        final: dict | None,
        prior: dict | None = None,
        recovery: dict | None = None,
        *,
        daemon_stop_contained: bool | None = None,
    ) -> None:
        if len(self.cleanups) >= 8:
            raise RuntimeError("context SLO containment record budget exceeded")
        row = {
            "fixture": label,
            "final_contained": final is not None and final.get("status") in {"contained", "already-stopped"},
        }
        if daemon_stop_contained is not None:
            row["daemon_stop_contained"] = daemon_stop_contained
            row["final_contained"] = row["final_contained"] and daemon_stop_contained
        if prior is not None and prior.get("status") in {"failed", "contained_client_cleanup_failed"}:
            row["earlier_stop_failed"] = True
            if prior.get("process_outcome") in {"timed_out", "launch_failed", "exited"}:
                row["earlier_process_outcome"] = prior["process_outcome"]
        if recovery is not None:
            row["recovery_cleanup"] = recovery
        self.cleanups.append(row)

    @contextmanager
    def background(self, label: str, guard: Path, workspace_path: Path):
        if label not in _PHASES or len(self.phases) >= 32:
            raise RuntimeError("context SLO phase budget exceeded")
        state = control("status", guard_home=guard)
        if state["requested_enabled"] is not self.enabled:
            raise RuntimeError("context SLO preferences differ from the selected variant")
        workload = None
        row = {"phase": label, "completed": False}
        self.phases.append(row)
        try:
            if self.enabled:
                if not state["effective_enabled"]:
                    self.scopes.pop(guard, None)
                    self.activation_ms.append(activate(guard))
                workload = ContextWorkload(
                    guard, workspace_path, latency_sample_every=8, reuse_scope=self.scopes.get(guard)
                )
                self.scopes[guard] = workload.scope
                workload.start()
            elif state["effective_enabled"] or state["runtime"] is not None:
                raise RuntimeError("off context SLO unexpectedly retained an optional runtime")
            if label in _LOAD_PHASES:
                time.sleep(self.settle_seconds)
            self.sampler.sample()
            mark = self.sampler.checkpoint() - 1
            before = workload.successes if workload is not None else 0
            started = time.perf_counter()
            try:
                yield
                row["hook_interval_completed"] = True
            finally:
                row["measured_interval_ms"] = round((time.perf_counter() - started) * 1000, 3)
                row["successful_overlapping_compiles"] = workload.successes - before if workload else 0
                self.sampler.sample()
                row["observed_tree_memory"] = self.sampler.summary(mark)
        finally:
            if workload is not None:
                row["context_workload"] = workload.close()
        state = control("status", guard_home=guard)
        row["effective_at_end"] = state["effective_enabled"]
        if self.enabled:
            if not state["effective_enabled"] or not state["execution_ready"]:
                raise RuntimeError("context SLO lost its verified runtime during the phase")
            if row["context_workload"]["refusals"]:
                raise RuntimeError("context SLO workload returned refusals")
            if label in _LOAD_PHASES and row["successful_overlapping_compiles"] == 0:
                raise RuntimeError("context SLO phase has no actual compilation overlap")
        elif state["runtime"] is not None:
            raise RuntimeError("off context SLO started an optional runtime")
        row["completed"] = True

    def after_restart(self, label: str, guard: Path, workspace_path: Path) -> None:
        del workspace_path
        if label not in {"cold", "recovery"} or len(self.restarts) >= 16:
            raise RuntimeError("context SLO restart budget exceeded")
        state = control("status", guard_home=guard)
        if state["requested_enabled"] is not self.enabled:
            raise RuntimeError("native restart changed the saved context preference")
        if state["effective_enabled"] or state["runtime"] is not None or state["execution_ready"]:
            raise RuntimeError("native restart restored optional runtime authority")
        old_scope = self.scopes.pop(guard, None)
        refused = old_scope is None
        if old_scope is not None:
            try:
                workspace(
                    "workspace",
                    guard_home=guard,
                    payload={
                        "action": "compile",
                        "scope_id": old_scope,
                        "query": "reviewed release procedure",
                    },
                )
            except ContextAssistanceError as error:
                if error.code not in {
                    "native_context_assistance_runtime_not_verified",
                    "native_context_assistance_disabled",
                }:
                    raise RuntimeError("old scope returned an unexpected restart outcome") from None
                refused = True
        if not refused:
            raise RuntimeError("native restart restored an old source scope")
        self.restarts.append({"phase": label, "runtime_absent": True, "old_scope_refused": refused})

    def summary(self) -> dict:
        expected = {
            "installed_corpus": 1,
            "warm": 1,
            "sizes": 1,
            "capacity": 1,
            "cold_precondition": 3,
            "recovery_precondition": 3,
            "readiness": 2,
        }
        from collections import Counter

        counts = Counter(row["phase"] for row in self.phases)
        observed = self.sampler.summary()["maximum_counts"]
        coverage = (
            observed.get("sdk_worker", 0) >= 2 and observed.get("python_bridge", 0) >= 1
            if self.enabled
            else not any(
                observed.get(kind, 0)
                for kind in ("sdk_worker", "python_bridge", "selected_python", "other_python_child")
            )
        )
        return {
            "mode": "on" if self.enabled else "off",
            "settle_seconds_per_load_phase": self.settle_seconds,
            "cold_and_recovery": (
                "real opt-in active before containment; native timed recovery restores no CIGAR authority"
            ),
            "native_readiness": "measured before explicit SDK activation; SDK activation is separately reported",
            "activation_ms": self.activation_ms,
            "phases": self.phases,
            "restarts": self.restarts,
            "fixture_containment": self.cleanups,
            "canonical_rss_reads": self.rss_reads,
            "gates": {
                "complete_declared_activity_phases": counts == expected,
                "all_activity_intervals_completed": all(row["completed"] for row in self.phases),
                "all_six_restarts_restore_no_optional_authority": len(self.restarts) == 6,
                "process_sampling_complete": self.sampler.errors == 0,
                "canonical_rss_observed_without_root_fallback": len(self.rss_reads) >= 5,
                "optional_worker_coverage": coverage,
                "all_five_private_fixtures_finally_contained": len(self.cleanups) == 5
                and all(row["final_contained"] for row in self.cleanups),
            },
        }
