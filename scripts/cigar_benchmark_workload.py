"""Explicit local-candidate setup and bounded real native context workload."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path

from codex_plugin_scanner.guard.native_context_assistance import ContextAssistanceError, control, workspace
from scripts.native_slo_contract import summarize


def configure(runtime: Path, guard: Path, enabled: bool) -> None:
    def operator(command: str, value: dict) -> dict:
        result = subprocess.run(
            [str(runtime), command, "--stdin"], input=json.dumps(value), capture_output=True, text=True, timeout=60
        )
        if result.returncode:
            raise RuntimeError("native benchmark setup command failed")
        data = json.loads(result.stdout)
        if data.get("ok") is not True:
            raise RuntimeError("native benchmark setup was refused")
        return data

    if enabled:
        operator(
            "context-assistance-enroll-local",
            {
                "schema": "guard-cigar-enroll-local.v1",
                "guard_home": str(guard),
                "runtime_id": "benchmark-candidate",
                "local_candidate_approved": True,
                "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
                "selection": json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text()),
                "approval": json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text()),
            },
        )
    operator(
        "guard-config-update",
        {
            "schema": "guard-config-update.v1",
            "guard_home": str(guard),
            "kind": "settings",
            "value_text": json.dumps(
                {
                    "context_assistance": {
                        "enabled": enabled,
                        "runtime_id": "benchmark-candidate" if enabled else "",
                        "features": {"execution_context": enabled, "agent_context": False, "shared_agents": False},
                        "sources": {
                            "workspace_documents": True,
                            "sanitized_receipt_facts": False,
                            "source_set_id": "benchmark-synthetic-documents",
                        },
                    }
                }
            ),
        },
    )


def activate(guard: Path) -> float:
    started = time.perf_counter()
    control("activate", guard_home=guard)
    deadline = time.monotonic() + 90
    while True:
        state = control("status", guard_home=guard)
        if state["job"] is None:
            if not state["effective_enabled"] or not state["execution_ready"]:
                raise RuntimeError("actual candidate benchmark activation failed")
            if state["runtime"]["interpreter"]["version"][:2] != [3, 14]:
                raise RuntimeError("benchmark selected an ineligible interpreter")
            return (time.perf_counter() - started) * 1000
        if time.monotonic() >= deadline:
            raise RuntimeError("candidate verification exceeded benchmark deadline")
        time.sleep(0.05)


class ContextWorkload:
    def __init__(
        self, guard: Path, project: Path, *, latency_sample_every: int = 1, reuse_scope: str | None = None
    ) -> None:
        if type(latency_sample_every) is not int or not 1 <= latency_sample_every <= 16:
            raise ValueError("latency sampling interval exceeds the bounded workload profile")
        self.latency_sample_every = latency_sample_every
        self.guard = guard
        if reuse_scope is None:
            (project / "README.md").write_text(
                "Synthetic benchmark workspace uses a reviewed release procedure.\n" * 32
            )
            self.scope = workspace(
                "workspace_grant",
                guard_home=guard,
                payload={"action": "grant", "workspace": str(project), "app": "dashboard", "sources": ["README.md"]},
            )["result"]["scope_id"]
        else:
            self.scope = reuse_scope
        self.latencies: list[float] = []
        self.revisions: set[int] = set()
        self.failures: Counter[str] = Counter()
        self.successes = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="cigar-compile-load", daemon=True)

    def compile(self) -> None:
        start = time.perf_counter()
        result = workspace(
            "workspace",
            guard_home=self.guard,
            payload={"action": "compile", "scope_id": self.scope, "query": "reviewed release procedure"},
        )["result"]
        brief = result["brief"]
        if not result["current"] or not brief["data_role"] or not brief["citations"]:
            raise RuntimeError("actual SDK workload returned unqualified context")
        if "Synthetic benchmark workspace" not in brief["rendered"]:
            raise RuntimeError("context workload did not retrieve its selected fixture")
        self.revisions.add(brief["graph_revision"])
        if self.successes % self.latency_sample_every == 0:
            if len(self.latencies) >= 8192:
                raise RuntimeError("context workload sample budget exhausted")
            self.latencies.append((time.perf_counter() - start) * 1000)
        self.successes += 1

    def start(self) -> None:
        self.compile()  # Prove real selected-file retrieval before measuring contention.
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.compile()
            except ContextAssistanceError as error:
                self.failures[error.code] += 1
            except Exception:
                self.failures["benchmark_workload_invalid"] += 1
                return
            self._stop.wait(0.01)

    def close(self) -> dict:
        self._stop.set()
        if self._thread.ident is not None:
            self._thread.join(timeout=12)
        if self._thread.is_alive():
            raise RuntimeError("bounded context workload did not stop")
        return {
            "successful_compiles": self.successes,
            "latency": summarize(self.latencies),
            "latency_sample_every": self.latency_sample_every,
            "refusals": dict(self.failures),
            "distinct_graph_revisions": len(self.revisions),
            "unchanged_graph_revision_reused": len(self.revisions) == 1,
            "internal_tokenization_work_measured": False,
        }
