"""Bounded offered load with an immutable terminal result for every attempt."""

from __future__ import annotations

import hashlib
import json
import math
import os
import queue
import threading
import time
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.native_slo_contract import summarize
from scripts.native_slo_mixed_request import fixture_request
from scripts.native_slo_mixed_response import delivered_decision
from scripts.native_slo_mixed_witness import MAX_ATTEMPTS
from scripts.native_slo_session import _is_explicit_capacity_response


@dataclass(frozen=True)
class MixedPlan:
    duration_seconds: float = 30.0
    rate: float = 20.0
    concurrency: int = 16
    mutations: int = 4
    restarts: int = 1
    inventory_batches: int = 3
    completion_seconds: float = 10.0

    def __post_init__(self) -> None:
        if any(
            type(value) is not int
            for value in (self.concurrency, self.mutations, self.restarts, self.inventory_batches)
        ):
            raise ValueError("mixed counts must be integers")
        if not math.isfinite(self.duration_seconds) or not 0 < self.duration_seconds <= 3600:
            raise ValueError("mixed duration outside bound")
        if not math.isfinite(self.rate) or not 0 < self.rate <= 10_000:
            raise ValueError("mixed rate outside bound")
        if not 1 <= self.attempts <= MAX_ATTEMPTS or not 1 <= self.concurrency <= 64:
            raise ValueError("mixed offered work outside bound")
        if not 0 < self.completion_seconds <= 30:
            raise ValueError("mixed completion deadline outside bound")
        if not (2 <= self.mutations <= 16 and 1 <= self.restarts <= 8 and 1 <= self.inventory_batches <= 16):
            raise ValueError("mixed scenario coverage outside bound")

    @property
    def attempts(self) -> int:
        return math.ceil(self.duration_seconds * self.rate)


class PrivateLedger:
    """Append each offer and outcome immediately to a fresh private bounded file."""

    def __init__(self, path: Path) -> None:
        self._lock = threading.Lock()
        self._digest = hashlib.sha256()
        self.rows = self.bytes = 0
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._stream = os.fdopen(descriptor, "wb", buffering=0)

    def write(self, row: Mapping[str, Any]) -> None:
        encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
        if len(encoded) > 8192:
            raise ValueError("mixed ledger record outside bound")
        with self._lock:
            if self.rows >= 350_000 or self.bytes + len(encoded) > 256 * 1024 * 1024:
                raise ValueError("mixed ledger capacity exceeded")
            pending = memoryview(encoded)
            while pending:
                written = self._stream.write(pending)
                if written is None or written <= 0:
                    raise OSError("mixed ledger write made no progress")
                pending = pending[written:]
            self._digest.update(encoded)
            self.rows += 1
            self.bytes += len(encoded)

    def finish(self) -> dict[str, object]:
        with self._lock:
            try:
                self._stream.flush()
                os.fsync(self._stream.fileno())
            finally:
                self._stream.close()
            return {"records": self.rows, "bytes": self.bytes, "sha256": self._digest.hexdigest()}


class MixedLoad:
    def __init__(
        self,
        plan: MixedPlan,
        request: Callable[[str, Mapping[str, object]], tuple[Mapping[str, object], float]],
        ledger: PrivateLedger,
    ) -> None:
        self.plan, self.request, self.ledger = plan, request, ledger
        self.started = 0.0
        self._lock = threading.Lock()
        self._pending: queue.Queue[int] = queue.Queue(maxsize=plan.concurrency)
        self._stop = threading.Event()
        self._offering_done = threading.Event()
        self._rows: dict[int, dict[str, Any]] = {}
        self._threads: list[threading.Thread] = []
        self._errors: Counter[str] = Counter()
        self.late_completions = 0

    def start(self) -> None:
        self.started = time.monotonic()
        self._threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.plan.concurrency)]
        self._threads.append(threading.Thread(target=self._offer, daemon=True))
        for thread in self._threads:
            thread.start()

    def _record(self, record: Mapping[str, Any]) -> None:
        try:
            self.ledger.write(record)
        except (OSError, ValueError):
            # Preserve in-memory terminal accounting and surface failed private
            # retention; a full disk must never silently discard attempted work.
            self._errors["ledger_write_failure"] += 1

    def _offer(self) -> None:
        try:
            for index in range(self.plan.attempts):
                delay = self.started + index / self.plan.rate - time.monotonic()
                if delay > 0:
                    self._stop.wait(delay)
                with self._lock:
                    row = {
                        "attempt": f"mixed-load-{index}",
                        "offered_ms": index / self.plan.rate * 1000,
                        "generator_offered_ms": (time.monotonic() - self.started) * 1000,
                        "state": "queued",
                    }
                    self._rows[index] = row
                    self._record({"kind": "offer", **row})
                    if self._stop.is_set():
                        self._terminal(index, "generator_cancelled")
                        continue
                    try:
                        self._pending.put_nowait(index)
                    except queue.Full:
                        self._terminal(index, "generator_rejected")
        finally:
            self._offering_done.set()

    def _terminal(self, index: int, state: str, **fields: Any) -> None:
        """Caller owns lock. A late worker cannot overwrite a deadline result."""
        row = self._rows[index]
        if row["state"] not in {"queued", "dispatched"}:
            self.late_completions += 1
            self._record(
                {
                    "kind": "late_completion",
                    "attempt": row["attempt"],
                    "late_state": state,
                    "finished_ms": (time.monotonic() - self.started) * 1000,
                    **fields,
                }
            )
            return
        row.update(state=state, finished_ms=(time.monotonic() - self.started) * 1000, **fields)
        self._record({"kind": "terminal", **row})

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                index = self._pending.get(timeout=0.05)
            except queue.Empty:
                if self._offering_done.is_set():
                    return
                continue
            try:
                with self._lock:
                    row = self._rows[index]
                    if row["state"] != "queued" or self._stop.is_set():
                        continue
                    row.update(state="dispatched", dispatched_ms=(time.monotonic() - self.started) * 1000)
                harness = "claude-code" if index % 2 else "codex"
                event = "PostToolUse" if index % 3 == 0 else "PreToolUse"
                size = "250k" if event == "PostToolUse" and index % 2 == 0 else "1k"
                request = fixture_request(harness, event, size, attempt=f"mixed-load-{index}")
                try:
                    response, latency = self.request(harness, request)
                    if not math.isfinite(latency) or latency < 0:
                        raise ValueError("mixed request latency invalid")
                    result = {
                        "harness": harness,
                        "event": event,
                        "size": size,
                        "latency_ms": latency,
                        "allowed": delivered_decision(event, response) == "allow",
                        "delivered_decision": delivered_decision(event, response),
                        "delivered_action": response.get("policy_action")
                        if response.get("policy_action") in ("allow", "warn", "block")
                        else None,
                        "capacity_rejected": _is_explicit_capacity_response(response),
                    }
                    with self._lock:
                        self._terminal(index, "completed", **result)
                except Exception as error:
                    with self._lock:
                        self._terminal(index, "transport_failed", failure_type=type(error).__name__)
            finally:
                self._pending.task_done()

    def finish(self) -> dict[str, object]:
        deadline = self.started + self.plan.duration_seconds + self.plan.completion_seconds
        for thread in reversed(self._threads):
            thread.join(max(0, deadline - time.monotonic()))
        self._stop.set()
        # Offer generation is finite and its sleep is interruptible. It still
        # emits cancelled terminal results for every planned, unoffered index.
        self._threads[-1].join(timeout=1)
        with self._lock:
            for index, row in self._rows.items():
                if row["state"] in {"queued", "dispatched"}:
                    self._terminal(index, "completion_timeout")
            rows = [dict(row) for row in self._rows.values()]
            states = Counter(row["state"] for row in rows)
            latencies = [row["latency_ms"] for row in rows if row["state"] == "completed"]
            offered = [row["finished_ms"] - row["offered_ms"] for row in rows if row["state"] == "completed"]
            waits = [row["dispatched_ms"] - row["offered_ms"] for row in rows if "dispatched_ms" in row]
            return {
                "offered": len(rows),
                "planned": self.plan.attempts,
                "generator_admitted": len(rows) - states["generator_rejected"] - states["generator_cancelled"],
                "completed": states["completed"],
                "transport_failed": states["transport_failed"],
                "completion_timeout": states["completion_timeout"],
                "generator_rejected": states["generator_rejected"],
                "generator_cancelled": states["generator_cancelled"],
                "capacity_rejected": sum(row.get("capacity_rejected") is True for row in rows),
                "allowed": sum(row.get("allowed") is True for row in rows),
                "denied": sum(
                    row.get("delivered_decision") == "deny" and not row.get("capacity_rejected") for row in rows
                ),
                "response_contract_invalid": sum(
                    row["state"] == "completed"
                    and row.get("delivered_decision") is None
                    and not row.get("capacity_rejected")
                    for row in rows
                ),
                "request_latency": summarize(latencies) if latencies else None,
                "offered_latency": summarize(offered) if offered else None,
                "generator_wait": summarize(waits) if waits else None,
                "accounting_complete": len(rows) == self.plan.attempts and sum(states.values()) == self.plan.attempts,
                "workers_unfinished": sum(thread.is_alive() for thread in self._threads),
                "late_completions": self.late_completions,
                "errors": dict(self._errors),
            }

    def row(self, index: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._rows.get(index)
            return dict(row) if row is not None else None
