"""Bounded, payload-free SQLite latency profiling."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from typing import TypedDict, final

from .sqlite_errors import sqlite_error_is_busy_locked as sqlite_error_is_busy_locked

_MAX_SAMPLES = 10_000


class SQLiteProfileSnapshot(TypedDict):
    connects: int
    transactions: int
    commits: int
    busy_locked: int
    busy_locked_percent: float
    connect_ms: dict[str, float]
    transaction_ms: dict[str, float]
    commit_ms: dict[str, float]


class SQLiteMigrationGateReport(TypedDict):
    store_p95_percent: float | None
    busy_locked_percent: float
    store_wait_gate_tripped: bool | None
    busy_locked_gate_tripped: bool
    conclusion: str


def _percentiles(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    if not ordered:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}

    def value(percentile: float) -> float:
        index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * percentile) - 1))
        return round(ordered[index], 3)

    return {"p50": value(0.50), "p95": value(0.95), "p99": value(0.99), "max": round(ordered[-1], 3)}


@dataclass(slots=True)
class _Samples:
    connect: list[float]
    transaction: list[float]
    commit: list[float]


@final
class SQLiteProfiler:
    """Collects bounded timings and stable contention counts."""

    def __init__(self, *, max_samples: int = _MAX_SAMPLES) -> None:
        if max_samples < 1:
            raise ValueError("SQLite profiler sample limit must be positive")
        self._max_samples = max_samples
        self._lock = threading.Lock()
        self._samples = _Samples(connect=[], transaction=[], commit=[])
        self._connects = 0
        self._transactions = 0
        self._commits = 0
        self._busy_locked = 0

    def record_connect(self, duration_ms: float) -> None:
        with self._lock:
            self._connects += 1
            self._append(self._samples.connect, duration_ms)

    def record_transaction(self, duration_ms: float) -> None:
        with self._lock:
            self._transactions += 1
            self._append(self._samples.transaction, duration_ms)

    def record_commit(self, duration_ms: float) -> None:
        with self._lock:
            self._commits += 1
            self._append(self._samples.commit, duration_ms)

    def record_busy_locked(self) -> None:
        with self._lock:
            self._busy_locked += 1

    def snapshot(self) -> SQLiteProfileSnapshot:
        with self._lock:
            attempts = max(self._transactions + self._commits, 1)
            return {
                "connects": self._connects,
                "transactions": self._transactions,
                "commits": self._commits,
                "busy_locked": self._busy_locked,
                "busy_locked_percent": round(self._busy_locked * 100 / attempts, 4),
                "connect_ms": _percentiles(self._samples.connect),
                "transaction_ms": _percentiles(self._samples.transaction),
                "commit_ms": _percentiles(self._samples.commit),
            }

    def migration_gate_report(self, *, end_to_end_p95_ms: float | None = None) -> SQLiteMigrationGateReport:
        snapshot = self.snapshot()
        transaction_p95 = snapshot["transaction_ms"]["p95"]
        store_percent = (
            round(transaction_p95 * 100 / end_to_end_p95_ms, 3)
            if end_to_end_p95_ms is not None and end_to_end_p95_ms > 0
            else None
        )
        store_gate = store_percent > 20.0 if store_percent is not None else None
        busy_gate = snapshot["busy_locked_percent"] > 0.1
        if store_gate or busy_gate:
            conclusion = "sqlite_migration_evaluation_required"
        elif store_gate is None:
            conclusion = "insufficient_end_to_end_profile"
        else:
            conclusion = "retain_sqlite_wal"
        return {
            "store_p95_percent": store_percent,
            "busy_locked_percent": snapshot["busy_locked_percent"],
            "store_wait_gate_tripped": store_gate,
            "busy_locked_gate_tripped": busy_gate,
            "conclusion": conclusion,
        }

    def _append(self, samples: list[float], duration_ms: float) -> None:
        if len(samples) < self._max_samples:
            samples.append(max(0.0, duration_ms))


__all__ = [
    "SQLiteMigrationGateReport",
    "SQLiteProfileSnapshot",
    "SQLiteProfiler",
    "sqlite_error_is_busy_locked",
]
