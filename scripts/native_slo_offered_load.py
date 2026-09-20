"""Bounded offered-rate load with explicit accounting for every scheduled attempt."""

from __future__ import annotations

import math
import queue
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from scripts.native_slo_adapter import Observation
from scripts.native_slo_contract import summarize


@dataclass(frozen=True)
class Attempt:
    outcome: str
    latency_ms: float
    queue_ms: float
    service_ms: float
    observation: Observation | None = None


def run_offered_load(
    observe: Callable[[int], Observation],
    *,
    rate: float,
    duration_seconds: float,
    concurrency: int,
    completion_timeout_seconds: float = 6.0,
    observations_sink: list[Observation] | None = None,
) -> dict[str, object]:
    """Schedule independently of completion, with no unbounded executor queue.

    Full generator capacity is counted as a dropped offered attempt; it is never
    silently replaced by a lower offered rate. Queue and total latency begin at
    the scheduled arrival. Workers are daemon threads and unresolved calls fail
    the run, so a broken observer cannot make shutdown wait indefinitely.
    Observers used with a live daemon must retain their own transport deadline.
    """

    if not 1 <= concurrency <= 64:
        raise ValueError("offered concurrency outside bound")
    if not math.isfinite(rate) or not 0 < rate <= 10_000:
        raise ValueError("offered rate outside bound")
    if not math.isfinite(duration_seconds) or not 0 < duration_seconds <= 3600:
        raise ValueError("offered duration outside bound")
    count = math.ceil(rate * duration_seconds)
    if count > 100_000 or not 0 < completion_timeout_seconds <= 30:
        raise ValueError("offered attempts or deadline outside bound")
    pending: queue.Queue[tuple[int, float] | None] = queue.Queue(maxsize=concurrency)
    completed: dict[int, Attempt] = {}
    lock = threading.Lock()
    ready = threading.Barrier(concurrency + 1, timeout=5.0)

    def worker() -> None:
        ready.wait()
        while True:
            item = pending.get()
            if item is None:
                pending.task_done()
                return
            index, arrival = item
            started = time.perf_counter()
            observation = None
            try:
                observation = observe(index)
                if not isinstance(observation, Observation):
                    raise TypeError("offered observer did not return a measurement")
                outcome = "completed"
            except Exception:
                outcome = "failed"
                observation = None
            finished = time.perf_counter()
            attempt = Attempt(
                outcome,
                (finished - arrival) * 1000,
                (started - arrival) * 1000,
                (finished - started) * 1000,
                observation,
            )
            with lock:
                completed[index] = attempt
            pending.task_done()

    workers = [threading.Thread(target=worker, daemon=True, name="native-slo-load") for _ in range(concurrency)]
    for thread in workers:
        thread.start()
    ready.wait()
    started = time.perf_counter()
    for index in range(count):
        arrival = started + index / rate
        remaining = arrival - time.perf_counter()
        if remaining > 0:
            time.sleep(remaining)
        try:
            pending.put_nowait((index, arrival))
        except queue.Full:
            elapsed = (time.perf_counter() - arrival) * 1000
            with lock:
                completed[index] = Attempt("generator_dropped", elapsed, elapsed, 0.0)
    deadline = time.perf_counter() + completion_timeout_seconds
    while time.perf_counter() < deadline:
        with lock:
            if len(completed) == count:
                break
        time.sleep(0.001)
    finished = time.perf_counter()
    with lock:
        results = [
            completed.get(index, Attempt("timed_out", (finished - started - index / rate) * 1000, 0.0, 0.0))
            for index in range(count)
        ]
    # Queued work that exceeded the run budget is cancelled and accounted above.
    while True:
        try:
            pending.get_nowait()
            pending.task_done()
        except queue.Empty:
            break
    for _ in workers:
        pending.put_nowait(None)
    join_deadline = time.perf_counter() + 0.1
    for thread in workers:
        thread.join(timeout=max(0, join_deadline - time.perf_counter()))
    counts = Counter(item.outcome for item in results)
    observations = [item.observation for item in results if item.observation is not None]
    if observations_sink is not None:
        observations_sink.extend(observations)
    serviced = [item for item in results if item.outcome in {"completed", "failed"}]
    workers_stopped = not any(thread.is_alive() for thread in workers)
    valid_decisions = all(
        (item.allowed and item.route == "native_resident") or (concurrency == 64 and item.overloaded)
        for item in observations
    )
    return {
        "load_model": "offered_rate",
        "offered_per_second": rate,
        "duration_seconds": duration_seconds,
        "concurrency": concurrency,
        "attempted": count,
        "admitted": count - counts["generator_dropped"],
        "completed": counts["completed"],
        "failed": counts["failed"],
        "generator_dropped": counts["generator_dropped"],
        "timed_out": counts["timed_out"],
        "accounted": sum(counts.values()) == count,
        "worker_shutdown_complete": workers_stopped,
        "load_contract_passed": (workers_stopped and counts["completed"] == count and valid_decisions),
        "latency": summarize([item.latency_ms for item in results]),
        "queue": summarize([item.queue_ms for item in serviced]),
        "service": summarize([item.service_ms for item in serviced]),
        "routes": dict(Counter(item.route for item in observations)),
        "delivered_allowed": sum(item.allowed for item in observations),
        "evaluated_allowed": sum(item.allowed and item.route == "native_resident" for item in observations),
        "overloaded": sum(item.overloaded for item in observations),
    }
