"""Bounded, content-free wall/thread-CPU timing for an owned HTTP diagnostic.

Connect addresses exist only in memory to associate the two ends of one local
connection. Never retain arguments, results, headers, credentials or addresses
in the report. Every wrapper calls the original implementation unchanged.
"""

from __future__ import annotations

import math
import statistics
import threading
import time
from collections import Counter
from functools import wraps

CLIENT_COMPONENTS = (
    "client_state_initial",
    "client_challenge",
    "client_verify",
    "client_state_recheck",
    "client_hook_send",
    "client_hook_headers",
    "client_hook_body",
)
LABELS = frozenset(
    (
        *CLIENT_COMPONENTS,
        "client_state_extra",
        "wire_connect",
        "wire_challenge_send",
        "wire_challenge_headers",
        "server_challenge",
        "server_hook",
        "server_execute",
        "server_native",
        "server_directories",
        "server_policy",
        "server_identity_write",
        "server_hook_write",
    )
)
STAGES = ("startup", "rss_baseline", "http_1", "http_16", "http_64", "direct")
POST_SEGMENTS = frozenset({"route", "heartbeat", "origin", "header_auth", "body"})
LABELS |= frozenset(
    f"server_{kind}_{part}" for kind in ("identity", "hook", "other") for part in (*POST_SEGMENTS, "post")
)


def distribution(values):
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {
        "count": len(values),
        "mean_ms": statistics.mean(values) / 1e6,
        "p50_ms": ordered[math.ceil(len(ordered) * 0.5) - 1] / 1e6,
        "p95_ms": ordered[math.ceil(len(ordered) * 0.95) - 1] / 1e6,
        "max_ms": ordered[-1] / 1e6,
    }


def summaries(rows):
    result = {}
    for stage in STAGES:
        selected = [row for row in rows if row["stage"] == stage]
        if not selected:
            continue
        successful = [row for row in selected if row["outcome"] == "returned"]
        tail = sorted(successful, key=lambda row: row["total"]["wall_ns"], reverse=True)[
            : max(1, math.ceil(len(successful) * 0.05))
        ]
        phases = {label for row in selected for label in row["phases"]}
        result[stage] = {
            "requests": len(selected),
            "raised": len(selected) - len(successful),
            "total_wall": distribution([row["total"]["wall_ns"] for row in selected]),
            "total_thread_cpu": distribution([row["total"]["cpu_ns"] for row in selected]),
            "phases": {
                label: {
                    kind: distribution(
                        [sample[kind + "_ns"] for row in selected for sample in row["phases"].get(label, [])]
                    )
                    for kind in ("wall", "cpu")
                }
                for label in sorted(phases)
            },
            "tail_requests": len(tail),
            "tail_mean_total_wall_ms": statistics.mean(row["total"]["wall_ns"] for row in tail) / 1e6 if tail else None,
            "tail_mean_client_components_ms": {
                label: statistics.mean(
                    sum(sample["wall_ns"] for sample in row["phases"].get(label, [])) for row in tail
                )
                / 1e6
                for label in CLIENT_COMPONENTS
            }
            if tail
            else {},
            "tail_mean_other_client_wall_ms": statistics.mean(
                row["total"]["wall_ns"]
                - sum(sample["wall_ns"] for label in CLIENT_COMPONENTS for sample in row["phases"].get(label, []))
                for row in tail
            )
            / 1e6
            if tail
            else None,
        }
    return result


class PhaseObserver:
    def __init__(self, *, maximum_requests=4096):
        self.maximum_requests = maximum_requests
        self.lock = threading.RLock()
        self.local = threading.local()
        self.server_local = threading.local()
        self.rows = []
        self.links = {}
        self.stage = "startup"
        self.checkpoints = 0
        self.dropped = Counter()

    @staticmethod
    def start():
        return time.perf_counter_ns(), time.thread_time_ns()

    @staticmethod
    def elapsed(start):
        cpu = time.thread_time_ns() - start[1]
        wall = time.perf_counter_ns() - start[0]
        return {"wall_ns": wall, "cpu_ns": cpu}

    def add(self, row, label, elapsed):
        if row is None:
            return
        assert label in LABELS
        with self.lock:
            samples = row["phases"].setdefault(label, [])
            if len(samples) >= 16:
                self.dropped["phase_samples"] += 1
            else:
                samples.append(elapsed)

    def client(self, original):
        @wraps(original)
        def wrapped(*args, **kwargs):
            if getattr(self.local, "row", None) is not None:
                return original(*args, **kwargs)
            with self.lock:
                if len(self.rows) >= self.maximum_requests:
                    self.dropped["requests"] += 1
                    row = None
                else:
                    row = {"ordinal": len(self.rows), "stage": self.stage, "outcome": "raised", "phases": {}}
                    self.rows.append(row)
            if row is None:
                return original(*args, **kwargs)
            self.local.row, self.local.state_calls, self.local.in_challenge = row, 0, False
            self.local.connections = []
            started = self.start()
            try:
                result = original(*args, **kwargs)
                row["outcome"] = "returned"
                return result
            finally:
                row["total"] = self.elapsed(started)
                with self.lock:
                    for key in self.local.connections:
                        if self.links.get(key) is row:
                            del self.links[key]
                self.local.row = None
                self.local.connections = []

        return wrapped

    def connect(self, original):
        @wraps(original)
        def wrapped(connection, *args, **kwargs):
            row = getattr(self.local, "row", None)
            if row is None:
                return original(connection, *args, **kwargs)
            started = self.start()
            try:
                result = original(connection, *args, **kwargs)
                if connection.sock is not None:
                    key = connection.sock.getsockname()
                    with self.lock:
                        previous = self.links.get(key)
                        if previous is not None and previous is not row:
                            self.dropped["connection_collision"] += 1
                        else:
                            self.links[key] = row
                            self.local.connections.append(key)
                return result
            finally:
                self.add(row, "wire_connect", self.elapsed(started))

        return wrapped

    def client_phase(self, original, label):
        assert label in LABELS or label in {"state", "send", "headers"}

        @wraps(original)
        def wrapped(*args, **kwargs):
            row = getattr(self.local, "row", None)
            if row is None:
                return original(*args, **kwargs)
            actual = label
            if label == "state":
                self.local.state_calls += 1
                actual = {1: "client_state_initial", 2: "client_state_recheck"}.get(
                    self.local.state_calls, "client_state_extra"
                )
            elif label in {"send", "headers"}:
                actual = ("wire_challenge_" if self.local.in_challenge else "client_hook_") + label
            previous = self.local.in_challenge
            if label == "client_challenge":
                self.local.in_challenge = True
            started = self.start()
            try:
                return original(*args, **kwargs)
            finally:
                self.add(row, actual, self.elapsed(started))
                self.local.in_challenge = previous

        return wrapped

    def server_phase(self, original, label):
        assert label in LABELS or label in {"write", "post"}

        @wraps(original)
        def wrapped(handler, *args, **kwargs):
            with self.lock:
                row = self.links.get(handler.client_address)
            if row is None:
                return original(handler, *args, **kwargs)
            previous = getattr(self.server_local, "operation", None)
            previous_row = getattr(self.server_local, "row", None)
            self.server_local.row = row
            actual = label
            if label == "post":
                kind = (
                    "identity"
                    if handler.path == "/v1/daemon/identity-challenge"
                    else ("hook" if handler.path.startswith("/v1/hooks/") else "other")
                )
                self.server_local.operation = kind
                actual = f"server_{kind}_post"
            if label == "server_challenge":
                self.server_local.operation = "identity"
            elif label == "server_hook":
                self.server_local.operation = "hook"
            if label == "write":
                operation = getattr(self.server_local, "operation", None)
                if operation not in {"identity", "hook"}:
                    self.server_local.row = previous_row
                    return original(handler, *args, **kwargs)
                actual = f"server_{operation}_write"
            started = self.start()
            try:
                return original(handler, *args, **kwargs)
            finally:
                self.add(row, actual, self.elapsed(started))
                self.server_local.operation = previous
                self.server_local.row = previous_row

        return wrapped

    def server_context_phase(self, original, segment):
        assert segment in POST_SEGMENTS

        @wraps(original)
        def wrapped(*args, **kwargs):
            row = getattr(self.server_local, "row", None)
            kind = getattr(self.server_local, "operation", None)
            if row is None or kind not in {"identity", "hook", "other"}:
                return original(*args, **kwargs)
            started = self.start()
            try:
                return original(*args, **kwargs)
            finally:
                self.add(row, f"server_{kind}_{segment}", self.elapsed(started))

        return wrapped

    def checkpoint(self):
        with self.lock:
            self.checkpoints += 1
            self.stage = {1: "rss_baseline", 2: "http_1", 3: "http_16", 4: "http_64"}.get(self.checkpoints, "direct")

    def server_submit(self, original):
        @wraps(original)
        def wrapped(server, request, address, *args, **kwargs):
            with self.lock:
                row = self.links.get(address)
                if row is not None:
                    connection = row.setdefault("connection", {})
                    connection["watchdog_submission"] = connection.get("watchdog_submission", False) or (
                        threading.current_thread() is server.unclassified_watchdog_thread
                    )
            return original(server, request, address, *args, **kwargs)

        return wrapped

    def server_worker(self, original):
        @wraps(original)
        def wrapped(server, request, address, *args, **kwargs):
            with self.lock:
                row = self.links.get(address)
            if row is not None:
                with server.request_capacity_lock:
                    accepted = server.request_accepted_at.get(id(request))
                if accepted is not None:
                    elapsed = round((time.monotonic() - accepted) * 1e9)
                    with self.lock:
                        row.setdefault("connection", {})["accepted_to_worker_ns"] = elapsed
            return original(server, request, address, *args, **kwargs)

        return wrapped

    def after_summary(self):
        with self.lock:
            if self.checkpoints == 4:
                self.stage = "direct"

    def report(self):
        with self.lock:
            rows = self.rows
            serial = [r for r in rows if r["stage"] == "http_1"]
            incomplete = sum(
                r["outcome"] != "returned"
                or any(len(r["phases"].get(label, [])) != 1 for label in CLIENT_COMPONENTS)
                or any(
                    len(r["phases"].get(label, [])) != 1
                    for label in (
                        "server_challenge",
                        "server_hook",
                        "server_native",
                        "server_identity_post",
                        "server_hook_post",
                        "server_identity_route",
                        "server_hook_route",
                    )
                )
                for r in serial
            )
            negative_residual = sum(
                r["total"]["wall_ns"]
                < sum(s["wall_ns"] for label in CLIENT_COMPONENTS for s in r["phases"].get(label, []))
                for r in rows
            )
            return {
                "client_scope": "Claude authenticated transport; concurrent Codex traffic is unprofiled",
                "timing": "wall and current-thread CPU nanoseconds; wrappers affect scheduling and cost",
                "composition": "Disjoint client components; nested server/wire phases must not be added to them.",
                "tail_estimator": "Slowest ceil(5% of returned requests); means of each selected trace's components.",
                "requests": len(rows),
                "checkpoints": self.checkpoints,
                "remaining_links": len(self.links),
                "dropped": dict(self.dropped),
                "incomplete_serial_requests": incomplete,
                "negative_client_residuals": negative_residual,
                "profile_complete": bool(serial)
                and self.checkpoints == 4
                and not (self.links or self.dropped or incomplete or negative_residual),
                "summaries": summaries(rows),
                "rows": rows,
            }
