"""Bounded metadata for owned native clients and private benchmark teardown.

Never retain arguments, environment, IPC frames, state-file contents or raw
process/path identities in reports. Weak references avoid prolonging a
client's pipe lifetime. Original operations run outside the observer lock.
"""

from __future__ import annotations

import sys
import threading
import time
import weakref
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

LABELS = frozenset(
    {
        "client_close",
        "pool_close",
        "stop_clients",
        "stop_resident",
        "daemon_stop",
        "session_close",
        "finish_cleanup",
        "dispatch_stop",
        "writer_stop",
        "heartbeat_stop",
        "hook_worker_close",
        "publisher_close",
        "request_executors_stop",
        "header_watchdog_stop",
        "service_background_join",
        "command_queue_stop",
        "cloud_sync_stop",
        "approval_attention_stop",
        "discovery_close",
    }
)
PHASES = frozenset({"workload", "session_close", "finish_cleanup"})
STATUSES = frozenset({"contained", "already-stopped", "failed", "contained_client_cleanup_failed"})


class CleanupObserver:
    def __init__(self, installed: Path, repo: Path, *, limit: int = 512):
        self.installed, self.repo = installed, repo
        self.limit = limit
        self._lock = threading.Lock()
        self._phase = "workload"
        self._scopes = {}
        self._clients = []
        self.events = []
        self.snapshots = []
        self.dropped = Counter()

    def scope(self, state_dir) -> int:
        # This exact path is transient correlation data, never report data.
        with self._lock:
            if state_dir not in self._scopes:
                if len(self._scopes) >= 32:
                    self.dropped["scopes"] += 1
                    return 0
                self._scopes[state_dir] = len(self._scopes) + 1
            return self._scopes[state_dir]

    @contextmanager
    def phase(self, name):
        if name not in PHASES:
            raise ValueError("unknown cleanup phase")
        with self._lock:
            previous, self._phase = self._phase, name
        try:
            yield
        finally:
            with self._lock:
                self._phase = previous

    def event(self, kind, **values):
        allowed = {
            "wall_ms",
            "raised",
            "result_is_false",
            "result_is_none",
            "scope",
            "process_retained",
            "status",
            "finish_completed",
        }
        if kind not in LABELS | {"client_started"} or set(values) - allowed:
            raise ValueError("unknown cleanup metadata")
        if any(
            type(v) not in {bool, int, float} and not (k == "status" and type(v) is str and v in STATUSES | {"other"})
            for k, v in values.items()
        ):
            raise ValueError("non-numeric cleanup metadata")
        with self._lock:
            if len(self.events) >= self.limit:
                self.dropped["events"] += 1
                return
            self.events.append(
                {
                    "kind": kind,
                    "phase": self._phase,
                    "main_thread": threading.current_thread() is threading.main_thread(),
                    **values,
                }
            )

    def observe(self, original, label, *, phase=None, after=None):
        if label not in LABELS or (phase is not None and phase not in PHASES):
            raise ValueError("unknown cleanup operation")

        def invoke(*args, **kwargs):
            started = time.perf_counter()
            raised, result = True, None
            try:
                result = original(*args, **kwargs)
                raised = False
                return result
            finally:
                try:
                    values = {"wall_ms": (time.perf_counter() - started) * 1000, "raised": raised}
                    if not raised:
                        values["result_is_false"] = result is False
                        values["result_is_none"] = result is None
                    if label in {"client_close", "pool_close"}:
                        values["scope"] = self.scope(args[0]._state_dir)
                    if label == "client_close":
                        values["process_retained"] = args[0]._process is not None
                    if label == "stop_resident" and not raised:
                        diagnostic = getattr(result, "diagnostic", {})
                        status = diagnostic.get("status")
                        values["status"] = status if status in STATUSES else "other"
                    if label == "daemon_stop":
                        values["finish_completed"] = getattr(args[0], "_finish_service_completed", False) is True
                    self.event(label, **values)
                    if after is not None:
                        after(args)
                except Exception:
                    with self._lock:
                        self.dropped["observation_error"] += 1

        if phase is None:
            return invoke

        def phased(*args, **kwargs):
            with self.phase(phase):
                return invoke(*args, **kwargs)

        return phased

    def client_start(self, original):
        def start(client, *args, **kwargs):
            before = client._process
            result = original(client, *args, **kwargs)
            process = client._process
            if process is not None and process is not before:
                try:
                    scope = self.scope(client._state_dir)
                    with self._lock:
                        if len(self._clients) < 128:
                            self._clients.append((weakref.ref(client), weakref.ref(process), process.pid, scope))
                        else:
                            self.dropped["clients"] += 1
                    self.event("client_started", scope=scope)
                except Exception:
                    with self._lock:
                        self.dropped["observation_error"] += 1
            return result

        return start

    def _pool_snapshot(self, pools):
        with pools._CLIENTS_LOCK:
            selected = list(pools._CLIENT_POOLS.values())
        if len(selected) > 32:
            with self._lock:
                self.dropped["pools"] += len(selected) - 32
        rows = []
        for pool in selected[:32]:
            row = {"scope": self.scope(pool._state_dir)}
            if pool._condition.acquire(blocking=False):
                try:
                    row.update(
                        closed=pool._closed,
                        clients=len(pool._clients),
                        idle=len(pool._idle),
                        retiring=len(pool._retiring),
                    )
                finally:
                    pool._condition.release()
            else:
                row["metadata_busy"] = True
            rows.append(row)
        return rows

    def _stacks(self):
        stacks = []
        for frame in list(sys._current_frames().values())[:128]:
            locations = []
            for _ in range(32):
                if frame is None:
                    break
                filename = Path(frame.f_code.co_filename)
                prefix = None
                for root, label in ((self.installed, "installed"), (self.repo / "scripts", "tooling")):
                    if filename.is_absolute() and filename.is_relative_to(root):
                        prefix = (label, filename.relative_to(root).as_posix())
                        break
                if prefix:
                    locations.append(
                        {
                            "root": prefix[0],
                            "module": prefix[1],
                            "function": frame.f_code.co_name,
                            "line": frame.f_lineno,
                        }
                    )
                frame = frame.f_back
            if locations:
                stacks.append(locations)
        return stacks

    def snapshot(self, label, pools, sampler=None):
        if label not in {"after_daemon_stop", "after_finish_cleanup"}:
            raise ValueError("unknown cleanup snapshot")
        with self._lock:
            clients = list(self._clients)
        living = {}
        if sampler is not None:
            # Read the exact original final snapshot without extending its
            # five-second gate or taking a replacement process sample.
            with sampler._lock:
                living = dict(sampler._live_descendants)
        known = {}
        for _client, process_ref, pid, scope in clients:
            process = process_ref()
            if process is not None and process.poll() is None:
                known[pid] = scope
        roles, scopes = Counter(), Counter()
        for (pid, _start), kind in living.items():
            role = (
                "known_client_stream"
                if pid in known
                else "other_native"
                if kind == "native_runtime"
                else "other_worker"
            )
            roles[role] += 1
            if pid in known:
                scopes[str(known[pid])] += 1
        row = {
            "label": label,
            "pools": self._pool_snapshot(pools),
            "known_client_processes_alive": len(known),
            "original_final_live_roles": dict(roles),
            "original_final_live_client_scopes": dict(scopes),
            "stacks": self._stacks(),
        }
        with self._lock:
            if len(self.snapshots) < 8:
                self.snapshots.append(row)
            else:
                self.dropped["snapshots"] += 1

    def report(self):
        with self._lock:
            return {
                "schema": "guard-cigar-native-cleanup-observer.v1",
                "scope_count": len(self._scopes),
                "client_processes_started": len(self._clients),
                "events": list(self.events),
                "snapshots": list(self.snapshots),
                "dropped": dict(self.dropped),
                "profile_complete": not self.dropped,
                "limits": (
                    "Instrumentation changes scheduling; roles only identify directly observed "
                    "Python-owned client streams. "
                    "No state, argv, environment or request content is read. Missing roles remain unknown."
                ),
            }
