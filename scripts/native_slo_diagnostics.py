"""Retain only bounded logs and numeric server counters from private SLO homes."""

from __future__ import annotations

import inspect
import json
import sys
import threading
from collections import Counter
from pathlib import Path


def capture_inflight_failure(_kind, error, _traceback, *, destination: Path) -> bool:
    """Capture bounded stack locations before containment; never inspect locals."""
    if error is None:
        return False
    threads = []
    for frame in list(sys._current_frames().values())[:256]:
        stack = []
        while frame is not None and len(stack) < 32:
            stack.append(
                {"file": Path(frame.f_code.co_filename).name, "function": frame.f_code.co_name, "line": frame.f_lineno}
            )
            frame = frame.f_back
        threads.append(stack)
    with destination.open("x") as out:
        json.dump({"schema": "guard-native-slo-inflight-failure.v1", "threads": threads}, out, indent=2)
    return False  # ExitStack must preserve the original benchmark exception.


def capture_transport_refusals(server) -> None:
    """Diagnostic observer only; call the original close/discard unchanged."""
    counts, lock = Counter(), threading.Lock()
    server._cigar_probe_transport_counts = counts
    server._cigar_probe_transport_lock = lock
    allowed = {
        "_submit_transport_request",
        "_advance_pending_classifications",
        "_watch_unclassified_connections",
        "_evict_oldest_unclassified_connection",
        "_advance_saturation_probes",
        "_park_saturation_probe",
    }

    def wrap(name):
        original = getattr(server, name)

        def observe(request):
            frame = inspect.currentframe()
            caller = frame.f_back.f_code.co_name if frame is not None and frame.f_back is not None else "other"
            del frame
            with lock:
                counts[name.removeprefix("_") + ":" + (caller if caller in allowed else "other")] += 1
            return original(request)

        setattr(server, name, observe)

    wrap("_discard_request")
    wrap("_close_unclassified_socket")


def preserve_session_diagnostics(session, destination: Path | None) -> None:
    if destination is None:
        return
    destination.mkdir(mode=0o700)
    counts = {}
    server = session.daemon._server
    for name in (
        "active_requests",
        "rejected_requests",
        "active_hook_requests",
        "rejected_hook_requests",
        "request_capacity_limit",
        "connection_capacity_limit",
    ):
        value = getattr(server, name, None)
        if type(value) is int:
            counts[name] = value
    observer = getattr(server, "_cigar_probe_transport_counts", None)
    if observer is not None:
        with server._cigar_probe_transport_lock:
            counts["diagnostic_transport_refusals"] = dict(observer)
    with (destination / "server-counts.json").open("x") as out:
        json.dump(counts, out, indent=2)
    for relative, label in (
        ("logs/daemon.log", "daemon.log"),
        ("native-runtime/managed-resident-phases.v1.log", "native-phases.log"),
    ):
        path = session.guard_home / relative
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as stream:
                encoded = stream.read(2 * 1024 * 1024 + 1)
            if len(encoded) > 2 * 1024 * 1024:
                raise RuntimeError("private SLO diagnostic exceeded its bounded log limit")
            with (destination / label).open("xb") as out:
                out.write(encoded)
