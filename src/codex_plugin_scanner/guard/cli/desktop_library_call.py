"""Hidden ``desktop library-call`` and ``desktop library-serve``.

``library-call`` answers one Guard library call in a CLI process: the native
daemon writes ``{"call": name, "args": {...}}`` to standard input and reads
one JSON object back from standard output; see ``library_calls``.

``library-serve`` is the resident form for calls whose state must outlive one
request, such as an extension-control preview's proof awaiting its apply.
The daemon writes one call per line, each with an ``id``, and reads one
answer per line carrying the same ``id``. Calls run side by side on a
bounded pool of workers, so a slow one never holds up the rest, and a call
the daemon has stopped waiting for is dropped before it runs. The process exits when its standard input closes and every
call it started has answered.
"""

from __future__ import annotations

import json
import os
import queue
import re
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

# The native daemon sends at most this much: a request body plus its routing.
_REQUEST_LIMIT_BYTES = 2_200_000
# How many resident calls may run at once; the rest wait in order for a worker.
_RESIDENT_CALL_LIMIT = 32
# Call bytes read but not yet started. Past this the read loop waits for the
# workers, so a pool that stops making progress cannot grow the queue without
# bound; the daemon bounds its own side and replaces a process that stalls.
_QUEUED_LIMIT_BYTES = 64 * 1024 * 1024
_EXPIRES_IN = re.compile(rb'"expires_in_ms":(\d{1,9})[,}]')


def run_library_call(guard_home: Path) -> int:
    """Answer the call on stdin; 2 when there is none to answer."""

    from ..library_calls import run_library_call as run
    from .desktop_daemon_workers import wait_for_early_runtime_status

    request = sys.stdin.buffer.read(_REQUEST_LIMIT_BYTES + 1)
    if not request or len(request) > _REQUEST_LIMIT_BYTES:
        return 2
    # The call opens a store, whose first native call needs the runtime status
    # this process started resolving beside its imports.
    wait_for_early_runtime_status()
    result = run(guard_home, request)
    out = sys.stdout.buffer
    out.write(json.dumps(result, separators=(",", ":"), default=str).encode("utf-8"))
    out.flush()
    # The daemon reads the answer to end of file; close it before letting
    # work the call started after answering (evidence, audit) finish.
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, sys.stdout.fileno())
    os.close(devnull)
    from ..routes.request_host import wait_for_background_work

    wait_for_background_work()
    return 0


def answer_line(guard_home: Path, request: bytes) -> bytes:
    """The answer line for one resident call line, with the call's ``id``."""

    from ..library_calls import run_library_call as run
    from .desktop_daemon_workers import wait_for_early_runtime_status

    # As in run_library_call: the store this call opens needs the runtime status.
    wait_for_early_runtime_status()
    result = run(guard_home, request)
    try:
        call_id = json.loads(request.decode("utf-8")).get("id")
    except (UnicodeDecodeError, ValueError, AttributeError, RecursionError):
        call_id = None
    if isinstance(call_id, int) and not isinstance(call_id, bool):
        result = {"id": call_id, **result}
    line = json.dumps(result, separators=(",", ":"), default=str) + "\n"
    return line.encode("utf-8")


def _worker_failure_line(request: bytes) -> bytes:
    """Return a bounded answer when a resident worker raises unexpectedly."""

    try:
        call_id = json.loads(request.decode("utf-8")).get("id")
    except (UnicodeDecodeError, ValueError, AttributeError, RecursionError):
        call_id = None
    result: dict[str, object] = {
        "error": {
            "type": "LibraryWorkerError",
            "message": "worker_failed",
            "kind": "library_worker",
        }
    }
    if isinstance(call_id, int) and not isinstance(call_id, bool):
        result = {"id": call_id, **result}
    return (json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8")


def _expires_at(request: bytes, received: float) -> float | None:
    """The monotonic time the daemon stops waiting for ``request``'s answer.

    The daemon writes ``expires_in_ms`` near the start of each line, ahead of
    the arguments, so it is found without decoding the whole call.
    """

    match = _EXPIRES_IN.search(request, 0, 128)
    if match is None:
        return None
    return received + int(match.group(1)) / 1000


def serve_lines(guard_home: Path, read_line: Callable[[], bytes], write: Callable[[bytes], None]) -> int:
    """Run every call line ``read_line`` returns on a pool of worker threads.

    The read loop never waits for a free worker: a burst of calls queues
    here rather than in the pipe, so the daemon's writes never stall behind
    a busy pool. A call still queued when the daemon has stopped waiting for
    it is dropped unrun, so a burst cannot leave the pool working through
    answers nobody will read while live calls wait behind them. The queue
    holds at most ``_QUEUED_LIMIT_BYTES`` of call lines.
    """

    write_lock = threading.Lock()
    room = threading.Condition()
    queued_bytes = 0
    calls: queue.SimpleQueue[tuple[bytes, float | None] | None] = queue.SimpleQueue()
    workers: list[threading.Thread] = []

    def _work() -> None:
        while True:
            item = calls.get()
            if item is None:
                return
            request, expires_at = item
            _taken(len(request))
            if expires_at is not None and time.monotonic() >= expires_at:
                continue
            try:
                line = answer_line(guard_home, request)
                with write_lock:
                    write(line)
            except OSError:
                pass
            except BaseException as error:
                try:
                    from ..runtime_health.background_diagnostics import failure_detail, record_background_event

                    record_background_event("library_worker_failed", failure_detail(error))
                except BaseException:
                    pass
                try:
                    with write_lock:
                        write(_worker_failure_line(request))
                except BaseException:
                    pass

    def _taken(size: int) -> None:
        nonlocal queued_bytes
        with room:
            queued_bytes -= size
            room.notify()

    status = 0
    while True:
        request = read_line()
        if not request:
            break
        if len(request) > _REQUEST_LIMIT_BYTES and not request.endswith(b"\n"):
            # The daemon never sends a line this long; the stream is not one
            # this loop can stay in step with.
            status = 2
            break
        received = time.monotonic()
        with room:
            while queued_bytes and queued_bytes + len(request) > _QUEUED_LIMIT_BYTES:
                _ = room.wait()
            queued_bytes += len(request)
        calls.put((request, _expires_at(request, received)))
        if len(workers) < _RESIDENT_CALL_LIMIT:
            worker = threading.Thread(target=_work, daemon=True)
            worker.start()
            workers.append(worker)
    for _ in workers:
        calls.put(None)
    for worker in workers:
        worker.join()
    return status


def serve_library_calls(guard_home: Path) -> int:
    """Answer the calls on stdin, one per line, until it closes."""

    from ..runtime_health.background_diagnostics import install_sink, release_sink
    from ..runtime_health.diagnostics import BackgroundLogWriter

    source = sys.stdin.buffer
    out = sys.stdout.buffer

    def _write(line: bytes) -> None:
        out.write(line)
        out.flush()

    # The extension-control service and the catalog tick run in this process;
    # their background failures reach daemon.log only through these sinks.
    writer = BackgroundLogWriter(guard_home)
    install_sink(writer.error, notice=writer.notice)
    try:
        return serve_lines(guard_home, lambda: source.readline(_REQUEST_LIMIT_BYTES + 1), _write)
    finally:
        release_sink(writer.error)
        _ = writer.close()


__all__ = ["answer_line", "run_library_call", "serve_library_calls", "serve_lines"]
