"""Hidden ``desktop library-call`` and ``desktop library-serve``.

``library-call`` answers one Guard library call in a CLI process: the native
daemon writes ``{"call": name, "args": {...}}`` to standard input and reads
one JSON object back from standard output; see ``library_calls``.

``library-serve`` is the resident form for calls whose state must outlive one
request, such as an extension-control preview's proof awaiting its apply.
The daemon writes one call per line, each with an ``id``, and reads one
answer per line carrying the same ``id``. Calls run side by side, as the
Python daemon's threaded server ran its requests, so a slow one never holds
up the rest. The process exits when its standard input closes and every
call it started has answered.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path

# The native daemon sends at most this much: a request body plus its routing.
_REQUEST_LIMIT_BYTES = 2_200_000
# How many resident calls may run at once; the next one waits for a slot.
_RESIDENT_CALL_LIMIT = 32


def run_library_call(guard_home: Path) -> int:
    """Answer the call on stdin; 2 when there is none to answer."""

    from ..library_calls import run_library_call as run

    request = sys.stdin.buffer.read(_REQUEST_LIMIT_BYTES + 1)
    if not request or len(request) > _REQUEST_LIMIT_BYTES:
        return 2
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

    result = run(guard_home, request)
    try:
        call_id = json.loads(request.decode("utf-8")).get("id")
    except (UnicodeDecodeError, ValueError, AttributeError):
        call_id = None
    if isinstance(call_id, int) and not isinstance(call_id, bool):
        result = {"id": call_id, **result}
    line = json.dumps(result, separators=(",", ":"), default=str) + "\n"
    return line.encode("utf-8")


def serve_lines(guard_home: Path, read_line: Callable[[], bytes], write: Callable[[bytes], None]) -> int:
    """Run every call line ``read_line`` returns, each in its own thread."""

    write_lock = threading.Lock()
    slots = threading.BoundedSemaphore(_RESIDENT_CALL_LIMIT)
    workers: list[threading.Thread] = []

    def _answer(request: bytes) -> None:
        try:
            line = answer_line(guard_home, request)
            with write_lock:
                write(line)
        except OSError:
            pass
        finally:
            slots.release()

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
        slots.acquire()
        worker = threading.Thread(target=_answer, args=(request,), daemon=True)
        worker.start()
        workers = [current for current in workers if current.is_alive()]
        workers.append(worker)
    for worker in workers:
        worker.join()
    return status


def serve_library_calls(guard_home: Path) -> int:
    """Answer the calls on stdin, one per line, until it closes."""

    source = sys.stdin.buffer
    out = sys.stdout.buffer

    def _write(line: bytes) -> None:
        out.write(line)
        out.flush()

    return serve_lines(guard_home, lambda: source.readline(_REQUEST_LIMIT_BYTES + 1), _write)


__all__ = ["answer_line", "run_library_call", "serve_library_calls", "serve_lines"]
