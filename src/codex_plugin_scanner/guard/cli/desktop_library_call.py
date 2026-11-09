"""Hidden ``desktop library-call`` and ``desktop library-serve``.

``library-call`` answers one Guard library call in a CLI process: the native
daemon writes ``{"call": name, "args": {...}}`` to standard input and reads
one JSON object back from standard output; see ``library_calls``.

``library-serve`` is the resident form for calls whose state must outlive one
request, such as an extension-control preview's proof awaiting its apply.
The daemon writes one call per line and reads one answer per line, in order,
and the process exits when its standard input closes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# The native daemon sends at most this much: a request body plus its routing.
_REQUEST_LIMIT_BYTES = 2_200_000


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
    return 0


def serve_library_calls(guard_home: Path) -> int:
    """Answer one call per line on stdin until it closes."""

    from ..library_calls import run_library_call as run

    source = sys.stdin.buffer
    out = sys.stdout.buffer
    while True:
        request = source.readline(_REQUEST_LIMIT_BYTES + 1)
        if not request:
            return 0
        if len(request) > _REQUEST_LIMIT_BYTES and not request.endswith(b"\n"):
            # The daemon never sends a line this long; the stream is not one
            # this loop can stay in step with.
            return 2
        result = run(guard_home, request)
        out.write(json.dumps(result, separators=(",", ":"), default=str).encode("utf-8") + b"\n")
        out.flush()


__all__ = ["run_library_call", "serve_library_calls"]
