"""Hidden ``desktop library-call``: one Guard library call in a CLI process.

The native daemon writes ``{"call": name, "args": {...}}`` to standard input
and reads one JSON object back from standard output; see ``library_calls``.
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


__all__ = ["run_library_call"]
