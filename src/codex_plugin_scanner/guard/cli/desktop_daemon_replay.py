"""Hidden ``desktop daemon-replay``: one daemon request in a CLI process.

The native daemon writes a request's raw bytes to standard input and reads
the raw response from standard output; see ``daemon.request_replay``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# The native edge reads at most this much of a request (head and body).
_REQUEST_LIMIT_BYTES = 1_100_000


def run_daemon_replay(guard_home: Path, port: int) -> int:
    """Answer the request on stdin; 2 when there is none to answer."""

    from ..daemon.request_replay import replay_request, wait_for_background_work

    request = sys.stdin.buffer.read(_REQUEST_LIMIT_BYTES + 1)
    if not request or len(request) > _REQUEST_LIMIT_BYTES or not 0 < port < 65536:
        return 2
    response = replay_request(guard_home, request, port=port)
    out = sys.stdout.buffer
    out.write(response)
    out.flush()
    # The edge has its answer once stdout closes; work the handler started
    # for later (a connect flow waiting on the browser) carries on here.
    os.close(sys.stdout.fileno())
    wait_for_background_work()
    return 0 if response else 1


__all__ = ["run_daemon_replay"]
