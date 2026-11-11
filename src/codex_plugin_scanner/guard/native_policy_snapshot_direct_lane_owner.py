"""Keep the direct-lane ACK with the newest publication of a Guard home.

More than one daemon process can hold a policy publisher for the same Guard
home, and they share one ACK file. The resident binds the newest generation
pushed to it and defers every direct hook whose ACK names another, so a
publisher that keeps renewing an older generation shuts the lane for every
harness each time its renewal lands. A publisher whose generation another has
since passed stops renewing and leaves the file to that one.

This only decides whether to keep a lease alive. The resident still checks the
ACK's generation and digest against its own binding before any direct use.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Written by the snapshot materializer before a generation leaves for the resident.
GENERATION_STATE_NAME = "native-policy-snapshot-generation-v3.json"
_MAX_STATE_BYTES = 4096


def renewable(guard_home: Path, target: tuple[int, str] | None) -> bool:
    """Whether the lease for `target` may be renewed.

    An unreadable state keeps the lease renewing as before.
    """

    if target is None:
        return False
    try:
        descriptor = os.open(guard_home / GENERATION_STATE_NAME, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            text = handle.read(_MAX_STATE_BYTES + 1)
        state = json.loads(text) if len(text) <= _MAX_STATE_BYTES else None
    except (OSError, ValueError):
        return True
    latest = state.get("generation") if isinstance(state, dict) else None
    if isinstance(latest, bool) or not isinstance(latest, int):
        return True
    return latest <= target[0]
