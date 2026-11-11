"""Keep the direct-lane ACK with the newest acknowledged publication.

More than one daemon process can hold a policy publisher for the same Guard
home, and they share one ACK file. The resident binds the newest generation
pushed to it and defers every direct hook whose ACK names another, so a
publisher that keeps renewing an older generation shuts the lane for every
harness each time its renewal lands. A publisher writes the ACK only after the
resident acknowledged its generation, so once the file names a newer one, the
older publisher stops renewing and leaves the file to the newer one.

This only decides whether to keep a lease alive. The resident still checks the
ACK's generation and digest against its own binding before any direct use.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_MAX_ACK_BYTES = 4096


def renewable(ack_path: Path, target: tuple[int, str] | None) -> bool:
    """Whether the lease for `target` may be renewed.

    A missing or unreadable ACK keeps the lease renewing as before.
    """

    if target is None:
        return False
    try:
        descriptor = os.open(ack_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            text = handle.read(_MAX_ACK_BYTES + 1)
        ack = json.loads(text) if len(text) <= _MAX_ACK_BYTES else None
    except (OSError, ValueError):
        return True
    written = ack.get("generation") if isinstance(ack, dict) else None
    if isinstance(written, bool) or not isinstance(written, int):
        return True
    return written <= target[0]
