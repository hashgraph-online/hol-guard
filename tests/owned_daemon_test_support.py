"""Atomic readiness publication for the owned-daemon qualification fixture."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def publish_ready_pid(ready: Path, pid: int) -> None:
    """Make the unique fixture marker visible only after its complete PID is closed."""
    if type(pid) is not int or pid <= 0:
        raise ValueError("readiness PID must be a positive integer")
    descriptor, name = tempfile.mkstemp(prefix=f".{ready.name}-", dir=ready.parent)
    pending = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write(str(pid))
        os.replace(pending, ready)
    finally:
        pending.unlink(missing_ok=True)
