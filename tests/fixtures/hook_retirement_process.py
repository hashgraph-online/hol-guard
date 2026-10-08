"""Stdlib-only spawned tree for process-group retirement qualification."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path


def spawn_term_ignoring_descendant(ready_path: str, escaped_path: str) -> None:
    os.setsid()
    child_code = (
        "import signal,time;"
        "from pathlib import Path;"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        f"Path({ready_path!r}).touch();"
        "time.sleep(1);"
        f"Path({escaped_path!r}).touch()"
    )
    _ = subprocess.Popen(
        [sys.executable, "-c", child_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 2
    while not Path(ready_path).is_file() and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(10)
