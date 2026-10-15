"""In-process revision for the managed-install table.

Writers bump the revision after their commit so readers that remember a
"protected" answer drop it as soon as this process changes the table.
"""

from __future__ import annotations

import itertools
import threading

_lock = threading.Lock()
_counter = itertools.count(1)
_revision = 0


def current_managed_install_revision() -> int:
    return _revision


def bump_managed_install_revision() -> None:
    global _revision
    with _lock:
        _revision = next(_counter)
