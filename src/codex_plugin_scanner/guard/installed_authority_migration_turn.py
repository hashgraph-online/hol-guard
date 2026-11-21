"""One process at a time admits the installed release's command packs.

After a runtime upgrade the daemon's worker host and every extension-control
host (each library server, each CLI process that reads controls) find the same
unmigrated activation and start the same migration. Each prepares the whole
candidate set on its own, they compete for the resident and the authority lock,
and all but one lose the final compare-and-swap. On a long-lived install that
turned a migration of seconds into minutes during which every hook failed
closed. A turn file serialises the attempt: whoever holds it migrates, a waiter
then finds the work done, and a caller that cannot wait retries later.
"""

from __future__ import annotations

import os
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from pathlib import Path

from .native_resident_update_lock import _is_lock_contention, _try_lock, _unlock, open_private_lock_file

TURN_FILE_NAME = "installed-authority-migration.v1.lock"
_POLL_SECONDS = 0.05


@contextmanager
def installed_authority_migration_turn(guard_home: Path, *, wait_seconds: float) -> Generator[bool]:
    """Yield True while this process holds the migration turn.

    Yields False when another process kept the turn for ``wait_seconds``; the
    caller then leaves its migration pending and retries later. A turn file
    that cannot be opened or locked raises, so the caller records why.
    """

    descriptor = open_private_lock_file(guard_home, TURN_FILE_NAME)
    try:
        deadline = time.monotonic() + max(wait_seconds, 0.0)
        while True:
            try:
                _try_lock(descriptor)
                break
            except OSError as error:
                if not _is_lock_contention(error):
                    raise
            if time.monotonic() >= deadline:
                yield False
                return
            time.sleep(_POLL_SECONDS)
        try:
            yield True
        finally:
            with suppress(OSError):
                _unlock(descriptor)
    finally:
        os.close(descriptor)
