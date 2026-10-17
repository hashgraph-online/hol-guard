"""Atomic file replacement that waits out a reader's open handle on Windows."""

from __future__ import annotations

import os
import time
from pathlib import Path

_IS_WINDOWS = os.name == "nt"
_ERROR_ACCESS_DENIED = 5
_ERROR_SHARING_VIOLATION = 32
_REPLACE_ATTEMPTS = 20
_REPLACE_RETRY_SECONDS = 0.025


def replace_file(source: Path, destination: Path) -> None:
    """Move ``source`` over ``destination`` in one step.

    Windows refuses the replace while another process holds the destination
    open without delete sharing, which is how Python opens a file to read it.
    Status readers hold the file for a few milliseconds, so the replace is
    retried for up to half a second before the error is raised.
    """
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(source, destination)
            return
        except PermissionError as error:
            transient = getattr(error, "winerror", None) in {_ERROR_ACCESS_DENIED, _ERROR_SHARING_VIOLATION}
            if not _IS_WINDOWS or not transient or attempt == _REPLACE_ATTEMPTS - 1:
                raise
            time.sleep(_REPLACE_RETRY_SECONDS)
