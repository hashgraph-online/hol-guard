"""Best-effort permission repair without rewriting already-private metadata."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path


def set_private_mode(path: Path, mode: int, *, logger: logging.Logger) -> None:
    if os.name == "nt":
        return
    try:
        if stat.S_IMODE(path.stat().st_mode) == mode:
            return
    except OSError:
        pass
    try:
        os.chmod(path, mode)
    except OSError as exc:
        logger.debug("Could not set private mode %o on %s: %s", mode, path, exc)
