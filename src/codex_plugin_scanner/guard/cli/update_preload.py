"""Keep `hol-guard update` able to print its result after the installer runs.

The installer rewrites this package's files while the update command is still
running. A module first imported after that comes from the new release, and it
can ask a module this process already holds for a name the older copy never
had. Release 3.59.0 failed that way: `_emit` imported `render` only when it
printed the result, so the new `render` asked the old `protect_output` for
`protect_desktop_approval_url`, raised ImportError, and a finished update
exited 1.

Importing `render` here, at module level, loads the renderer and everything it
imports when the CLI starts, before any install. If a later import still
fails while the result is printed, the result is written with the standard
library alone, so a finished update is never reported as a failure.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import TextIO

from . import render as _render  # loaded before the installer replaces it

RENDER_MODULE = _render.__name__


def emit_update_result(
    emit: Callable[[str, dict[str, object], bool], None],
    payload: dict[str, object],
    as_json: bool,
    *,
    stream: TextIO | None = None,
) -> None:
    """Print the update result, without the renderer if a stale import breaks it."""
    try:
        emit("update", payload, as_json)
    except ImportError:
        out = stream if stream is not None else sys.stdout
        if as_json:
            out.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
            return
        message = payload.get("message")
        out.write(f"{message if isinstance(message, str) else 'Update finished.'}\n")
        out.write("Run `hol-guard status` to see the updated install.\n")
