"""Answers the native daemon asks of Guard's CLI.

The daemon's native edge serves every HTTP route itself. A few answers depend
on how this Guard was installed (the package surface, the trusted update
environment), which only the installed CLI can describe; the edge runs this
hidden command for those and reads one JSON object from its output.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import TextIO


def _update_status(guard_home: Path) -> dict[str, object]:
    from .update_commands import build_guard_update_status_payload

    return build_guard_update_status_payload(guard_home=guard_home)


_QUERIES: dict[str, Callable[[Path], dict[str, object]]] = {
    "update-status": _update_status,
}


def run_daemon_query(query: str, guard_home: Path, output_stream: TextIO) -> int:
    """Print the answer to ``query`` as one JSON object; 2 for an unknown query."""

    answer = _QUERIES.get(query)
    if answer is None:
        output_stream.write(json.dumps({"error": "unknown_query"}) + "\n")
        return 2
    output_stream.write(json.dumps(answer(guard_home), separators=(",", ":"), default=str) + "\n")
    return 0


__all__ = ["run_daemon_query"]
