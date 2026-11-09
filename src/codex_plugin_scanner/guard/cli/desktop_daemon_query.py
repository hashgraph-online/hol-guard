"""Answers the native daemon asks of Guard's CLI.

Some answers depend on how this Guard was installed (the package surface and
the trusted update environment), which only the installed CLI can describe;
the daemon's native edge runs this hidden command for those and reads one JSON
envelope, ``{"status": <http status>, "body": <object>}``, from its output.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

Answer = tuple[int, dict[str, object]]


def _update_status(guard_home: Path, payload: dict[str, object]) -> Answer:
    del payload
    from .update_commands import build_guard_update_status_payload

    return 200, build_guard_update_status_payload(guard_home=guard_home)


_QUERIES: dict[str, Callable[[Path, dict[str, object]], Answer]] = {
    "update-status": _update_status,
}


# The edge refuses request bodies past 1 MiB; leave room for the JSON envelope.
_INPUT_LIMIT_BYTES = 2 * 1024 * 1024


def read_daemon_query_input(stream: TextIO) -> str | None:
    """The query input the edge wrote to stdin, or ``None`` past the limit."""

    text = stream.read(_INPUT_LIMIT_BYTES + 1)
    return None if len(text) > _INPUT_LIMIT_BYTES else text


def run_daemon_query(query: str, guard_home: Path, output_stream: TextIO, input_text: str | None = "") -> int:
    """Print the answer to ``query`` as one JSON envelope; 2 for a bad request."""

    answer = _QUERIES.get(query)
    payload: object = {}
    if input_text is None:
        payload = None
    elif input_text:
        try:
            payload = json.loads(input_text)
        except json.JSONDecodeError:
            payload = None
    if answer is None or not isinstance(payload, dict):
        output_stream.write(json.dumps({"error": "unknown_query"}) + "\n")
        return 2
    status, body = answer(guard_home, payload)
    output_stream.write(json.dumps({"status": status, "body": body}, separators=(",", ":"), default=str) + "\n")
    return 0


__all__ = ["run_daemon_query"]
