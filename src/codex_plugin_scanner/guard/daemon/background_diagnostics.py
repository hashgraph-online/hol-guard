"""Module-level diagnostic sink for background workers without a daemon handle.

A catalog preparation or publication thread runs outside every HTTP request and
holds no daemon object, so a failure there has nowhere to report. The daemon
installs its diagnostics here once it has a log file and releases them when it
closes. With no sink installed the record is dropped, which keeps a one-shot
hook off the daemon's file I/O on the fail-closed path.

Callers pass an event name and one bounded detail line. ``failure_detail``
builds that line from an exception without letting a path or a secret through,
because daemon.log is a support artifact an operator may hand over. Nothing
here reads a record back, so no decision depends on whether a sink was
installed.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from contextlib import suppress

from ..secret_redaction import sanitize_secret

BackgroundSink = Callable[[str, str], object]

_MAX_FAILURE_DETAIL = 160
# Background work wraps arbitrary OS errors, whose text carries the file that
# failed. Every path-shaped run goes. A quoted path may contain spaces, so a
# quoted run goes whole before the unquoted runs are matched.
_QUOTED_PATH = re.compile(r"'[^']*[/\\][^']*'|\"[^\"]*[/\\][^\"]*\"")
_PATH_LIKE = re.compile(r"[^\s'\"]*[/\\][^\s'\"]*")
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")

_lock = threading.Lock()
_sink: BackgroundSink | None = None


def install_sink(sink: BackgroundSink) -> None:
    """Route later background events to ``sink`` until it is released."""

    global _sink
    with _lock:
        _sink = sink


def release_sink(sink: BackgroundSink) -> None:
    """Stop routing to ``sink``; a newer daemon's sink is left alone."""

    global _sink
    with _lock:
        if _sink == sink:
            _sink = None


def record_background_event(event: str, detail: str) -> bool:
    """Record one background diagnostic. Returns whether a sink took it."""

    with _lock:
        sink = _sink
    if sink is None:
        return False
    # A background worker must never die because diagnostics are closing.
    with suppress(Exception):
        sink(event, detail)
        return True
    return False


def failure_detail(error: BaseException) -> str:
    """One bounded, path-free line naming a failure and its type."""

    if isinstance(error, OSError) and (error.filename is not None or error.filename2 is not None):
        # The file names are the only part of an OS error that could leak.
        text = f"[Errno {error.errno}] {error.strerror}"
    else:
        text = str(error)
    text = _UNPRINTABLE.sub(" ", text)
    message = sanitize_secret(_PATH_LIKE.sub("<path>", _QUOTED_PATH.sub("<path>", text))).strip()
    if len(message) > _MAX_FAILURE_DETAIL:
        message = message[:_MAX_FAILURE_DETAIL] + "..."
    return f"error={type(error).__name__}" + (f" detail={message}" if message else "")


__all__ = [
    "BackgroundSink",
    "failure_detail",
    "install_sink",
    "record_background_event",
    "release_sink",
]
