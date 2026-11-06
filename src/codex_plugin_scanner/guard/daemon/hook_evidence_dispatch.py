"""Run a finished hook's evidence off the thread that answered it.

Recording what a hook decided never changes what it decided. The receipt, the
command activity and the Composio discovery are written after the verdict is
settled, and the caller waiting on the hook response gains nothing by waiting
for them.

While the writer was a Python object in this process, that cost nothing worth
naming: a submission pushed a record onto an in-process queue. The writer now
lives in the resident, so each submission is a round trip, and three of them
per hook sat in front of the response the harness was waiting for. This moves
them behind it.

The dispatch is one thread with a bounded queue, so a hook's receipt is always
submitted before the activity that links to it and one hook's evidence is
always submitted before the next hook's. Its calls are labelled as the
background traffic they are, the same way the daemon's own evidence drain is.

Nothing here decides anything or holds a record that the writer would
otherwise keep: the resident still owns the queue, the journal and the store.
Order outranks delivery here, because a record that overtakes the one it links
to is read as a contradiction rather than as a gap: a post event that reaches
the writer before its own pre event is stored as explicitly unpaired, and the
pre event that follows it stays `allowed_unconfirmed` for good. So a caller
that finds the queue full waits briefly for a slot and then drops the record,
which is what the resident's own writer does when its queue overflows. Only a
host with no dispatch at all runs the work inline, where there is no queued
record for it to overtake.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable
from typing import Final

from ..native_resident_client import background_resident_requests

# The label the resident request log counts this traffic under. The hook
# budget test reads it to tell a hook's own round trips from the ones a
# daemon thread spends on its own schedule.
BACKGROUND_LABEL: Final = "hook_evidence_writer_drain"

# Three submissions per hook, so this holds the evidence of a few hundred
# hooks. A queue this deep is already a resident that has stopped answering,
# and the next caller runs its own work rather than growing the backlog.
_MAX_PENDING: Final = 1024

# How long a caller waits for a slot before its record is dropped. A queue
# this deep means the resident has stopped answering, so the wait is short
# enough that a wedged writer cannot hold up the hook response it sits behind.
_ENQUEUE_WAIT_SECONDS: Final = 0.05

_LOGGER: Final = logging.getLogger(__name__)


class HookEvidenceDispatch:
    """A single ordered worker for evidence a finished hook left behind."""

    def __init__(self, *, max_pending: int = _MAX_PENDING) -> None:
        self._queue: queue.Queue[Callable[[], object] | None] = queue.Queue(maxsize=max(1, max_pending))
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._run, name="hol-guard-hook-evidence-dispatch", daemon=True)
        self._thread.start()

    def run(self, work: Callable[[], object]) -> None:
        """Take `work` for the dispatch thread, in the order it arrived.

        A record is never run on the calling thread while earlier records are
        still queued: that would let a hook's later evidence reach the writer
        before its earlier evidence. A caller that cannot get a slot inside
        the wait drops its record instead.
        """

        if not self._stopping.is_set() and self._thread.is_alive():
            try:
                self._queue.put(work, timeout=_ENQUEUE_WAIT_SECONDS)
            except queue.Full:
                _LOGGER.debug("Hook evidence dispatch is full; the record was dropped to keep order.")
            return
        _run_quietly(work)

    def flush(self, timeout_seconds: float = 1.0) -> bool:
        """Wait for the evidence already taken to be submitted.

        Reports `False` when the marker itself was dropped by a full queue,
        which is the same answer it gives when the queue drains too slowly.
        """

        done = threading.Event()
        self.run(done.set)
        return done.wait(max(0.0, timeout_seconds))

    def stop(self, timeout_seconds: float = 1.0) -> bool:
        """Submit what is queued, then leave the thread.

        The budget is the whole wait, not a wait per record: a resident that
        has stopped answering must not hold the daemon's shutdown open for as
        long as the queue is deep.
        """

        deadline = time.monotonic() + max(0.0, timeout_seconds)
        if not self._stopping.is_set():
            self._stopping.set()
            # The sentinel goes through the same queue as the work, so the
            # thread leaves only after it has submitted everything taken
            # before the stop. A full queue is one the worker is draining, so
            # the sentinel waits for a slot inside the budget rather than
            # being dropped, which would park the thread on an empty queue
            # that nothing will ever close.
            try:
                self._queue.put(None, timeout=max(0.0, deadline - time.monotonic()))
            except queue.Full:
                # Nothing drained the queue in the budget that was left. The
                # records in it are evidence of hooks that have already
                # answered, the thread is a daemon, and the resident keeps its
                # own journal of what it accepted.
                _LOGGER.debug("Hook evidence dispatch stopped with a full queue.")
        self._thread.join(max(0.0, deadline - time.monotonic()))
        return not self._thread.is_alive()

    def _run(self) -> None:
        with background_resident_requests(BACKGROUND_LABEL):
            while True:
                work = self._queue.get()
                if work is None:
                    return
                _run_quietly(work)


def _run_quietly(work: Callable[[], object]) -> None:
    """Record what a hook decided without letting the recording raise.

    Every caller already wrapped its own submission this way: a hook that has
    answered must not fail because its evidence could not be written.
    """

    try:
        work()
    except Exception:
        _LOGGER.debug("Hook evidence was not recorded.", exc_info=True)


def run_hook_evidence(host: object, work: Callable[[], object]) -> None:
    """Hand `work` to `host`'s dispatch, or run it here when it has none."""

    dispatch = getattr(host, "evidence_dispatch", None)
    if isinstance(dispatch, HookEvidenceDispatch):
        dispatch.run(work)
        return
    _run_quietly(work)


__all__ = ["BACKGROUND_LABEL", "HookEvidenceDispatch", "run_hook_evidence"]
