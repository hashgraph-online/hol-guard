"""Fail-closed reconciliation of the inputs behind a published native snapshot."""

from __future__ import annotations

import logging
import sqlite3
from typing import TYPE_CHECKING

from .native_policy_snapshot_constants import NativePolicySnapshotError

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher

logger = logging.getLogger(__name__)

# Errors a store or filesystem read can raise while another process holds the
# database. They say nothing about whether the policy changed.
_UNREADABLE_INPUT_ERRORS = (NativePolicySnapshotError, OSError, RuntimeError, ValueError, sqlite3.Error)


def _local_cli_revision_or_none(publisher: NativePolicySnapshotPublisher) -> int | None:
    try:
        return publisher._current_local_cli_revision()
    except _UNREADABLE_INPUT_ERRORS:
        # -1 is never a bound revision, so an unreadable one closes the lane.
        return -1


def reconcile_policy_inputs(publisher: NativePolicySnapshotPublisher) -> None:
    """Republish when a policy input moved, and treat an unreadable one as moved.

    Every check here reads the store. Under cross-process load SQLite can give
    up on a read lock with ``locking protocol`` or ``database is locked``. If
    that escaped, the publisher thread would end and no later policy edit
    would be published for the life of the process. An input that cannot be
    read may have changed, so it gets the same answer as a detected change:
    the direct lane closes, a republish is queued, and the next poll reads
    again.
    """

    try:
        _reconcile(publisher)
    except _UNREADABLE_INPUT_ERRORS:
        logger.debug("Native policy inputs could not be read; republishing", exc_info=True)
        _treat_inputs_as_changed(publisher)


def _reconcile(publisher: NativePolicySnapshotPublisher) -> None:
    fingerprint = publisher._current_input_fingerprint()
    if publisher._input_fingerprint is None:
        publisher._input_fingerprint = fingerprint
    elif fingerprint[1] != publisher._input_fingerprint[1]:
        publisher._accept_resident_fingerprint(fingerprint)
    elif fingerprint[0] != publisher._input_fingerprint[0]:
        previous_inputs = dict(publisher._input_fingerprint[0])
        current_inputs = dict(fingerprint[0])
        changed_paths = {
            path
            for path in previous_inputs.keys() | current_inputs.keys()
            if previous_inputs.get(path) != current_inputs.get(path)
        }
        publisher._input_fingerprint = fingerprint
        if publisher._policy_input_changed(changed_paths):
            publisher._republish_preserving_watch()
    if publisher._monotonic_clock() >= publisher._reconcile_due_monotonic:
        publisher._reconcile_due_monotonic = publisher._monotonic_clock() + 1.0
        if publisher._policy_input_changed():
            publisher._republish_preserving_watch()
        publisher._recheck_direct_lane_local_cli(_local_cli_revision_or_none(publisher))
        publisher._recheck_direct_lane_review_facts()
        publisher._recheck_direct_lane_structured_output()
        publisher._recheck_direct_lane_mcp_relay()
        publisher._recheck_direct_lane_saved_state()


def _treat_inputs_as_changed(publisher: NativePolicySnapshotPublisher) -> None:
    publisher._close_direct_lane_ack()
    with publisher._condition:
        # A pending publish compiles every input from scratch. Requeueing it
        # on each failed poll would reset its retry backoff.
        publish_pending = not publisher._acked or publisher._renewal_after_generation is not None
    if not publish_pending:
        publisher._republish_preserving_watch()
