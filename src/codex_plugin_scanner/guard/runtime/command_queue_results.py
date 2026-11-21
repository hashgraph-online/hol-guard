"""Command results that Guard Cloud refuses outright."""

from __future__ import annotations

import logging
import urllib.error
from collections.abc import Callable

from ..store import GuardStore
from .command_capability import audit_command_decision
from .command_queue_state import transition_command_queue_state

_LOGGER = logging.getLogger(__name__)

# Guard Cloud answered this exact result with a permanent refusal: the lease
# went stale, the payload was malformed, or the result conflicts with what
# Cloud already recorded. Resending the same bytes cannot succeed, so holding
# the result as pending would stall every later job until its lease expires.
REFUSED_RESULT_STATUSES = frozenset({400, 404, 409, 410, 422})


def post_result_unless_refused(post: Callable[[], None]) -> urllib.error.HTTPError | None:
    """Upload one result, returning Cloud's refusal instead of raising it.

    Only the result upload is covered: a refused heartbeat says nothing about
    the result, so callers keep heartbeats outside this helper.
    """

    try:
        post()
    except urllib.error.HTTPError as error:
        if error.code in REFUSED_RESULT_STATUSES:
            return error
        raise
    return None


def drop_refused_result(
    store: GuardStore,
    state: dict[str, object],
    job: dict[str, object],
    error: urllib.error.HTTPError,
) -> None:
    _LOGGER.warning("Guard Cloud refused a command result (HTTP %s); dropping it.", error.code)
    transition_command_queue_state(store, state, "result_refused")
    audit_command_decision(store, "cloud_command.result_refused", job=job, reason=f"http_{error.code}")
