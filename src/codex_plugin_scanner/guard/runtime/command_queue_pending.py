"""Upload a result a lane kept because its first upload failed."""

from __future__ import annotations

import logging
import urllib.error
from collections.abc import Callable
from functools import partial

from ..store import GuardStore
from .command_queue_protocol import pending_result_is_stale
from .command_queue_results import drop_refused_result, post_result_unless_refused
from .command_queue_state import command_queue_now, save_command_queue_state

_LOGGER = logging.getLogger("codex_plugin_scanner.guard.runtime.command_queue")


def retry_pending_result(
    store: GuardStore,
    auth_context: dict[str, object],
    state: dict[str, object],
    *,
    post_result: Callable[[dict[str, object], dict[str, object], dict[str, object]], None],
    resolve_auth: Callable[..., dict[str, object]],
    save_state: Callable[[GuardStore, dict[str, object]], None],
) -> bool:
    """Send the kept result; True when it was delivered and the lane is idle again."""

    pending = state.get("pending_result")
    if not isinstance(pending, dict):
        return False
    job = pending.get("job")
    payload = pending.get("payload")
    if not isinstance(job, dict) or not isinstance(payload, dict):
        state.pop("pending_result", None)
        state.pop("active_job", None)
        save_state(store, state)
        return False
    if pending_result_is_stale(job):
        _LOGGER.warning("Guard command dropped stale pending result.")
        state.pop("pending_result", None)
        state.pop("active_job", None)
        state["state"] = "idle"
        state["last_error"] = None
        save_state(store, state)
        return False
    try:
        refused = post_result_unless_refused(partial(post_result, auth_context, job, payload))
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        _LOGGER.warning("Pending Guard result 401, attempting OAuth refresh retry.")
        refreshed_auth_context = resolve_auth(store, force_refresh=True)
        refused = post_result_unless_refused(partial(post_result, refreshed_auth_context, job, payload))
    if refused is not None:
        drop_refused_result(store, state, job, refused, save_state=save_state)
        return False
    state.pop("pending_result", None)
    state.pop("active_job", None)
    state.update(
        {
            "state": "idle",
            "last_result_at": command_queue_now(),
            "last_error": None,
            "last_poll_was_empty": False,
        }
    )
    save_state(store, state)
    return True


def hold_pending_result(
    store: GuardStore,
    state: dict[str, object],
    job: dict[str, object],
    payload: dict[str, object],
) -> None:
    """Keep a settled job's result in this lane's state until its upload succeeds."""

    _LOGGER.warning("Guard command result upload failed.")
    pending = {"job": job, "payload": payload, "recorded_at": command_queue_now()}
    state.update({"state": "result_pending", "pending_result": pending})
    save_command_queue_state(store, state)


__all__ = ["hold_pending_result", "retry_pending_result"]
