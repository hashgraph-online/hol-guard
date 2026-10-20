"""Daemon facts the resident needs to queue a reviewed ``PreToolUse`` itself.

When the daemon pauses a reviewed ``PreToolUse`` for approval it reads the
blocked-request mode from Guard config, links the approval center from its
runtime state, binds the queued request to its store's connection source, and
rebuilds the action envelope with its own working directory. A resident that
queues such a request without the daemon needs those same four facts, as the
daemon had them when it published. A fact the resident cannot accept is left
out, so such a hook defers to this daemon.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable, Mapping

# The resident accepts the review facts below in its direct-lane binding.
DIRECT_HOOK_REVIEW_FACTS_FEATURE = "hook-direct-review-facts-v1"

# Mirrors the resident limits in guard-policy-snapshot's direct_lane module.
_MAX_REVIEW_FACT_BYTES = 256
_MAX_PATH_BYTES = 4096
_BLOCKED_REQUEST_MODES = frozenset({"ask", "safe-alternative"})


def review_facts_bound(features: Iterable[str]) -> bool:
    return DIRECT_HOOK_REVIEW_FACTS_FEATURE in set(features)


def _text_fact(value: object, limit: int) -> str | None:
    if not isinstance(value, str) or not value or "\0" in value:
        return None
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None
    return value if length <= limit else None


def uniform_blocked_request_mode(configs: Iterable[object]) -> str | None:
    """The blocked-request mode every compiled config resolves to.

    The daemon reads the mode for the hook's own workspace. A binding covers
    the home and every settled workspace, so it carries a mode only when they
    all agree; otherwise such a hook defers to this daemon.
    """

    modes = {getattr(config, "blocked_request_mode", None) for config in configs}
    if len(modes) != 1:
        return None
    (mode,) = modes
    return mode if isinstance(mode, str) and mode in _BLOCKED_REQUEST_MODES else None


class _ReadState:
    """A store whose runtime state was already read once."""

    def __init__(self, state: object) -> None:
        self._state = state

    def get_runtime_state(self) -> object:
        return self._state


def _records_listen_origin(state: object) -> bool:
    if not isinstance(state, dict):
        return False
    center = state.get("approval_center_url")
    if isinstance(center, str) and center.strip():
        return True
    port = state.get("daemon_port")
    return isinstance(state.get("daemon_host"), str) and isinstance(port, int) and port > 0


def _read_origin(store: object) -> tuple[bool, str | None]:
    # The daemon falls back to the default origin until its runtime state
    # records where it listens, and when that state is unreadable. That
    # fallback is not the origin the daemon links once the state lands, so
    # neither case binds an origin; an unreadable state reports itself as
    # unknown so a transient lock reads as no change.
    from .daemon.native_review_records import native_review_approval_center_url

    getter = getattr(store, "get_runtime_state", None)
    if not callable(getter):
        return True, None
    try:
        state = getter()
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False, None
    if not _records_listen_origin(state):
        return True, None
    return True, _text_fact(native_review_approval_center_url(_ReadState(state)), _MAX_REVIEW_FACT_BYTES)


def approval_center_origin(store: object) -> str | None:
    """The approval center origin the daemon links a queued review to.

    A runtime state that is unreadable or does not yet record where the daemon
    listens binds no origin, so a reviewed hook defers.
    """

    return _read_origin(store)[1]


def review_host_cwd() -> str | None:
    """The working directory the daemon rebuilds the action envelope with."""

    try:
        cwd = os.getcwd()
    except OSError:
        return None
    return _text_fact(cwd, _MAX_PATH_BYTES)


def _review_oauth_source(store: object) -> str | None:
    # ``add_approval_request`` binds a queued request to this source.
    return _text_fact(getattr(store, "_guard_source", None), _MAX_REVIEW_FACT_BYTES)


def recheckable_review_facts(store: object) -> tuple[str | None, str | None] | None:
    """The review facts that no watched policy input covers.

    ``None`` when the runtime state could not be read, so a transient lock
    neither reads as a moved origin nor closes the lane.
    """

    readable, origin = _read_origin(store)
    if not readable:
        return None
    return origin, review_host_cwd()


def with_review_facts(
    binding: Mapping[str, object] | None,
    *,
    store: object,
    features: Iterable[str],
    blocked_request_mode: str | None,
) -> dict[str, object] | None:
    """Add the review facts, for a resident that accepts them."""

    if binding is None:
        return None
    bound = dict(binding)
    if not review_facts_bound(features):
        return bound
    facts = {
        "blocked_request_mode": blocked_request_mode if blocked_request_mode in _BLOCKED_REQUEST_MODES else None,
        "approval_center_origin": approval_center_origin(store),
        "review_oauth_source": _review_oauth_source(store),
        "review_host_cwd": review_host_cwd(),
    }
    bound.update({name: value for name, value in facts.items() if value is not None})
    return bound
