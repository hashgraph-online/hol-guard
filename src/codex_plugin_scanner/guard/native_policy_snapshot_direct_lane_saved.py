"""Daemon state the resident reads a saved exact-action decision with.

The daemon asks the resident for an exact-action proof with its own process
environment and extension-control digest, and verifies the saved decision
against the policy-integrity state it stored. A resident that answers a
reviewed ``PreToolUse`` from a saved decision needs all three, as the daemon
had them when it published. Any value the resident cannot accept is left out,
so such a hook defers to this daemon.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import AbstractContextManager
from typing import cast

from .native_policy_snapshot_direct_lane import DIRECT_HOOK_SAVED_DECISION_FEATURE
from .runtime.extension_control_runtime import current_extension_control_binding_digest

# Mirrors the resident limits in guard-policy-snapshot's direct_lane module.
_MAX_ENVIRONMENT_ENTRIES = 1024
_MAX_ENVIRONMENT_BYTES = 262_144
_MAX_STATE_FIELD_BYTES = 256
_MAX_DEGRADED_REASONS = 16
_U64_MAX = (1 << 64) - 1
_STATE_FIELDS = frozenset(
    {"backend", "cutover_complete", "degraded_reasons", "enforcement", "generation", "key_id", "mode"}
)


def saved_decision_bound(features: Iterable[str]) -> bool:
    return DIRECT_HOOK_SAVED_DECISION_FEATURE in set(features)


def _utf8_len(value: str) -> int | None:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _environment() -> dict[str, str] | None:
    # ``native_exact_action`` sends every text entry of ``os.environ``.
    environment = {name: value for name, value in os.environ.items() if isinstance(value, str)}
    if len(environment) > _MAX_ENVIRONMENT_ENTRIES:
        return None
    total = 0
    for name, value in environment.items():
        name_len, value_len = _utf8_len(name), _utf8_len(value)
        if name_len is None or value_len is None or not name or "=" in name or "\0" in name or "\0" in value:
            return None
        total += name_len + value_len
    return environment if total <= _MAX_ENVIRONMENT_BYTES else None


def _state_field_valid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    length = _utf8_len(value)
    return (
        length is not None
        and length <= _MAX_STATE_FIELD_BYTES
        and not any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value)
    )


def _integrity_state(store: object) -> dict[str, object] | None:
    connect = getattr(store, "_connect", None)
    load = getattr(store, "_load_policy_integrity_state", None)
    if not callable(connect) or not callable(load):
        return None
    try:
        with cast("AbstractContextManager[object]", connect()) as connection:
            state = load(connection)
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        return None
    if not isinstance(state, Mapping) or set(state) != _STATE_FIELDS:
        return None
    generation = state["generation"]
    key_id = state["key_id"]
    reasons = state["degraded_reasons"]
    if (
        not isinstance(state["cutover_complete"], bool)
        or not all(_state_field_valid(state[field]) for field in ("backend", "enforcement", "mode"))
        or not (key_id is None or _state_field_valid(key_id))
        or not (generation is None or (type(generation) is int and 0 <= generation <= _U64_MAX))
        or not isinstance(reasons, list)
        or len(reasons) > _MAX_DEGRADED_REASONS
        or not all(_state_field_valid(reason) for reason in reasons)
    ):
        return None
    return dict(state)


def with_saved_decision_state(
    binding: Mapping[str, object] | None,
    *,
    store: object,
    features: Iterable[str],
) -> dict[str, object] | None:
    """Add the exact-action state, for a resident that answers saved decisions."""

    if binding is None:
        return None
    bound = dict(binding)
    if not saved_decision_bound(features):
        return bound
    environment = _environment()
    digest = current_extension_control_binding_digest()
    state = _integrity_state(store)
    if environment is None or state is None or not _state_field_valid(digest):
        return bound
    bound["exact_action_environment"] = environment
    bound["exact_action_control_digest"] = digest
    bound["policy_integrity_state"] = state
    return bound
