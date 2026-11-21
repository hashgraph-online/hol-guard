"""The resident runtime's day, as its lifecycle journal counts it, for ``doctor``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, cast

from typing_extensions import TypedDict

from ..command_probes import command_probes_enabled
from ..native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY

# JSON has no integer bound; the runtime writes every count as a u32.
_MAX_U32 = 2**32 - 1


def _counter(value: object, bound: int) -> int | None:
    """A non-negative integer the runtime could have written, or ``None``.

    ``bool`` is an ``int`` in Python and none of these fields is ever written
    as one, so a boolean is as wrong here as a string.
    """

    if not isinstance(value, int) or isinstance(value, bool):
        return None
    if value < 0 or value > bound:
        return None
    return value


class NativeResidentLifecycle(TypedDict, total=False):
    """A day of this install's resident lifecycle; older runtimes omit the cold-start bands."""

    state: Literal["healthy", "degraded", "critical"]
    starts: int
    orderly_exits: int
    failed_exits: int
    premature_exits: int
    refused_starts: int
    last_event: str
    last_event_age_seconds: int
    window_age_seconds: int
    cold_starts_within_1s: int
    cold_starts_within_5s: int
    cold_starts_slower: int


_LIFECYCLE_STATES = ("healthy", "degraded", "critical")
_LIFECYCLE_COUNTS = ("starts", "orderly_exits", "failed_exits", "premature_exits", "refused_starts")
_LIFECYCLE_AGES = ("last_event_age_seconds", "window_age_seconds")
_LIFECYCLE_COLD_STARTS = ("cold_starts_within_1s", "cold_starts_within_5s", "cold_starts_slower")
_LIFECYCLE_FIELDS = frozenset({"state", "last_event", *_LIFECYCLE_COUNTS, *_LIFECYCLE_AGES})
_LIFECYCLE_FIELDS_WITH_COLD_STARTS = _LIFECYCLE_FIELDS | frozenset(_LIFECYCLE_COLD_STARTS)
# The runtime writes the counts as a u32 and the ages as seconds inside a
# one-day window, measured from the start of the hour an event fell in, so a
# day plus that hour is the most either age can honestly be. Anything past it
# did not come from a journal this runtime wrote.
_MAX_LIFECYCLE_AGE_SECONDS = 25 * 60 * 60
# The runtime's whole event vocabulary, as `resident_lifecycle_journal`
# spells it, plus the empty string for a window with no event left in it. A
# code outside this set is not one the runtime can have written, so it is a
# damaged or forged answer and not a new event this build has not heard of.
_LIFECYCLE_EVENTS = frozenset(
    {
        "",
        "started",
        "exited_orderly",
        "exited_failed",
        "exited_premature",
        "start_refused",
    }
)
_LIFECYCLE_TIMEOUT_SECONDS = 5.0
_LIFECYCLE_OUTPUT_LIMIT = 8 * 1024


def _validated_lifecycle(value: object) -> NativeResidentLifecycle | None:
    """The runtime's snapshot, or ``None`` when what came back is not one.

    Every field is checked against the shape the runtime documents rather than
    passed through: this report is read out to users and carried in support
    bundles, so a damaged or forged journal must not be able to put text of its
    own in front of a reader.
    """

    if not isinstance(value, dict) or set(value) not in (_LIFECYCLE_FIELDS, _LIFECYCLE_FIELDS_WITH_COLD_STARTS):
        return None
    if value["state"] not in _LIFECYCLE_STATES:
        return None
    last_event = value["last_event"]
    # The set lookup hashes what it is given, so an answer that put a list or
    # a mapping here would raise rather than be refused.
    if not isinstance(last_event, str) or last_event not in _LIFECYCLE_EVENTS:
        return None
    bounds: dict[str, int] = dict.fromkeys(_LIFECYCLE_COUNTS, _MAX_U32)
    bounds.update(dict.fromkeys(_LIFECYCLE_AGES, _MAX_LIFECYCLE_AGE_SECONDS))
    bounds.update(dict.fromkeys(set(_LIFECYCLE_COLD_STARTS) & set(value), _MAX_U32))
    for field, bound in bounds.items():
        if _counter(value[field], bound) is None:
            return None
    return cast(NativeResidentLifecycle, cast(object, value))


def native_resident_lifecycle(guard_home: Path | None) -> NativeResidentLifecycle | None:
    """What the runtime says this install's resident has been doing all day.

    The journal behind this answers the question a support request asks and the
    live counters cannot: whether enforcement has been healthy today, or has
    been failing and recovering all along. It is asked of the runtime rather
    than read out of its file, because the state the runtime derives from those
    counts is the runtime's to derive; Python forwards the question and checks
    the shape of the answer.

    Reading it runs the runtime binary, which the read-only commands promise
    not to do, so a caller inside ``without_command_probes`` gets ``None``.
    ``None`` also covers a fresh install with no history, a runtime that is not
    installed and a reply that does not look like a snapshot: in none of those
    cases has this install been shown to be unhealthy.

    The subcommand reads the journal file and returns; it starts no resident
    and spends none of the restart budget.
    """

    if guard_home is None:
        return None
    if not command_probes_enabled():
        return None

    from ..native_runtime import _run_native_process, native_runtime_status

    try:
        status = native_runtime_status()
    except (OSError, RuntimeError, ValueError):
        return None
    if status.identity is None or not status.available or not status.compatible:
        return None
    state_base = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
    try:
        answer = _run_native_process(
            status.identity.path,
            ("resident-health", "--state-dir", str(state_base)),
            input_text="",
            timeout_seconds=_LIFECYCLE_TIMEOUT_SECONDS,
            output_limit=_LIFECYCLE_OUTPUT_LIMIT,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    if answer is None:
        return None
    try:
        payload = json.loads(answer)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    return _validated_lifecycle(payload.get("health"))
