"""Ask the runtime whether a degraded background loop may run again, and log.

The runtime keeps one small ledger per Guard home that outlives the library
process. It decides how long a failing loop waits before trying again and
whether a failure is new enough to log; see ``background_loop_gate.rs``. This
module only forwards the question and checks the answer's shape.

Every helper falls back to what the loop did before the ledger existed: a
loop runs when the runtime cannot answer, and a failure it could not gate is
logged. None of these loops decides whether a command is allowed.

A line counts as said only when a sink took it. The ledger is told so with
the ``logged`` op; a line no sink took is offered again on the next outcome.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from pathlib import Path

from .background_diagnostics import record_background_event, record_background_notice

FEATURE = "native-background-loop-gate-v1"
_COMMAND = "background-loop-gate"
_SCHEMA = "hol-guard-background-loop-gate.v1"
_OUTPUT_LIMIT = 8 * 1024
_TIMEOUT_SECONDS = 2.0

CATALOG_REFRESH = "catalog_publication_refresh"
AUTHORITY_ENROLLMENT = "default_authority_enrollment"
AUTHORITY_MIGRATION = "installed_authority_migration"
LOOPS = (CATALOG_REFRESH, AUTHORITY_ENROLLMENT, AUTHORITY_MIGRATION)
_STATES = ("healthy", "failing")
_FAILING_FIELDS = frozenset({"loop", "state", "failures", "failing_for_seconds", "next_attempt_in_seconds"})
_MAX_COUNT = 2**64 - 1
# Startup loops this process has already reported healthy to the ledger, so a
# later success here costs no runtime call. A failure reported here clears the
# entry. A failure reported by another process is not seen here: it stays in
# the ledger until a process without this entry reports a success. Until then
# `doctor` shows the loop failing, and a later failure in this process extends
# that streak instead of starting a new one. These loops are never held back,
# so the cost is a status line and a longer streak, not a skipped run. The
# catalog refresh is asked every time, because its wait is what the ledger is
# for.
_settled: set[tuple[str, str]] = set()
_settled_lock = threading.Lock()


def _ask(
    guard_home: Path, op: str, loop: str | None = None, failure_key: str | None = None
) -> Mapping[str, object] | None:
    from ..mdm.runtime_request import runtime_answer

    request: dict[str, object] = {"schema": _SCHEMA, "guard_home": str(guard_home), "op": op}
    if loop is not None:
        request["loop"] = loop
    if failure_key is not None:
        request["failure_key"] = failure_key
    try:
        answer = runtime_answer(
            FEATURE, _COMMAND, request, output_limit=_OUTPUT_LIMIT, timeout_seconds=_TIMEOUT_SECONDS
        )
    except Exception:
        return None
    if not isinstance(answer, Mapping) or answer.get("ok") is not True:
        return None
    return answer


def may_attempt(guard_home: Path, loop: str) -> bool:
    """Whether ``loop`` may run now; a failing loop waits longer each time."""

    answer = _ask(guard_home, "attempt", loop)
    return answer is None or answer.get("run") is not False


def failure_is_due(guard_home: Path, loop: str, failure_key: str) -> tuple[bool, str]:
    """Count one failure of ``loop`` and say whether it is worth a log line.

    ``failure_key`` names the kind of failure, not its text: a loop that keeps
    failing the same way is logged when it starts, then every few hours with
    the number of attempts that were not logged in between. The second value
    is that count, ready to append to a detail line.
    """

    with _settled_lock:
        _settled.discard((str(guard_home), loop))
    answer = _ask(guard_home, "outcome", loop, failure_key)
    if answer is None:
        return True, ""
    if answer.get("log") is False:
        return False, ""
    suffix = ""
    failures, repeats = answer.get("failures"), answer.get("repeats")
    if _count(failures):
        suffix += f" failures={failures}"
    if _count(repeats) and repeats:
        suffix += f" unlogged_repeats={repeats}"
    return True, suffix


def failure_logged(guard_home: Path, loop: str, failure_key: str) -> None:
    """Tell the ledger a sink took the line ``failure_is_due`` offered."""

    _ = _ask(guard_home, "logged", loop, failure_key)


def report_failure(guard_home: Path, loop: str, failure_key: str, lines: tuple[tuple[str, str], ...]) -> None:
    """Log each ``(event, detail)`` line when this failure is new, changed or due again."""

    due, suffix = failure_is_due(guard_home, loop, failure_key)
    if not due:
        return
    taken = [record_background_event(event, detail + suffix) for event, detail in lines]
    if all(taken):
        failure_logged(guard_home, loop, failure_key)


def report_success(guard_home: Path, loop: str) -> None:
    """Clear ``loop``'s failure streak and say once that it recovered."""

    key = (str(guard_home), loop)
    cached = loop != CATALOG_REFRESH
    with _settled_lock:
        if cached and key in _settled:
            return
    answer = _ask(guard_home, "outcome", loop)
    if answer is None:
        return
    if answer.get("recovered") is True and _count(answer.get("failures")):
        if not record_background_notice(f"{loop}_recovered", f"failures={answer['failures']}"):
            # No sink took it, so the ledger offers it again on the next
            # success; this process must ask again rather than settle.
            return
        if _ask(guard_home, "logged", loop) is None:
            # The ledger still holds the recovery as unsaid; settling now
            # would skip the next success that could confirm it.
            return
    if cached:
        with _settled_lock:
            _settled.add(key)


def loop_status(guard_home: Path) -> list[dict[str, object]] | None:
    """Each loop's state for ``doctor``, or ``None`` when the runtime cannot say."""

    answer = _ask(guard_home, "status")
    loops = answer.get("loops") if answer is not None else None
    if not isinstance(loops, list) or len(loops) != len(LOOPS):
        return None
    validated: list[dict[str, object]] = []
    for name, entry in zip(LOOPS, loops, strict=True):
        if not isinstance(entry, dict) or entry.get("loop") != name or entry.get("state") not in _STATES:
            return None
        if entry["state"] == "healthy":
            if set(entry) != {"loop", "state"}:
                return None
        elif set(entry) != _FAILING_FIELDS or not all(
            _count(entry[field]) for field in _FAILING_FIELDS - {"loop", "state"}
        ):
            return None
        validated.append(dict(entry))
    return validated


def _count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_COUNT


__all__ = [
    "AUTHORITY_ENROLLMENT",
    "AUTHORITY_MIGRATION",
    "CATALOG_REFRESH",
    "FEATURE",
    "failure_is_due",
    "failure_logged",
    "loop_status",
    "may_attempt",
    "report_failure",
    "report_success",
]
