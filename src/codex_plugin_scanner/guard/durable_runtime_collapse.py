"""Let older durable runtime copies share the current copy's file.

A frozen build pins ``<guard_home>/native-runtime/<sha256>/hol-guard-runtime``
in hook commands, and every update leaves one more full copy behind. The
native runtime owns the proof and the relink (``durable-runtime-collapse``):
an older copy is never removed, only replaced by a hard link to the current
verified copy, and any doubt keeps it.
"""

from __future__ import annotations

import sys
from pathlib import Path

_FEATURE = "native-durable-runtime-collapse-v1"
_COMMAND = "durable-runtime-collapse"
_SCHEMA = "durable-runtime-collapse.v1"
_OUTPUT_LIMIT = 4 * 1024
# The runtime stops itself after 30 seconds of work.
_TIMEOUT_SECONDS = 45.0
_OUTCOMES = frozenset({"ok", "unsupported", "unavailable"})


def _current_digest() -> str | None:
    """The digest this frozen build pins in hook commands, or None."""

    if not getattr(sys, "frozen", False):
        return None
    from .native_runtime import native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        return None
    return status.identity.sha256


def collapse_durable_runtimes(guard_home: Path) -> dict[str, object] | None:
    """The runtime's collapse report, or ``None`` when there is nothing to ask or no answer."""

    digest = _current_digest()
    if digest is None:
        return None
    from .mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _FEATURE,
        _COMMAND,
        {"schema": _SCHEMA, "guard_home": str(guard_home.absolute()), "current_digest": digest},
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )
    return answer if answer is not None and _valid_report(answer) else None


def _valid_report(answer: dict[str, object]) -> bool:
    counts = (answer.get("collapsed"), answer.get("reclaimed_bytes"))
    errors = answer.get("errors")
    kept = answer.get("kept")
    return (
        answer.get("outcome") in _OUTCOMES
        and type(answer.get("budget_exhausted")) is bool
        and all(type(count) is int and count >= 0 for count in counts)
        and isinstance(errors, list)
        and all(isinstance(error, str) for error in errors)
        and isinstance(kept, dict)
        and all(isinstance(reason, str) and type(count) is int for reason, count in kept.items())
    )


__all__ = ["collapse_durable_runtimes"]
