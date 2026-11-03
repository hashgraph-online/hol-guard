"""Queue-time coverage hint: which extension governs which step of a paused command.

The allow hint answers one question — would enabling a few permissions let the
whole command run — and stays silent whenever the answer is no. Most paused
commands chain steps, so most of them get no hint at all even though an
extension plainly governs one of their steps.

This hint answers the weaker question the review screen still needs: which
extension matched which step. It is read straight out of the evidence the
resident already returned, so it costs no re-review and promises nothing. It
carries catalog identifiers and the matched executable basename only, and it
never implies that allowing one step's permission settles the others.

The resident computes it (``extension_coverage_hint.rs``) and owns the shape
checks for every stored hint (``extension_hint_shape``); this module asks it
for a checked copy and carries coverage on an allow hint.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import cast

EXTENSION_COVERAGE_HINT_SCHEMA = "guard.extension-coverage-hint.v1"
# A stored coverage hint describes a shell command, which the parser already
# bounds well below these limits; they only stop a malformed payload growing.
MAX_COVERED_SEGMENTS = 24
MAX_SEGMENT_IDS = 12
MAX_SEGMENT_TOTAL = 256
_KIND = "extension_hint_shape"
# Inside the runner allowance, so a slow check against a warm resident is the
# caller running out of time and never counts against the shared circuit.
_SHAPE_BUDGET_SECONDS = 4.0


# Checked answers by canonical hint text. A queue listing reads each row's
# hint, so repeats cost nothing; the bound only stops the map growing.
_SHAPES: dict[str, str] = {}
_MAX_SHAPES = 256


def _resident_warm() -> bool:
    """A cold resident keeps the runner's startup allowance instead of this budget."""

    from ..native_context import _native_runtime_status_memo, _resolve_digest_home
    from ..native_resident_client import native_resident_client_ready

    identity = _native_runtime_status_memo().identity
    return identity is not None and native_resident_client_ready(identity.path, _resolve_digest_home(None))


def _shape_answer(canonical: str, deadline_monotonic: float | None) -> str:
    cached = _SHAPES.get(canonical)
    if cached is not None:
        return cached
    from ..native_runner_authority import native_runner_authority

    if deadline_monotonic is None and _resident_warm():
        deadline_monotonic = time.monotonic() + _SHAPE_BUDGET_SECONDS
    answer = json.dumps(
        native_runner_authority(_KIND, {"hint": json.loads(canonical)}, deadline_monotonic=deadline_monotonic)
    )
    if len(_SHAPES) >= _MAX_SHAPES:
        _SHAPES.clear()
    _SHAPES[canonical] = answer
    return answer


def shaped_hint(
    value: object, key: str, *, deadline_monotonic: float | None = None, strict: bool = False
) -> dict[str, object] | None:
    """The runtime's checked copy of one kind of stored hint, or None.

    ``key`` is ``allow``, ``coverage`` or ``connector``. A hint only ever offers
    a choice, so a value the runtime cannot check is dropped like a bad one.
    ``strict`` raises instead when the check gives no answer, refused or
    unavailable, for callers that must not read a skipped hint as an absent one.
    ``deadline_monotonic`` keeps the check inside a caller's own budget.
    """

    if not isinstance(value, Mapping):
        return None
    from ..native_runner_authority import NativeRunnerAuthorityError

    try:
        canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
        answer = json.loads(_shape_answer(canonical, deadline_monotonic))
    except NativeRunnerAuthorityError:
        if strict:
            raise
        return None
    except (TypeError, ValueError):
        return None
    shaped = answer.get(key) if isinstance(answer, dict) else None
    return cast("dict[str, object]", shaped) if isinstance(shaped, dict) else None


def validated_extension_coverage_hint(
    value: object, *, deadline_monotonic: float | None = None
) -> dict[str, object] | None:
    """Return a shape-checked copy of a stored coverage hint, or None.

    Accepts both carriers: a standalone coverage hint, and the ``coverage`` key
    an allow hint carries when the command also earned a settling recommendation.
    """

    return shaped_hint(value, "coverage", deadline_monotonic=deadline_monotonic)


def with_extension_coverage(
    hint: dict[str, object] | None, coverage: dict[str, object] | None
) -> dict[str, object] | None:
    """Carry ``coverage`` on ``hint``, or alone when there is no settling hint.

    The allow hint's own validator rebuilds a fresh dict from the keys it knows,
    so the extra key never reaches the resident query.
    """

    if coverage is None:
        return hint
    if hint is None:
        return coverage
    return {**hint, "coverage": coverage}


__all__ = [
    "EXTENSION_COVERAGE_HINT_SCHEMA",
    "MAX_COVERED_SEGMENTS",
    "MAX_SEGMENT_IDS",
    "MAX_SEGMENT_TOTAL",
    "validated_extension_coverage_hint",
    "with_extension_coverage",
]
