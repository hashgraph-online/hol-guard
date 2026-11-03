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
from collections.abc import Mapping
from functools import lru_cache
from typing import cast

EXTENSION_COVERAGE_HINT_SCHEMA = "guard.extension-coverage-hint.v1"
# A stored coverage hint describes a shell command, which the parser already
# bounds well below these limits; they only stop a malformed payload growing.
MAX_COVERED_SEGMENTS = 24
MAX_SEGMENT_IDS = 12
MAX_SEGMENT_TOTAL = 256
_KIND = "extension_hint_shape"


@lru_cache(maxsize=256)
def _shape_answer(canonical: str) -> str:
    from ..native_runner_authority import native_runner_authority

    return json.dumps(native_runner_authority(_KIND, {"hint": json.loads(canonical)}))


def shaped_hint(value: object, key: str) -> dict[str, object] | None:
    """The runtime's checked copy of one kind of stored hint, or None.

    ``key`` is ``allow``, ``coverage`` or ``connector``. A hint only ever offers
    a choice, so a value the runtime cannot check is dropped like a bad one.
    Repeated values (a queue listing reads each row's hint) cost one call.
    """

    if not isinstance(value, Mapping):
        return None
    from ..native_runner_authority import NativeRunnerAuthorityError

    try:
        canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
        answer = json.loads(_shape_answer(canonical))
    except (NativeRunnerAuthorityError, TypeError, ValueError):
        return None
    shaped = answer.get(key) if isinstance(answer, dict) else None
    return cast("dict[str, object]", shaped) if isinstance(shaped, dict) else None


def validated_extension_coverage_hint(value: object) -> dict[str, object] | None:
    """Return a shape-checked copy of a stored coverage hint, or None.

    Accepts both carriers: a standalone coverage hint, and the ``coverage`` key
    an allow hint carries when the command also earned a settling recommendation.
    """

    return shaped_hint(value, "coverage")


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
