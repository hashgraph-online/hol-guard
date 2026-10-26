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

The resident computes it (``extension_coverage_hint.rs``); this module only
checks a stored hint's shape and carries it on an allow hint.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import cast

EXTENSION_COVERAGE_HINT_SCHEMA = "guard.extension-coverage-hint.v1"
# A stored coverage hint describes a shell command, which the parser already
# bounds well below these limits; they only stop a malformed payload growing.
MAX_COVERED_SEGMENTS = 24
MAX_SEGMENT_IDS = 12
MAX_SEGMENT_TOTAL = 256
_MAX_SEGMENT_INDEX = 255
_CATALOG_ID = re.compile(r"command\.[A-Za-z0-9._-]{1,248}")
_EXECUTABLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ID_KEYS = ("extension_ids", "rule_ids", "permission_ids")


def _segment_index(value: object) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value if 0 <= value <= _MAX_SEGMENT_INDEX else None


def _catalog_id(value: object) -> str | None:
    return value if isinstance(value, str) and _CATALOG_ID.fullmatch(value) else None


def _validated_segment(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    segment = cast("Mapping[str, object]", value)
    index = _segment_index(segment.get("index"))
    if index is None:
        return None
    executable = segment.get("executable")
    named = executable if isinstance(executable, str) and _EXECUTABLE.fullmatch(executable) else None
    checked: dict[str, object] = {"index": index, "executable": named}
    for key in _ID_KEYS:
        raw = segment.get(key)
        if not isinstance(raw, list) or len(cast("list[object]", raw)) > MAX_SEGMENT_IDS:
            return None
        ids = [_catalog_id(item) for item in cast("list[object]", raw)]
        if any(item is None for item in ids):
            return None
        checked[key] = cast("list[str]", ids)
    if not checked["extension_ids"]:
        return None
    return checked


def validated_extension_coverage_hint(value: object) -> dict[str, object] | None:
    """Return a shape-checked copy of a stored coverage hint, or None.

    Accepts both carriers: a standalone coverage hint, and the ``coverage`` key
    an allow hint carries when the command also earned a settling recommendation.
    """

    if not isinstance(value, Mapping):
        return None
    fields = cast("Mapping[str, object]", value)
    if fields.get("schema") != EXTENSION_COVERAGE_HINT_SCHEMA:
        nested = fields.get("coverage")
        return validated_extension_coverage_hint(nested) if nested is not None else None
    digest = fields.get("catalog_digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        return None
    raw_segments = fields.get("segments")
    if not isinstance(raw_segments, list) or not 0 < len(cast("list[object]", raw_segments)) <= MAX_COVERED_SEGMENTS:
        return None
    segments = [_validated_segment(item) for item in cast("list[object]", raw_segments)]
    if any(segment is None for segment in segments):
        return None
    checked = cast("list[dict[str, object]]", segments)
    indexes = {cast("int", segment["index"]) for segment in checked}
    if len(indexes) != len(checked):
        return None
    result: dict[str, object] = {
        "schema": EXTENSION_COVERAGE_HINT_SCHEMA,
        "catalog_digest": digest,
        "segments": sorted(checked, key=lambda segment: cast("int", segment["index"])),
    }
    total = fields.get("segment_total")
    if total is not None:
        # A total that cannot hold every covered step was measured on another
        # command, so the hint it came with describes nothing this one did.
        if not isinstance(total, int) or isinstance(total, bool) or not max(indexes) < total <= MAX_SEGMENT_TOTAL:
            return None
        result["segment_total"] = total
    return result


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
