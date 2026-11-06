"""Guard the recorded JSONC normalizations the Rust twin replays.

``rust/crates/guard-command/tests/guard_jsonc_normalization_parity.rs`` reads
the same fixture. ``normalize_jsonc`` blanks comments and trailing commas
without moving a single character, so a drift on either side changes both what
a Bun lockfile parses to and where a decode error points.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.jsonc import normalize_jsonc

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-jsonc-normalization.v1.json"


def _document() -> dict[str, Any]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-jsonc-normalization-parity.v1"
    return document


def _section(name: str) -> list[dict[str, Any]]:
    cases = _document()[name]
    assert cases, f"the fixture records no {name}"
    return cases


@pytest.mark.parametrize("case", _section("normalizations"), ids=lambda case: case["name"])
def test_recorded_normalization_still_holds(case: dict[str, Any]) -> None:
    normalized = normalize_jsonc(case["text"])
    assert normalized == case["normalized"]
    # Every replacement is one character wide, so offsets never move.
    assert len(normalized) == len(case["text"])


@pytest.mark.parametrize("case", _section("unterminated"), ids=lambda case: case["name"])
def test_recorded_unterminated_comment_still_points_at_the_same_place(case: dict[str, Any]) -> None:
    with pytest.raises(json.JSONDecodeError) as caught:
        normalize_jsonc(case["text"])
    assert str(caught.value) == case["message"]
    assert (caught.value.lineno, caught.value.colno, caught.value.pos) == (
        case["lineno"],
        case["colno"],
        case["pos"],
    )


def test_the_fixture_keeps_recording_a_comment_that_spans_lines() -> None:
    # A block comment keeps its line breaks, so a later decode error reports
    # the line the reader sees. Losing this case would let that drift.
    spanning = [
        case
        for case in _section("normalizations")
        if "\n" in case["text"] and "/*" in case["text"] and "\n" in case["normalized"]
    ]
    assert spanning, "no recorded block comment spans a line break"


def test_the_fixture_keeps_recording_an_unterminated_comment_past_line_one() -> None:
    assert any(case["lineno"] > 1 for case in _section("unterminated"))
