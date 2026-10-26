"""Guard the recorded shadow rollout decisions the Rust twin replays.

``rust/crates/guard-command/tests/guard_command_shadow_parity.rs`` reads the
same fixture. Both halves must agree on every row, so a change to either set of
controls that this file does not also record is caught here first.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV,
    CommandShadowCohort,
    _comparison,
    _disposition_matches,
    _sample_bucket,
    load_command_shadow_control,
)
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-command-shadow.v1.json"


def _document() -> dict[str, Any]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-command-shadow-parity.v1"
    return document


def _rows(field: str) -> list[dict[str, Any]]:
    rows = _document()[field]
    assert rows, f"the fixture records no {field}"
    return rows


@pytest.mark.parametrize("row", _rows("buckets"), ids=lambda row: f"{row['cohort']}-{len(row['activity_id'])}")
def test_recorded_sample_bucket_still_holds(row: dict[str, Any]) -> None:
    cohort = CommandShadowCohort(row["cohort"])
    assert _sample_bucket(cohort, row["activity_id"]) == row["bucket"]


@pytest.mark.parametrize("row", _rows("rejected_activity_ids"))
def test_recorded_activity_id_is_still_refused(row: dict[str, Any]) -> None:
    with pytest.raises(ValueError) as caught:
        _sample_bucket(CommandShadowCohort.BASELINE, row["activity_id"])
    assert str(caught.value) == row["error"]


@pytest.mark.parametrize("row", _rows("controls"))
def test_recorded_control_still_resolves(row: dict[str, Any]) -> None:
    control = load_command_shadow_control(row["env"])
    assert control.enabled == row["enabled"]
    assert control.kill_switch == row["kill_switch"]
    assert sorted(cohort.value for cohort in control.release_cohorts) == row["release_cohorts"]
    assert sorted(cohort.value for cohort in control.disabled_cohorts) == row["disabled_cohorts"]
    assert control.sample_basis_points == row["sample_basis_points"]
    assert control.generation == row["generation"]
    assert control.schema_version == row["schema_version"]


@pytest.mark.parametrize("row", _rows("selections"))
def test_recorded_selection_still_holds(row: dict[str, Any]) -> None:
    control = load_command_shadow_control(row["env"])
    selected = control.selected_cohorts(
        proposal_cohorts=frozenset(CommandShadowCohort(value) for value in row["proposal_cohorts"]),
        activity_id=row["activity_id"],
    )
    assert [cohort.value for cohort in selected] == row["selected"]


@pytest.mark.parametrize("row", _rows("comparisons"), ids=lambda row: f"{row['current']}-to-{row['proposed']}")
def test_recorded_comparison_still_holds(row: dict[str, Any]) -> None:
    assert _comparison(row["current"], row["proposed"]).value == row["comparison"]


@pytest.mark.parametrize("row", _rows("dispositions"), ids=lambda row: f"{row['action']}-{row['disposition']}")
def test_recorded_disposition_match_still_holds(row: dict[str, Any]) -> None:
    disposition = FinalDisposition(row["disposition"])
    assert _disposition_matches(row["action"], disposition) is row["matches"]


def test_the_fixture_keeps_recording_selections_that_sample_in() -> None:
    assert any(row["selected"] for row in _rows("selections"))


def test_the_fixture_keeps_the_sampling_rates_the_two_halves_read_differently() -> None:
    """A sampling rate is read the same way on both sides, digit for digit.

    ``int()`` reads any Unicode decimal digit, so a rate written in fullwidth
    digits (U+FF10 to U+FF19) parses as the number it looks like, while
    the native parser the Rust twin runs reads ASCII digits only. Both halves
    now refuse a rate spelled that way. They already agreed about padding: the
    characters ``str.strip()`` removes and ``str::trim`` leaves — U+001C through
    U+001F — are the ones ``int()`` itself refuses, so a rate carrying them is
    nothing on either side.
    """

    rates = {
        row["env"][COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV]: row["sample_basis_points"]
        for row in _rows("controls")
        if COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV in row["env"]
    }
    for spelling in ("\uff15\uff10\uff10", "\u0665\u0660\u0660", "\u066500", "\x1f500"):
        assert rates.get(spelling) == 0, ascii(spelling)
    assert rates.get("\xa0500\xa0") == 500
    assert rates.get("1_000") == 1000
