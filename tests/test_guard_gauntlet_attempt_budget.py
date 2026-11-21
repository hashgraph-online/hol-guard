"""The driver's round budget and the record it leaves behind.

A qualification round is clean only when every case in the catalog complies, so
the odds of a clean round fall as the catalog grows. The budget that produced
the 3.50.0 waiver was three rounds; nine were spent by hand, and the record of
each one said only that it had failed, never that the run had simply stopped
asking. These tests pin the ceiling and pin the two counts a reader needs to
tell a product failure apart from an exhausted budget.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ci.gauntlet import __main__ as cli
from ci.gauntlet import qualify

from .test_guard_gauntlet_qualify import _args, _fake_setup, _summary


def test_the_budget_reaches_far_enough_to_outlast_model_noise() -> None:
    # Three rounds is roughly a coin flip against a catalog this size; the ceiling
    # has to leave room for a clean one without becoming an unbounded loop.
    assert qualify.ATTEMPT_LIMIT == 10


def test_the_cli_help_spells_the_same_ceiling_the_driver_enforces(capsys) -> None:
    # `__main__` spells the number rather than importing `qualify`, which keeps the
    # parser cheap to build. This is what keeps the two from drifting apart.
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["qualify", "--help"])
    assert exit_info.value.code == 0
    assert f"Bounded fresh runs (1-{qualify.ATTEMPT_LIMIT})" in capsys.readouterr().out


@pytest.mark.parametrize("attempts", [0, -1, qualify.ATTEMPT_LIMIT + 1])
def test_a_budget_outside_the_ceiling_is_refused(tmp_path: Path, attempts: int) -> None:
    with pytest.raises(ValueError, match=rf"--attempts must be from 1 to {qualify.ATTEMPT_LIMIT}"):
        qualify.main(_args(tmp_path, attempts=attempts))


def test_a_budget_at_the_ceiling_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_setup(monkeypatch, tmp_path, [_summary([{"id": "a", "outcome": "pass"}], True)])
    assert qualify.main(_args(tmp_path, attempts=qualify.ATTEMPT_LIMIT)) == 0


def _record(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "run" / "qualification.json").read_text())


def test_a_run_that_stopped_early_reports_the_rounds_it_did_not_spend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A product failure ends the driver on its first round. Without both counts the
    # record reads the same as a run that exhausted a generous budget.
    failing = {"id": "a", "outcome": "false-negative", "reason": "protected effect occurred"}
    _fake_setup(monkeypatch, tmp_path, [_summary([failing], False)])
    assert qualify.main(_args(tmp_path, attempts=5)) == 1
    record = _record(tmp_path)
    assert record["attempts_run"] == 1 and record["attempts_allowed"] == 5
    assert record["attempts_run"] == len(record["attempts"])


def test_a_run_that_used_its_whole_budget_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    failing = {"id": "a", "outcome": "inference-error", "reason": "no live turn"}
    _fake_setup(monkeypatch, tmp_path, [_summary([failing], False), _summary([failing], False)])
    assert qualify.main(_args(tmp_path, attempts=2)) == 1
    record = _record(tmp_path)
    assert record["attempts_run"] == 2 and record["attempts_allowed"] == 2


def test_prepare_only_spends_nothing_and_still_names_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_setup(monkeypatch, tmp_path, [])
    assert qualify.main(_args(tmp_path, prepare_only=True)) == 0
    record = _record(tmp_path)
    assert record["attempts_run"] == 0 and record["attempts_allowed"] == 2


def test_an_interrupted_round_still_counts_against_the_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A round that started spent the lane whether or not it lived to be summarized.
    # Counting records instead would report `attempts_run: 0` for a driven lane.
    _fake_setup(monkeypatch, tmp_path, [])
    started: list[int] = []

    def interrupted(argv: list[str], **kwargs: Any) -> int:
        kwargs["on_started"]()
        started.append(1)
        raise KeyboardInterrupt

    monkeypatch.setattr(qualify, "run_attempt", interrupted)
    assert qualify.main(_args(tmp_path, attempts=3)) == 1
    record = _record(tmp_path)
    assert started == [1]
    assert record["attempts"] == []
    assert record["attempts_run"] == 1 and record["attempts_allowed"] == 3
