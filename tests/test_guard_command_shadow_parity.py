"""Guard the recorded shadow comparisons the Rust twin replays.

``rust/crates/guard-command/tests/guard_command_shadow_parity.rs`` reads the
same fixture and replays every row, including the rollout controls, sampling
buckets and cohort selections that only the native runtime resolves now. The
comparison lattice and disposition check still validate every stored
``CommandShadowObservation`` on the Python side, so those rows are held here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    _comparison,
    _disposition_matches,
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


@pytest.mark.parametrize("row", _rows("comparisons"), ids=lambda row: f"{row['current']}-to-{row['proposed']}")
def test_recorded_comparison_still_holds(row: dict[str, Any]) -> None:
    assert _comparison(row["current"], row["proposed"]).value == row["comparison"]


@pytest.mark.parametrize("row", _rows("dispositions"), ids=lambda row: f"{row['action']}-{row['disposition']}")
def test_recorded_disposition_match_still_holds(row: dict[str, Any]) -> None:
    disposition = FinalDisposition(row["disposition"])
    assert _disposition_matches(row["action"], disposition) is row["matches"]
