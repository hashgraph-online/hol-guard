"""The claim promotion script defers every decision to the native runtime."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("promote_harness_claim", ROOT / "scripts/promote_harness_claim.py")
assert SPEC is not None and SPEC.loader is not None
promote = importlib.util.module_from_spec(SPEC)
sys.modules["promote_harness_claim"] = promote
SPEC.loader.exec_module(promote)

RECEIPT = {
    "schema": "hol-guard.harness-claim-evidence.v1",
    "harness": "codex",
    "event": "PreToolUse",
    "transport": "native_hook",
    "surface": "foreground",
    "state": "live_block_proven",
}
CLAIM = {
    "state": "live_block_proven",
    "guard_version": "3.4.0",
    "harness_version": "0.130.0",
    "platform": "macos-arm64",
    "evidence_reference": "gauntlet-run-1234",
    "observed_at": "2026-11-14T12:00:00Z",
    "expires_at": "2026-12-14T12:00:00Z",
}


def _receipt(tmp_path: Path) -> Path:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(RECEIPT), encoding="utf-8")
    return path


def _decide(answer: Any, seen: list[tuple[str, dict[str, Any]]]):
    def decide(operation: str, params: dict[str, Any]) -> Any:
        seen.append((operation, params))
        return answer

    return decide


def test_a_refused_receipt_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before = promote.CONTRACT.read_text(encoding="utf-8")
    seen: list[tuple[str, dict[str, Any]]] = []
    answer = {"promotable": False, "refusals": ['a "unit_test" receipt is synthetic and cannot promote a claim']}
    code = promote.main([str(_receipt(tmp_path)), "--write", "--now", "2026-11-14T18:00:00Z"], _decide(answer, seen))
    assert code == 1
    assert "synthetic and cannot promote" in capsys.readouterr().err
    assert promote.CONTRACT.read_text(encoding="utf-8") == before
    operation, params = seen[0]
    assert operation == "harness_claim_promotion"
    assert params["receipt"] == RECEIPT
    assert params["contract"] == before
    assert params["now"] == "2026-11-14T18:00:00Z"


def test_a_promotable_receipt_is_shown_but_not_written_without_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = promote.CONTRACT.read_text(encoding="utf-8")
    answer = {"promotable": True, "refusals": [], "claim": CLAIM}
    assert promote.main([str(_receipt(tmp_path))], _decide(answer, [])) == 0
    assert json.loads(capsys.readouterr().out) == CLAIM
    assert promote.CONTRACT.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("answer", [None, {}, {"promotable": "yes"}, ["promotable"]])
def test_a_missing_decision_is_not_a_promotion(tmp_path: Path, answer: Any) -> None:
    assert promote.main([str(_receipt(tmp_path)), "--write"], _decide(answer, [])) == 2


def test_the_claim_lands_on_the_one_row_the_receipt_names() -> None:
    contract = json.loads(promote.CONTRACT.read_text(encoding="utf-8"))
    promote.apply_claim(contract, RECEIPT, CLAIM)
    changed = [
        (entry["harness"], event["event"], event["transport"])
        for entry in contract["contracts"]
        for event in entry["capability_events"]
        if event["claim"] == CLAIM
    ]
    assert changed == [("codex", "PreToolUse", "native_hook")]
    with pytest.raises(ValueError, match="no row"):
        promote.apply_claim(contract, {**RECEIPT, "surface": "background"}, CLAIM)
