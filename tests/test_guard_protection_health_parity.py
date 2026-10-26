"""Guard the recorded protection-health reports the Rust twin replays.

``rust/crates/guard-command/tests/guard_protection_health_parity.rs`` reads the
same fixture. Both sides must agree on every case, so a change to either
implementation that this file does not also record is caught here first.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.protection_health import (
    PROTECTION_CHECK_IDS,
    ProtectionCheckStatus,
    ProtectionSignal,
    evaluate_protection_health,
)

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-protection-health.v1.json"


def _document() -> dict[str, Any]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-protection-health-parity.v1"
    return document


def _cases() -> list[dict[str, Any]]:
    return _document()["cases"]


def _signals(raw: dict[str, list[str]]) -> dict[str, ProtectionSignal]:
    return {
        key: ProtectionSignal(ProtectionCheckStatus(status), reason_code) for key, (status, reason_code) in raw.items()
    }


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_recorded_report_still_holds(case: dict[str, Any]) -> None:
    signals = _signals(case["signals"])
    harness_signals = _signals(case["harness_signals"])
    if "expected_error" in case:
        with pytest.raises(ValueError) as refusal:
            evaluate_protection_health(signals, harness_signals=harness_signals)
        assert str(refusal.value) == case["expected_error"]
        return
    payload = evaluate_protection_health(signals, harness_signals=harness_signals)
    assert json.dumps(payload, separators=(",", ":")) == case["expected_json"]


@pytest.mark.parametrize(
    "entry", _document()["rejected_reason_codes"], ids=lambda entry: entry["reason_code"] or "empty"
)
def test_recorded_reason_code_is_still_refused(entry: dict[str, Any]) -> None:
    with pytest.raises(ValueError) as refusal:
        ProtectionSignal(ProtectionCheckStatus.UNKNOWN, entry["reason_code"])
    assert str(refusal.value) == entry["expected_error"]


def test_the_fixture_keeps_recording_both_outcomes() -> None:
    cases = _cases()
    assert sum("expected_json" in case for case in cases) >= 6
    assert sum("expected_error" in case for case in cases) >= 3


def _proven() -> ProtectionSignal:
    return ProtectionSignal(ProtectionCheckStatus.PASS, "verified")


def _every_check_proven() -> dict[str, ProtectionSignal]:
    return {check_id: _proven() for check_id in PROTECTION_CHECK_IDS}


def test_only_the_first_hundred_harnesses_are_reported_and_only_those_are_checked() -> None:
    """The slice precedes the identity check, so the hundred-and-first is never read.

    ``protection_health_tests.rs`` pins the same boundary on the Rust side.
    """

    harnesses = {f"h{index:03}": _proven() for index in range(100)}
    harnesses["zz-not-a-stable-id!"] = _proven()
    payload = evaluate_protection_health(_every_check_proven(), harness_signals=harnesses)
    assert len(payload["apps"]) == 100
    assert payload["apps"][0]["harness"] == "h000"
    assert payload["apps"][99]["harness"] == "h099"

    with pytest.raises(ValueError, match="harness protection identity must be a stable identifier"):
        evaluate_protection_health(_every_check_proven(), harness_signals={"zz-not-a-stable-id!": _proven()})


def test_a_harness_name_is_measured_in_characters() -> None:
    longest = "h" + "0" * 63
    assert len(longest) == 64
    payload = evaluate_protection_health(_every_check_proven(), harness_signals={longest: _proven()})
    assert len(payload["apps"]) == 1

    with pytest.raises(ValueError, match="harness protection identity must be a stable identifier"):
        evaluate_protection_health(_every_check_proven(), harness_signals={longest + "0": _proven()})
