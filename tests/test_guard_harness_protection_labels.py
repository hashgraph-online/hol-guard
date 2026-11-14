"""The CLI's protection proof labels match the shared fixture."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.cli.render_doctor_readiness import (
    PROTECTION_STATE_LABELS,
    UNKNOWN_PROTECTION_LABEL,
    protection_proof_rows,
    protection_state_text,
)

FIXTURE = Path(__file__).parent / "fixtures" / "harness-protection-states.v1.json"


def _fixture() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_labels_match_the_shared_fixture() -> None:
    fixture = _fixture()
    states = fixture["states"]
    assert isinstance(states, list)
    assert list(PROTECTION_STATE_LABELS) == [entry["state"] for entry in states]
    for entry in states:
        assert PROTECTION_STATE_LABELS[entry["state"]][0] == entry["label"]
    assert fixture["unknown_state_label"] == UNKNOWN_PROTECTION_LABEL


def test_an_unknown_or_missing_state_is_never_proven() -> None:
    for state in (None, "", "protected", 3, "LIVE_BLOCK_PROVEN"):
        assert protection_state_text(state).plain == "Protection unknown"


def test_proof_rows_list_the_overall_state_then_each_event() -> None:
    rows = protection_proof_rows(
        {
            "protection_state": "partial",
            "event_states": [
                {"event": "PreToolUse", "state": "live_block_proven"},
                {"event": "PostToolUse", "state": "observe_only"},
                {"state": "configured"},
                "Stop",
            ],
        }
    )
    assert [(label, text.plain) for label, text in rows] == [
        ("Protection proof", "Partly proven"),
        ("  PreToolUse", "Live block proven"),
        ("  PostToolUse", "Observe only"),
    ]


def test_a_missing_payload_reports_unknown_protection() -> None:
    rows = protection_proof_rows(None)
    assert [(label, text.plain) for label, text in rows] == [("Protection proof", "Protection unknown")]
