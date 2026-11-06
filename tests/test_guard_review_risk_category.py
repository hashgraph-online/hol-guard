"""The review claim names the same risk level as the Cloud Review event."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.review_contracts import _risk_category


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"risk_headline": "Destructive delete of the build cache", "policy_action": "allow"}, "high"),
        ({"risk_headline": "Reads a project file", "risk_summary": "Needs review", "policy_action": "allow"}, "medium"),
        ({"policy_action": "require-reapproval"}, "medium"),
        ({"policy_action": "block"}, "high"),
        ({"risk_headline": "low effort, high impact"}, "high"),
        ({"risk_headline": "Blocked writes to the keychain"}, "high"),
        ({"risk_headline": "Reviewing a follow-up"}, "medium"),
        ({"risk_headline": "Allows highlighting"}, "low"),
        ({"risk_headline": "follow the highlight", "policy_action": "sandbox-required"}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_risk_category_matches_whole_words_and_their_inflections(row: dict[str, object], expected: str) -> None:
    assert _risk_category(row) == expected
