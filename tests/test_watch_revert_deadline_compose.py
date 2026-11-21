"""Offline Watch proof must reflect all selected policy configuration sources."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import harness_posture
from codex_plugin_scanner.guard.native_policy_snapshot_harness_postures import signed_watch_ends


def test_workspace_only_watch_deadline_is_signed(monkeypatch: pytest.MonkeyPatch) -> None:
    home, workspace = object(), object()
    deadlines = {home: (None, {}), workspace: (None, {"claude-code": 123456})}
    monkeypatch.setattr(harness_posture, "watch_revert_deadlines", deadlines.__getitem__)

    combined = harness_posture.compose_watch_revert_deadlines((home, workspace))
    assert signed_watch_ends({"claude-code": "watch"}, combined) == (None, {"claude-code": 123456})


def test_earliest_of_overlapping_watch_deadlines_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    home, workspace = object(), object()
    deadlines = {
        home: (500, {"codex": 450, "cursor": 350}),
        workspace: (300, {"codex": 150, "claude-code": 250}),
    }
    monkeypatch.setattr(harness_posture, "watch_revert_deadlines", deadlines.__getitem__)

    combined = harness_posture.compose_watch_revert_deadlines((home, workspace))
    assert combined == (300, {"codex": 150, "cursor": 350, "claude-code": 250})
    assert signed_watch_ends({"codex": "watch", "cursor": "protected", "claude-code": "watch"}, combined) == (
        300,
        {"codex": 150, "claude-code": 250},
    )


def test_no_auto_revert_deadline_remains_unbounded(monkeypatch: pytest.MonkeyPatch) -> None:
    home, workspace = object(), object()
    monkeypatch.setattr(harness_posture, "watch_revert_deadlines", lambda _config: (None, {}))
    assert harness_posture.compose_watch_revert_deadlines((home, workspace)) == (None, {})
