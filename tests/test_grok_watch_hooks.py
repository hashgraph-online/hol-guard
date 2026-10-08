"""Watch/observe Grok hooks must allow instead of deny."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.grok_hooks import (
    emit_grok_hook_response,
    grok_hook_response_from_guard,
)


def test_watch_mode_never_denies_review_or_block() -> None:
    for action in ("review", "require-reapproval", "sandbox-required", "block"):
        payload = grok_hook_response_from_guard(
            policy_action=action,
            reason="Would have stopped this in Protected.",
            recording_only=True,
        )
        assert payload == {"decision": "allow"}, action


def test_emit_allows_block_when_guard_home_is_watch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'protection_posture = "watch"\nmode = "enforce"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["hol-guard", "--guard-home", str(guard_home)])
    stream = io.StringIO()
    emit_grok_hook_response(
        policy_action="block",
        reason="Would have stopped this in Protected.",
        event_name="PreToolUse",
        output_stream=stream,
    )
    assert json.loads(stream.getvalue()) == {"decision": "allow"}
