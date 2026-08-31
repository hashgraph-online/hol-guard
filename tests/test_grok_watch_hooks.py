"""Watch/observe Grok hooks must allow instead of deny."""

from __future__ import annotations

import argparse
import io
import json
import sys
from contextlib import redirect_stderr
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.grok_hooks import (
    emit_grok_hook_response,
    grok_hook_response_from_guard,
)
from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.store import GuardStore


def test_watch_mode_never_denies_review_or_block() -> None:
    for action in ("review", "require-reapproval", "sandbox-required", "block"):
        payload = grok_hook_response_from_guard(
            policy_action=action,
            reason="Would have stopped this in Protected.",
            recording_only=True,
        )
        assert payload == {"decision": "allow"}, action


def test_watch_posture_allows_pretool_even_when_mode_is_enforce(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    store = GuardStore(guard_home)
    config = GuardConfig(
        guard_home=guard_home,
        workspace=tmp_path,
        mode="observe",
        protection_posture="watch",
    )
    args = argparse.Namespace(
        harness="grok",
        json=False,
        policy_action="block",
        artifact_id=None,
        artifact_name=None,
    )
    payload = {
        "hookEventName": "pre_tool_use",
        "toolName": "run_terminal_command",
        "toolInput": {"command": "rm -rf /"},
    }
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    with redirect_stderr(stderr_capture):
        rc = _run_hook_generic_payload(
            args,
            action_envelope=None,
            config=config,
            output_stream=stdout_capture,
            payload=payload,
            home_dir=tmp_path,
            runtime_workspace=tmp_path,
            store=store,
        )
    assert rc == 0
    assert json.loads(stdout_capture.getvalue()) == {"decision": "allow"}


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
