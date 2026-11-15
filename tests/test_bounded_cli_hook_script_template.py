"""The managed Grok client only carries constants, and fails closed when run on its own."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _render_bounded_hook_script
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_failure import failure_payload

_REASON = "HOL Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal."


def _script(tmp_path: Path, *, timeout_seconds: float = 8) -> Path:
    script = tmp_path / "grok.py"
    script.write_text(
        _render_bounded_hook_script(guard_home=tmp_path / "guard", harness="grok", timeout_seconds=timeout_seconds),
        encoding="utf-8",
    )
    return script


def _run_client(tmp_path: Path, stdin: str) -> object:
    completed = subprocess.run(
        [sys.executable, "-I", str(_script(tmp_path)), "{}"],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return json.loads(completed.stdout)


def _contract(event: str) -> dict[str, object]:
    payload, exit_code = failure_payload(harness="grok", event_name=event, reason=_REASON, recording_only=False)
    assert exit_code == 0
    return payload


@pytest.mark.parametrize(
    "event",
    [
        "PreToolUse",
        "pre_tool_use",
        "pretoolcall",
        "PermissionRequest",
        "UserPromptSubmit",
        "user_prompt_submitted",
        "Stop",
        "Notification",
        "SessionStart",
        "post_tool_use",
        "PermissionDenied",
        "AfterToolCall",
    ],
)
def test_a_client_run_without_the_runtime_answers_as_the_shared_failure_contract(tmp_path: Path, event: str) -> None:
    assert _run_client(tmp_path, json.dumps({"hook_event_name": event, "tool_name": "Write"})) == _contract(event)


def test_a_prompt_is_blocked_not_denied(tmp_path: Path) -> None:
    answer = _run_client(tmp_path, json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}))

    assert isinstance(answer, dict)
    assert answer["decision"] == "block"
    assert answer["hookSpecificOutput"] == {"hookEventName": "UserPromptSubmit"}


@pytest.mark.parametrize(
    "stdin",
    [
        json.dumps({"hook_event_name": "PostToolUse", "event": "PreToolUse"}),
        json.dumps({"hook_event_name": "SessionStart", "eventName": "pre_tool_call"}),
        json.dumps({"hook_event_name": "Séssionstart"}),
        json.dumps({"hook_event_name": None}),
        json.dumps({"hook_event_name": ""}),
        json.dumps(["SessionStart"]),
        # An explicit id keeps the payload out of PYTEST_CURRENT_TEST, which has a size limit.
        pytest.param("[" * 100_000 + "]" * 100_000, id="deep-nesting"),
        "not json",
        "",
    ],
)
def test_an_unreadable_or_conflicting_event_is_denied_as_a_tool_call(tmp_path: Path, stdin: str) -> None:
    assert _run_client(tmp_path, stdin) == _contract("PreToolUse")


def test_an_open_input_pipe_is_denied_within_the_budget(tmp_path: Path) -> None:
    process = subprocess.Popen(
        [sys.executable, "-I", str(_script(tmp_path, timeout_seconds=0.5)), "{}"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    started = time.monotonic()
    try:
        assert process.stdin is not None
        process.stdin.write(b'{"hook_event_name":"SessionStart"')
        process.stdin.flush()
        # The pipe stays open: the client must answer without waiting for EOF.
        process.wait(timeout=10)
        assert process.stdout is not None
        stdout = process.stdout.read()
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.kill()
            process.wait()

    assert time.monotonic() - started < 5
    assert json.loads(stdout) == _contract("PreToolUse")


def test_the_rendered_client_names_its_home_harness_and_timeout(tmp_path: Path) -> None:
    source = _render_bounded_hook_script(guard_home=tmp_path / "guard", harness="Grok", timeout_seconds=2.5)

    assert f"GUARD_HOME = {json.dumps(str((tmp_path / 'guard').resolve()))}" in source
    assert 'HARNESS = "grok"' in source
    assert "TIMEOUT_SECONDS = 2.5" in source
    assert "urllib" not in source
