"""Current generated native-hook JSON/exit fixtures; the child policy is modeled."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters import cline_hooks
from codex_plugin_scanner.guard.adapters.base import HarnessContext

_FIXTURE = Path(__file__).parent / "fixtures/guard-hook-responses/current-cline-native.v1.json"
_CONTRACT: dict[str, Any] = json.loads(_FIXTURE.read_text(encoding="utf-8"))
_EVENTS = tuple(_CONTRACT["events"])
_CONDITIONS = tuple(_CONTRACT["conditions"])


def _context(tmp_path: Path, condition: str) -> HarnessContext:
    home = tmp_path / "private home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    state = guard_home / "managed/cline/adapter-state.json"
    state.parent.mkdir(parents=True)
    if condition != "missing_transport":
        state.write_text(
            json.dumps({"active_transport": "plugin" if condition == "inactive_transport" else "hooks"}),
            encoding="utf-8",
        )
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def _input(event: str, condition: str) -> bytes:
    if condition == "malformed_input":
        return b"{unclosed"
    if condition == "nonobject_input":
        return b"[]"
    if condition == "overdepth_input":
        return b'{"nested":' * 50 + b"0" + b"}" * 50
    if condition == "oversize_input":
        return b" " * (256 * 1024 + 1)
    payload = {
        "hookName": event,
        "hook_event_name": event,
        "tool_call": {"name": "run_command", "input": {"command": "rm -rf /"}},
    }
    return json.dumps(payload).encode("utf-8")


def _guard(tmp_path: Path, condition: str) -> tuple[list[str], Path]:
    marker = tmp_path / "modeled-child-input.json"
    if condition == "child_unavailable":
        return [str(tmp_path / "missing-executable")], marker
    child = tmp_path / "modeled_guard.py"
    output = {
        "completed_allow": '{"decision":"allow"}',
        "child_invalid_json": "not JSON",
    }.get(condition, '{"decision":"deny","reason":"Synthetic completed refusal."}')
    child.write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(marker)!r}).write_bytes(sys.stdin.buffer.read())\n"
        f"sys.stdout.write({output!r})\n",
        encoding="utf-8",
    )
    return [sys.executable, "-I", "-s", str(child)], marker


@pytest.mark.parametrize("event", _EVENTS)
@pytest.mark.parametrize("condition", _CONDITIONS)
def test_generated_native_cline_json_and_exit_are_frozen(tmp_path: Path, event: str, condition: str) -> None:
    context = _context(tmp_path, condition)
    guard, marker = _guard(tmp_path, condition)
    worker = tmp_path / "generated-worker.py"
    worker.write_text(cline_hooks._hook_source(context, event_name=event, guard_cli=guard), encoding="utf-8")
    raw = _input(event, condition)
    result = subprocess.run(
        [sys.executable, "-I", "-s", str(worker)],
        input=raw,
        capture_output=True,
        timeout=15,
        check=False,
    )
    row = _CONTRACT["conditions"][condition]
    expected = row["blocking" if event == "PreToolUse" else "nonblocking"]
    # Full response shape matters: absent errorMessage and an empty errorMessage
    # are different current outputs. Compare stdout bytes as well as its JSON.
    assert json.loads(result.stdout) == expected
    assert result.stdout == (json.dumps(expected, separators=(",", ":")) + "\n").encode()
    assert result.stderr == b""
    assert result.returncode == _CONTRACT["exit_code"] == 0
    assert marker.exists() is row["child_invoked"]
    if marker.exists():
        assert json.loads(marker.read_bytes()) == json.loads(raw)
    proof = context.guard_home / "managed/cline/proofs" / f"native-{event.lower()}.json"
    assert proof.exists() is row["completion_proof"]
    if proof.exists():
        captured = json.loads(proof.read_text())
        assert captured["event"] == event
        assert captured["source"] == "cline"
        assert captured["outcome"] == (
            "observed" if event != "PreToolUse" else "allowed" if condition == "completed_allow" else "blocked"
        )


def test_cline_registered_events_cannot_escape_response_fixture_roster() -> None:
    # The source generator and actual installer iterate the same closed set.
    # A new event needs an explicit response/exit fixture, including observation
    # events; it must not inherit PreToolUse cancellation by assumption.
    assert _EVENTS == cline_hooks._EVENTS
    assert _CONTRACT["nonblocking_events"] == list(_EVENTS[1:])
    assert _CONTRACT["native_policy_boundary"] == "modeled_child_not_native_execution"


def test_size_constants_cannot_silently_change_frozen_input_boundaries() -> None:
    assert cline_hooks._MAX_BYTES == _CONTRACT["input_bytes_limit"] == 256 * 1024
    assert cline_hooks._MAX_DEPTH == _CONTRACT["input_depth_limit"] == 48
