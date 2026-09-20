"""Freeze current auxiliary event responses, with daemon/process results modeled."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

from .bounded_cli_hook_test_support import config as bridge_config

_FIXTURE = Path(__file__).parent / "fixtures/guard-hook-responses/auxiliary-events.v1.json"
_CONTRACT: dict[str, Any] = json.loads(_FIXTURE.read_text(encoding="utf-8"))
_CASES = tuple(_CONTRACT["cases"])


@pytest.mark.parametrize("case", _CASES, ids=lambda case: str(case["id"]))
def test_current_auxiliary_event_response_and_exit_are_frozen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: dict[str, Any]
) -> None:
    config = bridge_config(tmp_path, harness=case["harness"])
    guard_home = Path(str(config["guard_home"]))
    if case["posture"] == "watch":
        (guard_home / "config.toml").write_text('protection_posture = "watch"\nmode = "observe"\n', encoding="utf-8")
    raw = json.dumps(
        {
            "hook_event_name": case["event"],
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        },
        separators=(",", ":"),
    )
    # This is never executed. An unsafe command keeps emergency-safe fallback
    # out of the permission/lifecycle response oracle.
    calls: list[str] = []

    def no_daemon(**kwargs: object) -> None:
        del kwargs
        calls.append("daemon")

    def modeled_child(*args: object, **kwargs: object) -> BoundedHookProcessResult:
        del args
        assert kwargs["input_text"] == raw
        calls.append("child")
        if case["condition"] == "timeout":
            return BoundedHookProcessResult(None, "", False, True)
        if case["condition"] == "malformed_child":
            return BoundedHookProcessResult(0, "not-json\n", False, False)
        assert case["condition"] == "output_limit"
        return BoundedHookProcessResult(0, "", True, False)

    monkeypatch.setattr(daemon, "try_daemon_hook", no_daemon)
    monkeypatch.setattr(bridge, "run_isolated_hook_process", modeled_child)
    if case["condition"] == "input_limit":
        # Exercise the real bounded reader and event recovery from its prefix.
        raw += " " * (1_000_001 - len(raw))
    monkeypatch.setattr(bridge.sys, "stdin", io.TextIOWrapper(io.BytesIO(raw.encode("utf-8"))))
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bridge.main_from_argv([json.dumps(config)])
    expected = case["response"]
    assert json.loads(output.getvalue()) == expected
    assert output.getvalue() == json.dumps(expected, separators=(",", ":")) + "\n"
    assert returncode == case["exit_code"] == 0
    assert calls == ([] if case["condition"] == "input_limit" else ["daemon", "child"])


def test_auxiliary_capture_matrix_is_closed_over_current_registered_events() -> None:
    expected = {
        "copilot": {"userPromptSubmitted", "permissionRequest", "permissionRequestV2"},
        "kimi": {"UserPromptSubmit", "SessionStart", "Stop"},
        "grok": {"UserPromptSubmit", "SubagentStart", "SessionStart"},
        "zcode": {"UserPromptSubmit"},
    }
    observed = {(case["harness"], case["event"], case["posture"], case["condition"]) for case in _CASES}
    assert len(observed) == len(_CASES)
    assert observed == {
        (harness, event, posture, condition)
        for harness, events in expected.items()
        for event in events
        for posture in ("protected_default", "watch")
        for condition in ("timeout", "malformed_child", "input_limit", "output_limit")
    }
    assert bridge._MAX_HOOK_INPUT_BYTES == _CONTRACT["input_bytes_limit"] == 1_000_000
    assert _CONTRACT["native_policy_boundary"] == "modeled_results_not_native_execution"
