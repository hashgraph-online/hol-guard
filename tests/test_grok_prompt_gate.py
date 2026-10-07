from __future__ import annotations

import io
import json
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as transport
from codex_plugin_scanner.guard.adapters.grok_hooks import grok_hook_response_from_guard
from codex_plugin_scanner.guard.daemon.hook_worker_responses import harness_json_from_native_prompt

from .bounded_cli_hook_test_support import config
from .test_bounded_cli_hook_script_template import _load_script

_PROMPT_EVENTS = ["UserPromptSubmit", "user_prompt_submit", "UserPromptSubmitted", "user_prompt_submitted"]


@pytest.mark.parametrize("event", _PROMPT_EVENTS)
@pytest.mark.parametrize("action", ["review", "require-reapproval", "sandbox-required", "block"])
def test_restrictive_prompt_actions_use_grok_block(action: str, event: str) -> None:
    rendered = harness_json_from_native_prompt(
        "grok", {"decision": "deny", "minimum_action": action, "reason": "Rejected prompt."}
    )
    assert rendered["decision"] == "block"
    for response in (
        rendered,
        grok_hook_response_from_guard(policy_action=action, reason="Rejected prompt.", event_name=event),
    ):
        stdout, _, code = transport._daemon_response_to_native(response, harness="grok", event_name=event)
        assert json.loads(stdout)["decision"] == "block"
        assert code == 2


@pytest.mark.parametrize("event", _PROMPT_EVENTS)
@pytest.mark.parametrize("action", ["allow", "warn"])
def test_reviewed_benign_prompt_has_empty_success(action: str, event: str) -> None:
    rendered = harness_json_from_native_prompt("grok", {"decision": "allow", "minimum_action": action})
    assert rendered == {}
    stdout, stderr, code = transport._daemon_response_to_native(rendered, harness="grok", event_name=event)
    assert (json.loads(stdout), stderr, code) == ({}, "", 0)


def test_acknowledged_watch_prompt_does_not_block() -> None:
    assert (
        grok_hook_response_from_guard(
            policy_action="block", reason="Would block.", event_name="UserPromptSubmit", recording_only=True
        )
        == {}
    )


@pytest.mark.parametrize("event", _PROMPT_EVENTS)
@pytest.mark.parametrize("blocked", [False, True])
def test_generated_client_preserves_reviewed_prompt_alias_decision(tmp_path: Path, event: str, blocked: bool) -> None:
    module = _load_script(tmp_path, harness="grok")
    canonical = module._event_name(json.dumps({"hookEventName": event}))
    assert canonical == "UserPromptSubmit"
    response = {"decision": "block", "reason": "Rejected prompt."} if blocked else {}
    stdout, stderr, code = module._to_native(response, canonical)
    assert json.loads(stdout) == response
    assert stderr == ""
    assert code == (2 if blocked else 0)


@pytest.mark.parametrize("event", _PROMPT_EVENTS)
def test_unavailable_prompt_daemon_never_launches_cold_evaluator(tmp_path: Path, monkeypatch, event: str) -> None:
    monkeypatch.setattr(transport, "try_daemon_hook", lambda **_: None)

    def forbidden_fallback(*_, **__):
        raise AssertionError("Prompt gate must return a block before the host kills a cold evaluator.")

    monkeypatch.setattr(bridge, "run_isolated_hook_process", forbidden_fallback)
    output = io.StringIO()
    with redirect_stdout(output):
        code = bridge.run_bounded_cli_hook(
            config(tmp_path, harness="grok"), input_text=json.dumps({"hookEventName": event})
        )
    assert code == 0
    assert json.loads(output.getvalue())["decision"] == "block"


@pytest.mark.parametrize("event", _PROMPT_EVENTS)
def test_standalone_prompt_gate_blocks_offline_before_host_deadline(tmp_path: Path, event: str) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    script = tmp_path / "hook.py"
    script.write_text(bridge._render_bounded_hook_script(guard_home=guard_home, harness="grok", timeout_seconds=85))
    completed = subprocess.run(
        [sys.executable, "-I", str(script)],
        input=json.dumps({"hook_event_name": event, "prompt": "Explain a README."}),
        text=True,
        capture_output=True,
        timeout=3,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["decision"] == "block"
