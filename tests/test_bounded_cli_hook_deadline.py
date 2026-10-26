"""Shared bridge degradation must preserve the original budget and protection."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _render_bounded_hook_script
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

from .bounded_cli_hook_test_support import config


@pytest.mark.parametrize("harness", ["copilot", "grok", "hermes", "openclaw", "kimi", "zcode"])
def test_timeout_cannot_grant_unreviewed_protected_action(tmp_path, monkeypatch, harness):
    monkeypatch.setattr(daemon, "try_daemon_hook", lambda **kwargs: None)
    monkeypatch.setattr(
        bridge, "run_isolated_hook_process", lambda *args, **kwargs: BoundedHookProcessResult(None, "", False, True)
    )
    output = io.StringIO()
    with redirect_stdout(output):
        bridge.run_bounded_cli_hook(
            config(tmp_path, harness=harness),
            input_text=json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "rm -rf protected-project"},
                }
            ),
        )
    response = json.loads(output.getvalue())
    specific = response.get("hookSpecificOutput", {})
    assert response.get("decision") != "allow"
    assert response.get("permissionDecision") != "allow"
    assert specific.get("permissionDecision") != "allow"
    assert (
        response.get("decision") in {"deny", "block"}
        or response.get("permissionDecision") == "deny"
        or specific.get("permissionDecision") == "deny"
    )


def test_daemon_attempt_cannot_renew_cli_fallback_budget(tmp_path, monkeypatch):
    hook_config = config(tmp_path, harness="kimi")
    hook_config["timeout_seconds"] = 0.03
    spawned = []

    def exhausted_daemon(**kwargs):
        time.sleep(0.05)
        return None

    def unexpected_spawn(*args, **kwargs):
        spawned.append(kwargs)
        return BoundedHookProcessResult(None, "", False, True)

    monkeypatch.setattr(daemon, "try_daemon_hook", exhausted_daemon)
    monkeypatch.setattr(bridge, "run_isolated_hook_process", unexpected_spawn)
    with redirect_stdout(io.StringIO()):
        bridge.run_bounded_cli_hook(hook_config, input_text='{"hook_event_name":"PreToolUse"}')
    assert spawned == []


@pytest.mark.parametrize("late_boundary", ["daemon", "cli"])
def test_late_allow_cannot_commit_after_original_deadline(tmp_path, monkeypatch, late_boundary):
    hook_config = config(tmp_path, harness="grok")
    hook_config["timeout_seconds"] = 0.02

    def delayed_daemon(**kwargs):
        if late_boundary == "daemon":
            time.sleep(0.04)
            return '{"decision":"allow"}', "", 0
        return None

    def delayed_cli(*args, **kwargs):
        time.sleep(0.04)
        return BoundedHookProcessResult(0, '{"decision":"allow"}', False, False)

    monkeypatch.setattr(daemon, "try_daemon_hook", delayed_daemon)
    monkeypatch.setattr(bridge, "run_isolated_hook_process", delayed_cli)
    output = io.StringIO()
    with redirect_stdout(output):
        bridge.run_bounded_cli_hook(hook_config, input_text='{"hook_event_name":"PreToolUse"}')
    assert json.loads(output.getvalue())["decision"] == "deny"


@pytest.mark.parametrize("generated", [False, True])
@pytest.mark.parametrize("partial", ["", '{"hook_event_name":"PreToolUse"'])
def test_open_input_pipe_obeys_original_bridge_budget(tmp_path, generated, partial):
    hook_config = config(tmp_path, harness="grok")
    hook_config["timeout_seconds"] = 0.15
    if generated:
        script = tmp_path / "bounded-hook.py"
        script.write_text(
            _render_bounded_hook_script(
                guard_home=tmp_path / "guard-home",
                harness="grok",
                timeout_seconds=0.15,
            )
        )
        command = [sys.executable, "-S", str(script)]
    else:
        command = [
            sys.executable,
            "-c",
            "import sys; from codex_plugin_scanner.guard.adapters."
            "bounded_cli_hook_bridge import main_from_argv; raise SystemExit(main_from_argv(sys.argv[1:]))",
            json.dumps(hook_config),
        ]
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert process.stdin is not None
    try:
        if partial:
            process.stdin.write(partial)
            process.stdin.flush()
        process.wait(timeout=4)
        stdout, stderr = process.communicate(timeout=1)
        assert process.returncode == 0, stderr
        assert json.loads(stdout)["decision"] == "deny"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=1)


def test_input_time_cannot_renew_module_fallback_budget(tmp_path, monkeypatch):
    hook_config = config(tmp_path, harness="grok")
    hook_config["timeout_seconds"] = 0.02
    dispatches = []

    def slow_input(deadline):
        time.sleep(0.04)
        return '{"hook_event_name":"PreToolUse"}', ""

    def unexpected_dispatch(**kwargs):
        dispatches.append(kwargs)
        return '{"decision":"allow"}', "", 0

    monkeypatch.setattr(bridge, "_read_bounded_stdin", slow_input)
    monkeypatch.setattr(daemon, "try_daemon_hook", unexpected_dispatch)
    output = io.StringIO()
    with redirect_stdout(output):
        bridge.main_from_argv([json.dumps(hook_config)])
    assert dispatches == []
    assert json.loads(output.getvalue())["decision"] == "deny"


@pytest.mark.parametrize("generated", [False, True])
@pytest.mark.parametrize("raw", [b"\xff", b"x" * 1_000_001])
def test_invalid_input_never_reaches_protected_evaluator(tmp_path, monkeypatch, generated, raw):
    hook_config = config(tmp_path, harness="grok")
    monkeypatch.setattr(sys, "stdin", io.BytesIO(raw))

    def refuse_evaluation(*args, **kwargs):
        pytest.fail("Invalid input must not reach a protected evaluator")

    output = io.StringIO()
    with redirect_stdout(output):
        if generated:
            namespace = {"__name__": "input_fixture"}
            exec(
                _render_bounded_hook_script(guard_home=tmp_path / "guard-home", harness="grok", timeout_seconds=1),
                namespace,
            )
            namespace["_post_hook"] = refuse_evaluation
            namespace["main"]()
        else:
            monkeypatch.setattr(bridge, "run_bounded_cli_hook", refuse_evaluation)
            bridge.main_from_argv([json.dumps(hook_config)])
    assert json.loads(output.getvalue())["decision"] == "deny"


@pytest.mark.parametrize("generated", [False, True])
def test_expired_failure_does_not_read_posture_files(tmp_path, monkeypatch, generated):
    hook_config = config(tmp_path, harness="grok")
    hook_config["timeout_seconds"] = 0.02

    def refuse_read(*args, **kwargs):
        pytest.fail("Expired failure output must not start another posture read")

    output = io.StringIO()
    with redirect_stdout(output):
        if generated:
            namespace = {"__name__": "expired_fixture"}
            exec(
                _render_bounded_hook_script(guard_home=tmp_path / "guard-home", harness="grok", timeout_seconds=1),
                namespace,
            )
            namespace["_HOOK_DEADLINE_MONOTONIC"] = time.monotonic() - 1
            namespace["_read_private_text"] = refuse_read
            namespace["_fail"]("{}")
        else:

            def exhausted_daemon(**kwargs):
                time.sleep(0.04)
                monkeypatch.setattr(Path, "read_text", refuse_read)
                return None

            monkeypatch.setattr(daemon, "try_daemon_hook", exhausted_daemon)
            bridge.run_bounded_cli_hook(hook_config, input_text="{}")
    assert json.loads(output.getvalue())["decision"] == "deny"
