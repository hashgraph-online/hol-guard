"""Parsed generated hooks preserve decisions and deny unavailable evaluation."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source

_EVENTS = ["beforeReadFile", "beforeShellExecution", "beforeMCPExecution", "beforeWriteFile", "preToolUse"]
_FAILURES = ["exception", "timeout", "invalid-json", "missing-decision", "nonzero-allow", "nonzero-review"]


def _unavailable(failure: str) -> subprocess.CompletedProcess[str]:
    if failure == "exception":
        raise RuntimeError("Injected evaluation failure")
    if failure == "timeout":
        raise subprocess.TimeoutExpired("unused-guard", 0.75)
    stdout = {
        "invalid-json": "not-json",
        "missing-decision": "{}",
        "nonzero-allow": '{"policy_action":"allow"}',
        "nonzero-review": '{"policy_action":"review"}',
    }[failure]
    # EX_SOFTWARE is an unexpected CLI failure, unlike supported restriction exits 1/2.
    code = 70 if failure == "nonzero-review" else 1 if failure == "nonzero-allow" else 0
    return subprocess.CompletedProcess([], code, stdout, "")


def _generated(context: HarnessContext) -> dict[str, Any]:
    source = cursor_hook_script_source(context, guard_cli=["unused-guard"], recovery_command=["unused-recovery"])
    module_globals = {"__name__": "cursor_parsed_outage_fixture"}
    exec(compile(source, "generated-cursor-hook", "exec"), module_globals)
    return module_globals


@pytest.mark.parametrize("event", _EVENTS)
@pytest.mark.parametrize("local_watch", [False, True])
@pytest.mark.parametrize("failure", _FAILURES)
@pytest.mark.parametrize("policy_import_available", [True, False])
def test_generated_parsed_cursor_unavailable_denies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    event: str,
    local_watch: bool,
    failure: str,
    policy_import_available: bool,
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    module_globals = _generated(context)
    context.guard_home.mkdir()
    config_path = context.guard_home / "config.toml"
    config_bytes = f'mode = "{"observe" if local_watch else "prompt"}"\n'.encode()
    config_path.write_bytes(config_bytes)
    if not policy_import_available:
        monkeypatch.setitem(
            sys.modules,
            "codex_plugin_scanner.guard.daemon.hook_availability_policy",
            ModuleType("codex_plugin_scanner.guard.daemon.hook_availability_policy"),
        )
    module_globals["_recording_only_from_guard_home"] = lambda *_args: local_watch
    module_globals["_daemon_hook_result"] = lambda *_args, **_kwargs: (None, "overload")

    module_globals["_run_guard_fallback"] = lambda *_args, **_kwargs: _unavailable(failure)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"hook_event_name": event, "command": "git push", "file_path": "private.txt"})),
    )
    monkeypatch.setattr(sys, "argv", ["cursor-hook"])
    assert module_globals["main"]() == 2
    response = json.loads(capsys.readouterr().out)
    assert response["permission"] == "deny"
    assert "terminal" in response["user_message"]
    assert config_path.read_bytes() == config_bytes


@pytest.mark.parametrize("event", _EVENTS)
@pytest.mark.parametrize("local_watch", [False, True])
@pytest.mark.parametrize(
    ("policy", "code"),
    [
        ("allow", 0),
        ("warn", 0),
        ("review", 1),
        ("review", 2),
        ("require-reapproval", 1),
        ("require-reapproval", 2),
        ("sandbox-required", 1),
        ("sandbox-required", 2),
        ("block", 1),
        ("block", 2),
    ],
)
@pytest.mark.parametrize("reason_code", ["policy", "native_pre_tool_unavailable"])
def test_generated_parsed_cursor_preserves_trusted_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    event: str,
    local_watch: bool,
    policy: str,
    code: int,
    reason_code: str,
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    module_globals = _generated(context)
    module_globals["_recording_only_from_guard_home"] = lambda *_args: local_watch
    response = {"policy_action": policy, "reason_code": reason_code, "reason": "fixture decision"}
    module_globals["_daemon_hook_result"] = lambda *_args, **_kwargs: (None, "overload")
    module_globals["_run_guard_fallback"] = lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [],
        code,
        json.dumps(response),
        "",
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": event, "command": "git push"})))
    monkeypatch.setattr(sys, "argv", ["cursor-hook"])
    permission = {
        "allow": "allow",
        "warn": "allow",
        "review": "ask",
        "require-reapproval": "ask",
        "sandbox-required": "deny",
        "block": "deny",
    }[policy]
    if event == "beforeReadFile" and permission == "ask":
        permission = "deny"
    assert module_globals["main"]() == (2 if permission == "deny" else 0)
    assert json.loads(capsys.readouterr().out)["permission"] == permission


@pytest.mark.parametrize("event", ["afterShellExecution", "afterMCPExecution"])
@pytest.mark.parametrize("failure", _FAILURES)
def test_generated_parsed_cursor_observations_continue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], event: str, failure: str
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    module_globals = _generated(context)
    module_globals["_daemon_hook_result"] = lambda *_args, **_kwargs: (None, "overload")
    module_globals["_run_guard_fallback"] = lambda *_args, **_kwargs: _unavailable(failure)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": event})))
    monkeypatch.setattr(sys, "argv", ["cursor-hook"])
    assert module_globals["main"]() == 0
    assert json.loads(capsys.readouterr().out) == {}


@pytest.mark.parametrize("event", _EVENTS)
def test_generated_parsed_cursor_without_guard_imports_denies(tmp_path: Path, event: str) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    context.home_dir.mkdir()
    context.guard_home.mkdir()
    unavailable = [sys.executable, "-S", "-c", "raise SystemExit(1)"]
    source = cursor_hook_script_source(context, guard_cli=unavailable, recovery_command=unavailable)
    script = tmp_path / "cursor-hook.py"
    script.write_text(source, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-S", str(script)],
        input=json.dumps({"hook_event_name": event, "command": "git push", "file_path": "private.txt"}),
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(context.home_dir)},
        timeout=10,
        check=False,
    )
    assert result.returncode == 2, result.stderr
    response = json.loads(result.stdout)
    assert response["permission"] == "deny"
    assert "terminal" in response["user_message"]
