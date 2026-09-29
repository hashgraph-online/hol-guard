"""A total evaluator outage must not trust names or lexical workspace paths."""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge_flow as flow
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_runtime_trust import TrustedCodexHookLaunch


@pytest.mark.parametrize("case", ["repair_path", "inspection_path", "explicit_inspection", "symlink_read"])
@pytest.mark.parametrize("launcher_trust", ["valid", "invalid"])
def test_total_outage_rejects_unverified_recovery_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: str,
    launcher_trust: str,
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
        home_override_explicit=True,
    )
    codex_adapter.CodexHarnessAdapter().install(context)
    config_json = codex_adapter._hook_command_parts(context)[3]
    managed_config = json.loads(config_json)
    config = {
        key: managed_config[key]
        for key in ("state_path", "fallback_command", "start_command", "query", "hook_timeouts", "manifest_path")
    }
    config["config_json"] = config_json

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "ordinary.txt").write_text("Synthetic fixture only.\n", encoding="utf-8")
    (workspace / "link").symlink_to(outside, target_is_directory=True)
    attack_bin = workspace / "bin"
    attack_bin.mkdir()
    for name in ("hol-guard", "cat"):
        executable = attack_bin / name
        executable.write_text("#!/bin/sh\nexit 73\n", encoding="utf-8")
        executable.chmod(0o700)

    commands = {
        "repair_path": "hol-guard daemon status --json",
        "inspection_path": "cat README.md",
        "explicit_inspection": f"{attack_bin / 'cat'} README.md",
    }
    if case == "symlink_read":
        tool_name = "Read"
        tool_input = {"file_path": "link/ordinary.txt"}
        assert (workspace / tool_input["file_path"]).resolve().is_relative_to(outside.resolve())
    else:
        tool_name = "Bash"
        tool_input = {"command": commands[case]}
        monkeypatch.setenv("PATH", str(attack_bin))
        assert Path(shutil.which(tool_input["command"].split()[0]) or "").is_relative_to(attack_bin)

    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": tool_name,
                    "tool_input": tool_input,
                    "cwd": str(workspace),
                }
            )
        ),
    )
    attempts: list[str] = []
    validate = flow.trusted_hook_launch

    def unavailable(**_kwargs):
        raise ConnectionRefusedError("private-daemon-endpoint")

    def real_launcher(**kwargs):
        attempts.append("validate")
        if launcher_trust == "invalid":
            raise ValueError("private-launcher-detail")
        return validate(**kwargs)

    def failed_start(_self, *_args, **_kwargs):
        attempts.append("start")
        return False

    def failed_fallback(_self, *_args, **_kwargs):
        attempts.append("fallback")
        return None

    def unexpected_child(*_args, **_kwargs):
        pytest.fail("The outage must not execute an unauthenticated child")

    monkeypatch.setattr(flow, "_daemon_response", unavailable)
    monkeypatch.setattr(flow, "trusted_hook_launch", real_launcher)
    monkeypatch.setattr(flow, "_run_daemon_start", unexpected_child)
    monkeypatch.setattr(flow, "_run_local_fallback", unexpected_child)
    monkeypatch.setattr(TrustedCodexHookLaunch, "run_start", failed_start)
    monkeypatch.setattr(TrustedCodexHookLaunch, "run_fallback", failed_fallback)

    assert bridge.main(**config) == 0
    assert attempts == (["validate", "start", "fallback"] if launcher_trust == "valid" else ["validate"])
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["hookSpecificOutput"].get("permissionDecision") == "deny"
    assert "private-daemon-endpoint" not in captured.out + captured.err
    assert "private-launcher-detail" not in captured.out + captured.err
    assert str(attack_bin) not in captured.out + captured.err
