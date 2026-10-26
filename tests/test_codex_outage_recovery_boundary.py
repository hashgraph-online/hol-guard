"""A total runtime outage must not trust names or lexical workspace paths."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_bridge_runtime import decode_bridge_config_argument
from codex_plugin_scanner.guard.codex_hook_command_line import encode_hook_config_argument


@pytest.mark.parametrize("case", ["repair_path", "inspection_path", "explicit_inspection", "symlink_read"])
@pytest.mark.parametrize("event_name", ["PreToolUse", "PermissionRequest"])
def test_total_outage_rejects_unverified_recovery_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: str,
    event_name: str,
) -> None:
    # Exercise the Windows wire encoding on every platform. Authentication
    # must retain the registered argument, not its decoded JSON spelling.
    monkeypatch.setattr(
        codex_adapter,
        "encode_hook_config_argument",
        lambda value: encode_hook_config_argument(value, windows=True),
    )
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
        home_override_explicit=True,
    )
    codex_adapter.CodexHarnessAdapter().install(context)
    config_argument = codex_adapter._hook_command_parts(context)[-1]
    managed_config = json.loads(decode_bridge_config_argument(config_argument))
    config = {
        key: managed_config[key]
        for key in ("state_path", "fallback_command", "start_command", "query", "hook_timeouts", "manifest_path")
    }
    config["config_json"] = config_argument

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "ordinary.txt").write_text("Synthetic fixture only.\n", encoding="utf-8")
    if case == "symlink_read":
        if os.name == "nt":
            command_shell = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "cmd.exe"
            subprocess.run(
                [str(command_shell), "/c", "mklink", "/J", str(workspace / "link"), str(outside)],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            (workspace / "link").symlink_to(outside, target_is_directory=True)
    attack_bin = workspace / "bin"
    attack_bin.mkdir()
    executable_paths: dict[str, Path] = {}
    for name in ("hol-guard", "cat"):
        executable = attack_bin / (f"{name}.cmd" if os.name == "nt" else name)
        executable.write_text("@exit /b 73\n" if os.name == "nt" else "#!/bin/sh\nexit 73\n", encoding="utf-8")
        executable.chmod(0o700)
        executable_paths[name] = executable

    commands = {
        "repair_path": "hol-guard daemon status --json",
        "inspection_path": "cat README.md",
        "explicit_inspection": f'"{executable_paths["cat"]}" README.md',
    }
    if case == "symlink_read":
        tool_name = "Read"
        tool_input = {"file_path": "link/ordinary.txt"}
        assert (workspace / tool_input["file_path"]).resolve().is_relative_to(outside.resolve())
    else:
        tool_name = "Bash"
        tool_input = {"command": commands[case]}
        monkeypatch.setenv("PATH", str(attack_bin))
        if case == "explicit_inspection":
            assert executable_paths["cat"].is_file()
        else:
            assert Path(shutil.which(tool_input["command"].split()[0]) or "").is_relative_to(attack_bin)

    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": event_name,
                    "tool_name": tool_name,
                    "tool_input": tool_input,
                    "cwd": str(workspace),
                }
            )
        ),
    )

    def unexpected_child(*_args, **_kwargs):
        pytest.fail("The outage must not execute an unauthenticated child")

    # A total outage is a Guard home with no runtime beside it. A development
    # checkout may still have a built runtime somewhere the resolver finds, so
    # the outage is imposed here rather than assumed from the install. The
    # bridge must answer the hook itself rather than reach for a name on PATH
    # or a path the workspace can spell.
    def no_runtime(_guard_home: Path) -> None:
        return None

    monkeypatch.setattr(bridge, "_native_bridge_executable", no_runtime)
    monkeypatch.setattr(bridge.subprocess, "run", unexpected_child)

    assert bridge.main(**config) == 0
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    hook_output = output["hookSpecificOutput"]
    if event_name == "PermissionRequest":
        assert hook_output["decision"]["behavior"] == "deny"
    else:
        assert hook_output["permissionDecision"] == "deny"
    assert str(attack_bin) not in captured.out + captured.err
    assert str(outside) not in captured.out + captured.err
