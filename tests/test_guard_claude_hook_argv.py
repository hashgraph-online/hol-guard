"""Focused regressions for shell-free Claude hook argument vectors."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import claude_code
from codex_plugin_scanner.guard.adapters.base import HarnessContext, _shell_command
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.claude_hook_config import (
    CLAUDE_GUARD_SESSION_START_HOOK_MARKER,
    command_handler_argv,
    handler_identity,
)


def _handler_argv(handler: dict[str, object]) -> tuple[str, ...]:
    argv = command_handler_argv(handler)
    assert argv is not None
    return argv


def _runtime_hook_handlers(payload: dict[str, object]) -> list[dict[str, object]]:
    hooks = payload["hooks"]
    assert isinstance(hooks, dict)
    handlers: list[dict[str, object]] = []
    for key in ("PreToolUse", "PermissionRequest", "PostToolUse", "Notification", "Stop"):
        entries = hooks.get(key, [])
        assert isinstance(entries, list)
        for entry in entries:
            assert isinstance(entry, dict)
            entry_hooks = entry["hooks"]
            assert isinstance(entry_hooks, list)
            for hook in entry_hooks:
                assert isinstance(hook, dict)
                handlers.append(hook)
    return handlers


def _windows_crt_split(command_line: str) -> tuple[str, ...]:
    """Parse list2cmdline output using the documented MS C runtime rules."""

    arguments: list[str] = []
    index = 0
    while index < len(command_line):
        while index < len(command_line) and command_line[index] in " \t":
            index += 1
        if index == len(command_line):
            break
        argument: list[str] = []
        quoted = False
        while index < len(command_line) and (quoted or command_line[index] not in " \t"):
            if command_line[index] != "\\":
                if command_line[index] == '"':
                    quoted = not quoted
                else:
                    argument.append(command_line[index])
                index += 1
                continue
            backslash_start = index
            while index < len(command_line) and command_line[index] == "\\":
                index += 1
            backslash_count = index - backslash_start
            if index >= len(command_line) or command_line[index] != '"':
                argument.extend("\\" * backslash_count)
                continue
            argument.extend("\\" * (backslash_count // 2))
            if backslash_count % 2:
                argument.append('"')
            else:
                quoted = not quoted
            index += 1
        arguments.append("".join(argument))
    return tuple(arguments)


def test_install_bakes_source_root_into_structured_session_start_argv(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )

    install_output = ClaudeCodeHarnessAdapter().install(context)

    payload = json.loads((context.home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))
    hook_argv = _handler_argv(payload["hooks"]["SessionStart"][0]["hooks"][0])
    hook_command = "\0".join(hook_argv)
    expected_source_root = str(Path(__file__).resolve().parents[1] / "src")
    assert install_output["active"] is True
    assert "run_session_start_from_argv" in hook_command
    assert CLAUDE_GUARD_SESSION_START_HOOK_MARKER in hook_command
    assert expected_source_root in hook_command
    assert '"guard", "hook"' not in hook_command
    assert hook_argv[-3:] == (str(context.guard_home), str(context.home_dir), str(context.workspace_dir))


def test_session_start_argv_preserves_exact_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = str(tmp_path / "guard home 'quote $dollar `backtick` & semicolon; 雪 ")
    home_dir = str(tmp_path / 'home "double" (paren) \\backslash')
    workspace_dir = str(tmp_path / "-workspace trailing ")
    captured: dict[str, object] = {}

    class FakeDaemonModule:
        @staticmethod
        def ensure_guard_daemon(path: Path) -> None:
            captured["daemon_guard_home"] = path

    def fake_refresh(*, home_dir: Path, workspace_dir: Path | None, guard_home: Path) -> None:
        captured["refresh"] = (home_dir, workspace_dir, guard_home)

    monkeypatch.setattr(claude_code, "_daemon_module", lambda: FakeDaemonModule())
    monkeypatch.setattr(ClaudeCodeHarnessAdapter, "refresh_installed_hook_urls", fake_refresh)

    result = claude_code._run_session_start_from_argv((guard_home, home_dir, workspace_dir))

    assert result == 0
    assert captured["daemon_guard_home"] == Path(guard_home)
    assert captured["refresh"] == (Path(home_dir), Path(workspace_dir), Path(guard_home))
    assert json.loads(capsys.readouterr().out) == {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": "HOL Guard protection is active for this workspace.",
        }
    }


@pytest.mark.parametrize(
    "argv",
    [
        ("guard-home-only",),
        ("", "home"),
        ("guard-home", ""),
        ("guard-home", "home", ""),
        ("guard\x00home", "home"),
    ],
)
def test_session_start_rejects_malformed_argv(argv: tuple[str, ...]) -> None:
    with pytest.raises(SystemExit, match="claude_session_start_argv_invalid"):
        claude_code._run_session_start_from_argv(argv)


def test_shell_command_round_trips_hostile_posix_arguments_without_running_marker(tmp_path: Path) -> None:
    marker_path = tmp_path / "p43-shell-marker"
    arguments = (
        "path with spaces",
        "single'quote",
        'double"quote',
        "$HOME",
        f"`touch {marker_path}`",
        f"$(touch {marker_path})",
        "parentheses() & ampersand; semicolon",
        "backslash\\tail",
        "Unicode-雪-é",
        "-leading-dash",
        "trailing-space ",
        "",
    )
    argv = (sys.executable, "-c", "import json,sys;print(json.dumps(sys.argv[1:]))", *arguments)

    rendered = _shell_command(argv, windows=False)
    result = subprocess.run(
        ["/bin/sh", "-c", rendered],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert shlex.split(rendered) == list(argv)
    assert result.returncode == 0
    assert json.loads(result.stdout) == list(arguments)
    assert result.stderr == ""
    assert not marker_path.exists()


def test_shell_command_round_trips_hostile_windows_arguments_with_crt_reference() -> None:
    argv = (
        r"C:\Program Files\HOL Guard\python.exe",
        "-c",
        'print("quoted")',
        r"C:\workspace with spaces\project",
        "single' and double\" quotes",
        r"backslash\\tail",
        "trailing-backslash\\",
        "Unicode-雪-é",
        "&|<>^;$`()",
        "-leading-dash",
        "trailing-space ",
        "",
    )

    assert _windows_crt_split(_shell_command(argv, windows=True)) == argv


def test_legacy_session_start_command_uses_posix_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_dir = tmp_path / "workspace with 'quote $dollar `backtick` & semicolon; 雪 "
    workspace_dir.mkdir(parents=True)
    context = HarnessContext(
        home_dir=tmp_path / "home with 'quote",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard home $value",
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.base.os.name", "posix")

    rendered = ClaudeCodeHarnessAdapter._session_start_command(context)

    assert shlex.split(rendered) == list(ClaudeCodeHarnessAdapter._session_start_command_parts(context))


def test_install_uses_exec_argv_for_every_managed_hook_with_hostile_paths(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace with 'single' \"double\" $dollar `backtick` & semi; (paren) 雪 "
    workspace_dir.mkdir(parents=True)
    context = HarnessContext(
        home_dir=tmp_path / "home with spaces & quotes'",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard home; $value ",
    )
    adapter = ClaudeCodeHarnessAdapter()

    adapter.install(context)

    payload = json.loads((context.home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))
    session_handlers = [entry["hooks"][0] for entry in payload["hooks"]["SessionStart"]]
    runtime_handlers = _runtime_hook_handlers(payload)
    expected_session_argv = adapter._session_start_command_parts(context)
    expected_runtime_argv = adapter._daemon_hook_command_parts(context)
    bridge_config = json.loads(expected_runtime_argv[-1])
    assert all(_handler_argv(handler) == expected_session_argv for handler in session_handlers)
    assert all(_handler_argv(handler) == expected_runtime_argv for handler in runtime_handlers)
    assert all("shell" not in handler for handler in [*session_handlers, *runtime_handlers])
    assert tuple(bridge_config["fallback_command"]) == adapter._hook_command_parts(context)
    assert f"--workspace={context.workspace_dir}" in bridge_config["fallback_command"]
    assert bridge_config["state_path"] == str(context.guard_home / "daemon-state.json")
    assert handler_identity(session_handlers[0]) == ("command", "exec", *expected_session_argv)
    assert handler_identity(runtime_handlers[0]) == ("command", "exec", *expected_runtime_argv)


def test_global_install_uses_exec_argv_without_workspace(tmp_path: Path) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home global $value",
        workspace_dir=None,
        guard_home=tmp_path / "guard global 'quote",
    )
    adapter = ClaudeCodeHarnessAdapter()

    adapter.install(context)

    payload = json.loads((context.home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))
    session_handler = payload["hooks"]["SessionStart"][0]["hooks"][0]
    expected = adapter._session_start_command_parts(context)
    assert _handler_argv(session_handler) == expected
    assert expected[-2:] == (str(context.guard_home), str(context.home_dir))
    assert "--workspace" not in adapter._hook_command_parts(context)


def test_fallback_argv_preserves_leading_dash_paths_as_option_values() -> None:
    context = HarnessContext(
        home_dir=Path("-home trailing "),
        workspace_dir=Path("-workspace trailing "),
        guard_home=Path("-guard-home trailing "),
    )

    argv = ClaudeCodeHarnessAdapter._hook_command_parts(context)

    assert "--guard-home=-guard-home trailing " in argv
    assert "--home=-home trailing " in argv
    assert "--workspace=-workspace trailing " in argv


def test_exec_hook_does_not_run_marker_embedded_in_workspace_path(tmp_path: Path) -> None:
    marker_path = tmp_path / "p43-claude-marker"
    workspace_dir = tmp_path / "workspace; touch p43-claude-marker; # 'quote $value `backtick` 雪"
    workspace_dir.mkdir(parents=True)
    context = HarnessContext(
        home_dir=tmp_path / "home with spaces",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard home & state",
    )
    ClaudeCodeHarnessAdapter().install(context)
    payload = json.loads((context.home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))
    handler = payload["hooks"]["PreToolUse"][0]["hooks"][0]

    result = subprocess.run(
        list(_handler_argv(handler)),
        cwd=tmp_path,
        input=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hello"}),
        capture_output=True,
        text=True,
        check=False,
        timeout=40,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert not marker_path.exists()
