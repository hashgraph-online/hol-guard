"""Focused regressions for shell-free Claude hook argument vectors."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import claude_hook_entry
from codex_plugin_scanner.guard import native_harness_client as harness_client
from codex_plugin_scanner.guard.claude_hook_entry import (
    CLAUDE_GUARD_DAEMON_HOOK_MARKER,
    CLAUDE_GUARD_SESSION_START_HOOK_MARKER,
)
from codex_plugin_scanner.guard.diagnostics_bridge import shell_command as _shell_command
from codex_plugin_scanner.guard.harness_context import HarnessContext
from tests import harness_ops_support as harness_support
from tests.native_runtime_stamp import stamp_native_runtime


def _handler_argv(handler: dict[str, object]) -> tuple[str, ...]:
    assert handler["type"] == "command"
    command = handler["command"]
    args = handler["args"]
    assert isinstance(command, str)
    assert isinstance(args, list)
    return (command, *(str(arg) for arg in args))


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

    install_output = harness_support.install("claude-code", context)

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

    real_ask = harness_client.ask

    def recording_ask(op: str, context: HarnessContext, **kwargs: Any) -> dict[str, Any]:
        from codex_plugin_scanner.guard.native_context import _BOUND_GUARD_HOME

        captured["native_guard_home"] = _BOUND_GUARD_HOME.get()
        return real_ask(op, context, **kwargs)

    monkeypatch.setattr(claude_hook_entry, "_daemon_module", lambda: FakeDaemonModule())
    monkeypatch.setattr(claude_hook_entry, "refresh_claude_hooks", fake_refresh)
    monkeypatch.setattr(harness_client, "ask", recording_ask)

    result = claude_hook_entry._run_session_start_from_argv((guard_home, home_dir, workspace_dir))

    assert result == 0
    assert captured["native_guard_home"] == Path(guard_home)
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
def test_session_start_rejects_malformed_argv(
    argv: tuple[str, ...], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.chdir(work)
    with pytest.raises(SystemExit, match="claude_session_start_argv_invalid"):
        claude_hook_entry._run_session_start_from_argv(argv)
    # A refused vector never names the Guard home, so nothing lands beside the hook.
    assert list(work.iterdir()) == []


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


def test_install_uses_exec_argv_for_every_managed_hook_with_hostile_paths(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace with 'single' \"double\" $dollar `backtick` & semi; (paren) 雪 "
    workspace_dir.mkdir(parents=True)
    context = HarnessContext(
        home_dir=tmp_path / "home with spaces & quotes'",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard home; $value ",
    )

    harness_support.install("claude-code", context)

    payload = json.loads((context.home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))
    session_handlers = [entry["hooks"][0] for entry in payload["hooks"]["SessionStart"]]
    runtime_handlers = _runtime_hook_handlers(payload)
    expected_session_argv = claude_hook_entry.claude_argv("session_start", context)
    expected_runtime_argv = claude_hook_entry.claude_argv("daemon", context)
    bridge_config = json.loads(expected_runtime_argv[-1])
    assert all(_handler_argv(handler) == expected_session_argv for handler in session_handlers)
    assert all(_handler_argv(handler) == expected_runtime_argv for handler in runtime_handlers)
    assert all("shell" not in handler for handler in [*session_handlers, *runtime_handlers])
    assert tuple(bridge_config["fallback_command"]) == claude_hook_entry.claude_argv("hook", context)
    assert f"--workspace={context.workspace_dir}" in bridge_config["fallback_command"]
    assert bridge_config["state_path"] == str(context.guard_home / "daemon-state.json")


def test_global_install_uses_exec_argv_without_workspace(tmp_path: Path) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home global $value",
        workspace_dir=None,
        guard_home=tmp_path / "guard global 'quote",
    )

    harness_support.install("claude-code", context)

    payload = json.loads((context.home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))
    session_handler = payload["hooks"]["SessionStart"][0]["hooks"][0]
    expected = claude_hook_entry.claude_argv("session_start", context)
    assert _handler_argv(session_handler) == expected
    assert expected[-2:] == (str(context.guard_home), str(context.home_dir))
    assert "--workspace" not in claude_hook_entry.claude_argv("hook", context)


def test_fallback_argv_preserves_leading_dash_paths_as_option_values() -> None:
    context = HarnessContext(
        home_dir=Path("-home trailing "),
        workspace_dir=Path("-workspace trailing "),
        guard_home=Path("-guard-home trailing "),
    )

    argv = claude_hook_entry.claude_argv("hook", context)

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
    harness_support.install("claude-code", context)
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
    # The resident writes phase timing and discovery counts when it answers the prompt. Those lines
    # are not the injected command. Anything else on stderr still fails.
    diagnostic_prefixes = ("native_resident_phase ", "native_resident_note ")
    unexpected = [line for line in result.stderr.splitlines() if not line.startswith(diagnostic_prefixes)]
    assert unexpected == []
    assert not marker_path.exists()


def test_daemon_hook_uses_the_native_bridge_when_the_runtime_offers_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"runtime")
    stamp_native_runtime(monkeypatch, runtime, ("claude-hook-bridge-v1",))
    monkeypatch.setattr(claude_hook_entry, "load_guard_daemon_url", lambda _guard_home: "http://127.0.0.1:1")
    context = HarnessContext(home_dir=tmp_path / "h", workspace_dir=None, guard_home=tmp_path / "g")

    argv = claude_hook_entry.claude_argv("daemon", context)

    assert argv[:3] == (str(runtime), "claude-hook-bridge", CLAUDE_GUARD_DAEMON_HOOK_MARKER)
    config = json.loads(argv[3])
    assert config["state_path"] == str(context.guard_home / "daemon-state.json")
    assert config["fallback_command"] == list(claude_hook_entry.claude_argv("hook", context))
    assert config["recovery_command"]
    assert all(isinstance(part, str) for part in config["recovery_command"])


def test_daemon_hook_without_the_native_feature_asks_for_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"runtime")
    stamp_native_runtime(monkeypatch, runtime, ("resident-protocol-v2",))
    monkeypatch.setattr(claude_hook_entry, "load_guard_daemon_url", lambda _guard_home: "http://127.0.0.1:1")
    context = HarnessContext(home_dir=tmp_path / "h", workspace_dir=None, guard_home=tmp_path / "g")

    with pytest.raises(RuntimeError, match="hol-guard repair"):
        claude_hook_entry.claude_argv("daemon", context)


def test_an_install_from_cursor_writes_no_cursor_attribution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Claude Code and Cursor share these hooks; only the bridge, at run time,
    # can tell which one runs a hook. An install started from a Cursor
    # terminal once wrote runtime-harness=cursor for both.
    monkeypatch.setenv("CURSOR_TRACE_ID", "trace")
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(tmp_path / "cursor-project"))
    monkeypatch.setattr(claude_hook_entry, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:4781")
    facts = json.loads(claude_hook_entry.claude_facts(tmp_path / "guard"))
    assert facts == {"daemon_url": "http://127.0.0.1:4781"}
