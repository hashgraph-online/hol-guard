"""Cursor hooks must not boot the frozen control plane on every editor event."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.cursor_hook_config import (
    FROZEN_CURSOR_HOOK_COMMAND,
    HOOK_SCRIPT_NAME,
    _live_cursor_hook_script_path,
    _managed_hook_command,
    live_cursor_hooks_use_frozen_control_plane,
    live_guard_cursor_hooks_intercept,
    run_frozen_cursor_hook,
)


def _disable_isolated_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.isolated_cursor_hook_python",
        lambda: None,
    )


def _blocking_cursor_hooks(command: str) -> dict[str, list[dict[str, str]]]:
    entry = [{"command": command}]
    return {
        "beforeShellExecution": entry,
        "beforeMCPExecution": entry,
        "beforeReadFile": entry,
        "beforeWriteFile": entry,
    }


def test_isolated_python_rejects_group_writable(tmp_path: Path) -> None:
    import os

    from codex_plugin_scanner.guard.adapters.cursor_hook_config import _isolated_python_is_usable

    if os.name == "nt":
        pytest.skip("POSIX interpreter write bits are not enforced on Windows")

    path = tmp_path / "python3"
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o775)
    assert _isolated_python_is_usable(path) is False


def test_isolated_python_probe_requires_python_310(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters import cursor_hook_config

    path = tmp_path / "python3"
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    captured: list[str] = []

    def fake_run(argv: list[str], **_kwargs: object) -> object:
        captured.append(str(argv))
        return type("Completed", (), {"returncode": 1})()

    monkeypatch.setattr(cursor_hook_config.subprocess, "run", fake_run)
    assert cursor_hook_config._isolated_python_is_usable(path) is False
    assert captured
    assert "sys.version_info >= (3, 10)" in captured[0]


def test_frozen_cursor_hook_command_prefers_isolated_python(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.frozen", True, raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.executable",
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.isolated_cursor_hook_python",
        lambda: "/usr/bin/python3",
    )
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    command = _managed_hook_command(
        python_executable=None,
        script_path=script,
        event_name="beforeReadFile",
    )
    tokens = shlex.split(command)
    assert tokens[:3] == ["/usr/bin/python3", "-I", str(script.resolve())]
    assert FROZEN_CURSOR_HOOK_COMMAND not in command
    assert tokens[-2:] == ["--cursor-hook-event", "beforeReadFile"]


def test_frozen_cursor_hook_command_uses_supported_launcher(monkeypatch, tmp_path: Path) -> None:
    _disable_isolated_python(monkeypatch)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.frozen", True, raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.executable",
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
    )
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    command = _managed_hook_command(
        python_executable=None,
        script_path=script,
        event_name="beforeReadFile",
    )
    tokens = shlex.split(command)
    assert tokens[0] == "/Applications/HOL Guard.app/Contents/MacOS/hol-guard"
    assert tokens[1] == FROZEN_CURSOR_HOOK_COMMAND
    assert tokens[2].endswith(HOOK_SCRIPT_NAME)
    assert tokens[-2:] == ["--cursor-hook-event", "beforeReadFile"]


def test_frozen_cursor_hook_command_prefers_current_hol_guard_shim(monkeypatch, tmp_path: Path) -> None:
    _disable_isolated_python(monkeypatch)
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.55" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("", encoding="utf-8")
    shim = core_dir / "current-hol-guard"
    shim.write_text("", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.frozen", True, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.executable", str(versioned))
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    command = _managed_hook_command(
        python_executable=None,
        script_path=script,
        event_name="beforeReadFile",
    )
    tokens = shlex.split(command)
    assert tokens[0] == str(shim)
    assert tokens[1] == FROZEN_CURSOR_HOOK_COMMAND


def test_frozen_cursor_hook_command_prefers_macos_bundle_without_shim(monkeypatch, tmp_path: Path) -> None:
    _disable_isolated_python(monkeypatch)
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.55" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("", encoding="utf-8")
    bundle = tmp_path / "HOL Guard.app" / "Contents" / "MacOS" / "hol-guard"
    bundle.parent.mkdir(parents=True)
    bundle.write_text("", encoding="utf-8")
    bundle.chmod(0o755)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.frozen", True, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.executable", str(versioned))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.stable_guard_cli.sys.platform",
        "darwin",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.stable_guard_cli.MACOS_BUNDLED_HOL_GUARD",
        bundle,
    )
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    command = _managed_hook_command(
        python_executable=None,
        script_path=script,
        event_name="beforeReadFile",
    )
    tokens = shlex.split(command)
    assert tokens[0] == str(bundle)


def test_frozen_cursor_hook_command_keeps_versioned_executable_without_shim(monkeypatch, tmp_path: Path) -> None:
    _disable_isolated_python(monkeypatch)
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.55" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("", encoding="utf-8")
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.frozen", True, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.executable", str(versioned))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.stable_guard_cli.sys.platform",
        "linux",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.stable_guard_cli.MACOS_BUNDLED_HOL_GUARD",
        tmp_path / "missing-bundle",
    )
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    command = _managed_hook_command(
        python_executable=None,
        script_path=script,
        event_name="beforeReadFile",
    )
    tokens = shlex.split(command)
    assert tokens[0] == str(versioned)


def test_unfrozen_cursor_hook_command_uses_current_interpreter(monkeypatch, tmp_path: Path) -> None:
    _disable_isolated_python(monkeypatch)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.frozen", False, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.executable", "/usr/bin/python3")
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    command = _managed_hook_command(
        python_executable=None,
        script_path=script,
        event_name="beforeReadFile",
    )
    assert FROZEN_CURSOR_HOOK_COMMAND not in command
    tokens = shlex.split(command)
    assert tokens[:2] == ["/usr/bin/python3", "-I"]


def test_managed_python_executable_runs_isolated(tmp_path: Path) -> None:
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    command = _managed_hook_command(
        python_executable=Path("/opt/guard/bin/python"),
        script_path=script,
        event_name="beforeWriteFile",
    )
    tokens = shlex.split(command)
    assert tokens[:3] == ["/opt/guard/bin/python", "-I", str(script.resolve())]
    assert tokens[-2:] == ["--cursor-hook-event", "beforeWriteFile"]


def test_run_frozen_cursor_hook_executes_managed_script(tmp_path: Path) -> None:
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True)
    marker = tmp_path / "ran"
    script.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ok', encoding='utf-8')\n",
        encoding="utf-8",
    )
    assert run_frozen_cursor_hook([str(script)]) == 0
    assert run_frozen_cursor_hook([str(script), "--cursor-hook-event", "beforeReadFile"]) == 0
    assert marker.read_text(encoding="utf-8") == "ok"


def test_run_frozen_cursor_hook_rejects_unmanaged_script(tmp_path: Path) -> None:
    script = tmp_path / "not-hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir()
    script.write_text("raise SystemExit(0)\n", encoding="utf-8")
    assert run_frozen_cursor_hook([str(script)]) == 3


def test_run_frozen_cursor_hook_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "payload.py"
    target.write_text("raise SystemExit(0)\n", encoding="utf-8")
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True)
    try:
        script.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink creation unavailable: {error}")
    assert run_frozen_cursor_hook([str(script)]) == 3


def test_run_frozen_cursor_hook_rejects_empty_argv() -> None:
    assert run_frozen_cursor_hook([]) == 2


def test_live_cursor_hook_script_path_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "payload.py"
    target.write_text("raise SystemExit(0)\n", encoding="utf-8")
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True)
    try:
        script.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink creation unavailable: {error}")
    frozen_command = shlex.join(["hol-guard", FROZEN_CURSOR_HOOK_COMMAND, str(script)])
    python_command = shlex.join(["python3", str(script)])
    assert _live_cursor_hook_script_path(frozen_command) is None
    assert _live_cursor_hook_script_path(python_command) is None
    assert live_guard_cursor_hooks_intercept(_blocking_cursor_hooks(frozen_command)) is False
    assert live_guard_cursor_hooks_intercept(_blocking_cursor_hooks(python_command)) is False


def test_live_cursor_hooks_use_frozen_control_plane(tmp_path: Path) -> None:
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True)
    script.write_text("raise SystemExit(0)\n", encoding="utf-8")
    frozen_command = shlex.join(["hol-guard", FROZEN_CURSOR_HOOK_COMMAND, str(script)])
    python_command = shlex.join(["/usr/bin/python3", "-I", str(script)])
    assert live_cursor_hooks_use_frozen_control_plane(_blocking_cursor_hooks(frozen_command)) is True
    assert live_cursor_hooks_use_frozen_control_plane(_blocking_cursor_hooks(python_command)) is False


def test_live_cursor_hook_script_path_accepts_regular_managed_script(tmp_path: Path) -> None:
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True)
    script.write_text("raise SystemExit(0)\n", encoding="utf-8")
    frozen_command = shlex.join(["hol-guard", FROZEN_CURSOR_HOOK_COMMAND, str(script)])
    python_command = shlex.join(["python3", str(script)])
    assert _live_cursor_hook_script_path(frozen_command) == script
    assert _live_cursor_hook_script_path(python_command) == script
    assert live_guard_cursor_hooks_intercept(_blocking_cursor_hooks(frozen_command)) is True
    assert live_guard_cursor_hooks_intercept(_blocking_cursor_hooks(python_command)) is True
