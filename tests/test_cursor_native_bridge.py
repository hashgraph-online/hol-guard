"""Cursor hooks run the generated client behind the native runtime."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_command_line
from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_command_line import split_cursor_hook_command
from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_native import (
    NATIVE_CURSOR_HOOK_COMMAND,
    NATIVE_CURSOR_HOOK_FEATURE,
)
from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_script_template import HOOK_SCRIPT_TEMPLATE
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hook_config import (
    _is_managed_hook_command,
    _is_structured_managed_cursor_hook_command,
    _live_cursor_hook_script_path,
    _managed_hook_command,
)
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source
from codex_plugin_scanner.guard.adapters.native_hook_bridge import native_hook_bridge_executable

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="asserts POSIX paths and hook command syntax")
_PYTHON = Path("/usr/bin/python3")
_NATIVE_SCRIPT = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/cursor_hook_bridge_script.rs"
_CONSTANTS = (
    "GUARD_HOME",
    "GUARD_CLI",
    "GUARD_RECOVERY_COMMAND",
    "GUARD_HOOK_ARGV",
    "GUARD_INHERIT_ENV_KEYS",
    "GUARD_HOOK_TIMEOUT_SECONDS",
)


def _offer_native(monkeypatch: pytest.MonkeyPatch, runtime: Path) -> None:
    from codex_plugin_scanner.guard import native_runtime
    from codex_plugin_scanner.guard.native_runtime import (
        NativeRuntimeCapabilities,
        NativeRuntimeIdentity,
        NativeRuntimeStatus,
    )

    status = NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ok",
        identity=NativeRuntimeIdentity(path=runtime, size=1, mtime_ns=1, sha256="0" * 64),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0",
            rule_digest="0" * 64,
            build_sha="0" * 40,
            target="test",
            features=(NATIVE_CURSOR_HOOK_FEATURE,),
        ),
    )
    monkeypatch.delenv("HOL_GUARD_CURSOR_HOOK_BRIDGE", raising=False)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda *, deadline_monotonic=None: status)


def _script(tmp_path: Path) -> Path:
    script = tmp_path / "guard" / "managed" / "cursor" / "hol-guard-cursor-hook.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")
    return script


@_POSIX_ONLY
def test_cursor_hook_runs_the_client_behind_the_native_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime)
    script = _script(tmp_path)

    command = _managed_hook_command(python_executable=_PYTHON, script_path=script, event_name="preToolUse")

    assert shlex.split(command) == [
        str(runtime),
        NATIVE_CURSOR_HOOK_COMMAND,
        str(_PYTHON),
        "-I",
        str(script.resolve()),
        "--cursor-hook-event",
        "preToolUse",
    ]
    assert _live_cursor_hook_script_path(command) == script.resolve()
    assert _is_structured_managed_cursor_hook_command(command) is True


@_POSIX_ONLY
def test_pinning_the_python_client_keeps_its_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime")
    monkeypatch.setenv("HOL_GUARD_CURSOR_HOOK_BRIDGE", "python")
    script = _script(tmp_path)

    command = _managed_hook_command(python_executable=_PYTHON, script_path=script, event_name="beforeReadFile")

    assert shlex.split(command)[:2] == [str(_PYTHON), "-I"]


def test_frozen_cursor_hook_keeps_its_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.isolated_cursor_hook_python", lambda: None
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config._frozen_cursor_hook_launcher", lambda: "/bin/hol-guard"
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.native_cursor_hook_bridge", lambda _home=None: runtime
    )

    command = _managed_hook_command(python_executable=None, script_path=_script(tmp_path), event_name="preToolUse")

    assert shlex.split(command)[:4] == [
        str(runtime),
        NATIVE_CURSOR_HOOK_COMMAND,
        "/bin/hol-guard",
        "__guard-cursor-hook",
    ]


def test_native_bridge_is_offered_on_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime.exe"
    _offer_native(monkeypatch, runtime)
    monkeypatch.setattr(os, "name", "nt")

    assert native_hook_bridge_executable(NATIVE_CURSOR_HOOK_FEATURE) == runtime


def test_frozen_builds_never_consult_the_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    def consulted(*, deadline_monotonic: float | None = None) -> object:
        raise AssertionError("native status consulted")

    monkeypatch.setattr(native_runtime, "native_runtime_status", consulted)
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    assert native_hook_bridge_executable(NATIVE_CURSOR_HOOK_FEATURE) is None


_WINDOWS_PYTHON = r"C:\Program Files\Python312\python.exe"


def _use_windows_syntax(monkeypatch: pytest.MonkeyPatch, shorts: dict[str, str]) -> None:
    monkeypatch.setattr(
        codex_hook_command_line,
        "hook_commands_use_windows_syntax",
        lambda windows=None: True if windows is None else windows,
    )
    longs = {short: long for long, short in shorts.items()}
    monkeypatch.setattr(codex_hook_command_line, "_short_path", shorts.get)
    monkeypatch.setattr(codex_hook_command_line, "_long_path", longs.get)


def _assert_windows_native_command(command: str, runtime: str, script: Path) -> None:
    assert split_cursor_hook_command(command) == [
        runtime,
        NATIVE_CURSOR_HOOK_COMMAND,
        _WINDOWS_PYTHON,
        "-I",
        str(script.resolve()),
        "--cursor-hook-event",
        "preToolUse",
    ]
    assert _live_cursor_hook_script_path(command) == script.resolve()
    assert _is_structured_managed_cursor_hook_command(command) is True
    assert _is_managed_hook_command(command) is True


def test_windows_native_command_uses_short_names_as_plain_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = r"C:\Program Files\HOL Guard\hol-guard-runtime.exe"
    _offer_native(monkeypatch, Path(runtime))
    _use_windows_syntax(
        monkeypatch,
        {runtime: r"C:\PROGRA~1\HOLGUA~1\HOL-GU~1.EXE", _WINDOWS_PYTHON: r"C:\PROGRA~1\PYTHON~1\python.exe"},
    )
    script = _script(tmp_path)

    command = _managed_hook_command(
        python_executable=Path(_WINDOWS_PYTHON), script_path=script, event_name="preToolUse"
    )

    assert command.startswith("C:\\PROGRA~1\\HOLGUA~1\\HOL-GU~1.EXE cursor-hook-bridge C:\\PROGRA~1\\PYTHON~1")
    assert "'" not in command and '"' not in command
    _assert_windows_native_command(command, runtime, script)


def test_windows_native_command_falls_back_to_a_powershell_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = r"C:\Users\O'Neil\HOL Guard\hol-guard-runtime.exe"
    _offer_native(monkeypatch, Path(runtime))
    _use_windows_syntax(monkeypatch, {})
    script = _script(tmp_path)

    command = _managed_hook_command(
        python_executable=Path(_WINDOWS_PYTHON), script_path=script, event_name="preToolUse"
    )

    assert command.startswith("& 'C:\\Users\\O''Neil\\HOL Guard\\hol-guard-runtime.exe' 'cursor-hook-bridge' ")
    _assert_windows_native_command(command, runtime, script)


def test_legacy_posix_quoted_windows_command_still_parses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_windows_syntax(monkeypatch, {})
    script = _script(tmp_path)
    runtime = r"C:\HOL Guard\hol-guard-runtime.exe"
    command = shlex.join([runtime, NATIVE_CURSOR_HOOK_COMMAND, _WINDOWS_PYTHON, "-I", str(script.resolve())])

    assert split_cursor_hook_command(command) == [
        runtime,
        NATIVE_CURSOR_HOOK_COMMAND,
        _WINDOWS_PYTHON,
        "-I",
        str(script.resolve()),
    ]
    assert _live_cursor_hook_script_path(command) == script.resolve()


def _native_digest() -> str:
    match = re.search(r'CURSOR_SCRIPT_SHA256: &str =\s*"([0-9a-f]{64})"', _NATIVE_SCRIPT.read_text(encoding="utf-8"))
    assert match is not None
    return match.group(1)


def test_native_bridge_was_ported_from_the_current_client() -> None:
    # The native bridge reads the client's constants and never runs it, so a
    # template change must keep those lines readable before the digest moves.
    digest = hashlib.sha256(HOOK_SCRIPT_TEMPLATE.encode("utf-8")).hexdigest()

    assert digest == _native_digest()


def test_rendered_client_reads_back_as_the_template(tmp_path: Path) -> None:
    home = tmp_path / "home dir é"
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    source = cursor_hook_script_source(context, guard_cli=["/bin/hol-guard"], recovery_command=["/bin/hol-guard"])

    lines = []
    for line in source.split("\n"):
        name = next((name for name in _CONSTANTS if line.startswith(f"{name} = ")), None)
        lines.append(line if name is None else f"{name} = __{name}__")

    assert "\n".join(lines) == HOOK_SCRIPT_TEMPLATE


def _run_client(tmp_path: Path) -> tuple[str, int]:
    context = HarnessContext(home_dir=tmp_path, guard_home=tmp_path / "guard", workspace_dir=None)
    source = cursor_hook_script_source(context, guard_cli=[sys.executable], recovery_command=[sys.executable])
    namespace: dict[str, object] = {"__name__": "cursor_native_fixture"}
    exec(compile(source, "generated-cursor-hook", "exec"), namespace)
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = namespace["main"]()
    return stdout.getvalue(), exit_code


@pytest.mark.parametrize("event", ["afterShellExecution", "after_mcp_execution", "AFTER-SHELL-EXECUTION"])
def test_a_client_reached_directly_lets_an_observer_continue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event: str
) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard-cursor-hook.py", "--cursor-hook-event", event])

    assert _run_client(tmp_path) == ("{}\n", 0)


@pytest.mark.parametrize("argv", [["--cursor-hook-event", "beforeShellExecution"], ["--cursor-hook-event"], []])
def test_a_client_reached_directly_denies_a_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    # The native bridge answers every hook in front of this client; a gate
    # that reaches it directly had no native decision and is never allowed.
    monkeypatch.setattr(sys, "argv", ["hol-guard-cursor-hook.py", *argv])

    stdout, exit_code = _run_client(tmp_path)

    assert exit_code == 2
    assert json.loads(stdout) == {
        "permission": "deny",
        "user_message": "HOL Guard could not complete the native hook decision safely.",
    }
