from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_command_line
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_bridge_runtime import bridge_config_from_argv, decode_bridge_config_argument
from codex_plugin_scanner.guard.codex_hook_command_line import (
    encode_hook_config_argument,
    hook_command_launchable,
    render_hook_command,
    split_hook_command_line,
)
from codex_plugin_scanner.guard.codex_hook_file_integrity import split_hook_command
from codex_plugin_scanner.guard.codex_hook_manifest import MANAGED_CODEX_HOOK_EVENTS
from codex_plugin_scanner.guard.codex_hook_registration import (
    exact_legacy_hook_bindings,
    live_guard_codex_hooks_intercept,
    live_owned_codex_event_matches,
    require_codex_hook_owner,
)
from codex_plugin_scanner.guard.frozen_runtime_commands import (
    FROZEN_CODEX_BRIDGE_ARG,
    frozen_codex_bridge_tokens_are_live,
)

_PYTHON = r"C:\Users\tester\.venv\Scripts\python.exe"
_SPACED_PYTHON = r"C:\Program Files\HOL Guard's\.venv\Scripts\python.exe"
_BRIDGE = r"C:\Users\tester\site-packages\codex_plugin_scanner\guard\adapters\codex_daemon_hook_bridge.py"
_POSIX_PYTHON = "/opt/hol guard/.venv/bin/python3"
_POSIX_BRIDGE = "/opt/hol guard/site-packages/codex_plugin_scanner/guard/adapters/codex_daemon_hook_bridge.py"
_CONFIG = {
    "state_path": "C:\\Users\\a&b\\.hol-guard\\daemon-state.json",
    "fallback_command": [_PYTHON, "-I", "-c", 'print("100% ^done!")'],
    "query": "guard-home=C%3A%5CUsers%5Ca%26b%5C.hol-guard&home=%USERPROFILE%",
    "trailing": "C:\\Users\\",
}
_STATUS = "HOL Guard is reviewing this action"


def _config_json(*, windows: bool) -> str:
    return encode_hook_config_argument(json.dumps(_CONFIG, separators=(",", ":")), windows=windows)


def _argv(*, windows: bool) -> list[str]:
    if windows:
        return [_PYTHON, "-I", _BRIDGE, _config_json(windows=True)]
    return [_POSIX_PYTHON, "-I", _POSIX_BRIDGE, _config_json(windows=False)]


def _legacy_argv() -> list[str]:
    """Windows paths with the plain JSON that earlier installs wrote."""

    return [_PYTHON, "-I", _BRIDGE, _config_json(windows=False)]


def _legacy_command() -> str:
    return shlex.join(_legacy_argv())


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
        home_override_explicit=True,
    )


def _hooks(command: str) -> dict[str, object]:
    return {
        event: [{"matcher": "Bash", "hooks": [{"type": "command", "command": command, "statusMessage": _STATUS}]}]
        for event in MANAGED_CODEX_HOOK_EVENTS
    }


@pytest.mark.parametrize("windows", [False, True])
def test_hook_command_round_trips_argv_and_json(windows: bool) -> None:
    argv = _argv(windows=windows)
    command = render_hook_command(argv, windows=windows)

    assert split_hook_command_line(command, windows=windows) == argv
    assert split_hook_command(command, windows=windows) == argv
    assert json.loads(decode_bridge_config_argument(argv[-1])) == _CONFIG
    assert hook_command_launchable(command, windows=windows)


def test_posix_rendering_is_unchanged() -> None:
    argv = _argv(windows=False)

    assert argv[-1] == json.dumps(_CONFIG, separators=(",", ":"))
    assert render_hook_command(argv, windows=False) == shlex.join(argv)


def test_windows_rendering_uses_plain_tokens_both_shells_read() -> None:
    argv = _argv(windows=True)
    command = render_hook_command(argv, windows=True)

    assert command == " ".join(argv)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", argv[-1])
    assert not any(character in command for character in "\"'%!^&|<>$`;")


_SHORT_PYTHON = r"C:\PROGRA~1\HOLGUA~1\.venv\Scripts\python.exe"


def _short_names(monkeypatch: pytest.MonkeyPatch, names: dict[str, str]) -> None:
    longs = {short: long for long, short in names.items()}
    monkeypatch.setattr(codex_hook_command_line, "_short_path", names.get)
    monkeypatch.setattr(codex_hook_command_line, "_long_path", longs.get)


def test_windows_rendering_uses_short_names_for_spaced_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    _short_names(monkeypatch, {_SPACED_PYTHON: _SHORT_PYTHON})
    argv = [_SPACED_PYTHON, *_argv(windows=True)[1:]]
    command = render_hook_command(argv, windows=True)

    # Plain tokens read the same under PowerShell and under cmd.exe /C.
    assert command == " ".join([_SHORT_PYTHON, *argv[1:]])
    assert not any(character in command for character in "\"'%!^&|<>$`;")
    assert split_hook_command_line(command, windows=True) == argv
    assert split_hook_command(command, windows=True) == argv
    assert hook_command_launchable(command, windows=True)

    hooks = _hooks(command)
    assert live_guard_codex_hooks_intercept(hooks, windows=True)
    assert all(live_owned_codex_event_matches(hooks, windows=True).values())
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(command, ownership="unmanaged", windows=True)
    expected = [{"event": event, "group": {"matcher": "Bash"}} for event in MANAGED_CODEX_HOOK_EVENTS]
    bindings = exact_legacy_hook_bindings(
        hooks,
        expected_bindings=expected,
        current_argv=argv,
        legacy_argv=["C:\\old\\python.exe", *argv[1:]],
        legacy_status_messages={_STATUS},
        windows=True,
    )
    assert [binding["event"] for binding in bindings] == list(MANAGED_CODEX_HOOK_EVENTS)


@pytest.mark.parametrize(
    "short",
    [
        None,
        r"C:\Program Files\HOLGUA~1\.venv\Scripts\python.exe",
        r"C:\Program Files\HOL Guard's\.venv\Scripts\python.exe",
    ],
)
def test_windows_rendering_skips_short_names_that_are_not_plain_or_exact(
    monkeypatch: pytest.MonkeyPatch, short: str | None
) -> None:
    monkeypatch.setattr(codex_hook_command_line, "_short_path", lambda _path: short)
    monkeypatch.setattr(codex_hook_command_line, "_long_path", lambda _path: _SPACED_PYTHON)
    command = render_hook_command([_SPACED_PYTHON, *_argv(windows=True)[1:]], windows=True)

    assert command.startswith("& 'C:\\Program Files\\HOL Guard''s\\")


def test_windows_short_name_must_map_back_to_the_same_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex_hook_command_line, "_short_path", lambda _path: _SHORT_PYTHON)
    monkeypatch.setattr(codex_hook_command_line, "_long_path", lambda _path: r"C:\Other\python.exe")

    assert render_hook_command([_SPACED_PYTHON, "-I"], windows=True).startswith("& ")


def test_windows_rendering_quotes_paths_for_powershell_call(monkeypatch: pytest.MonkeyPatch) -> None:
    _short_names(monkeypatch, {})
    argv = [_SPACED_PYTHON, *_argv(windows=True)[1:]]
    command = render_hook_command(argv, windows=True)

    assert command.startswith("& 'C:\\Program Files\\HOL Guard''s\\")
    assert '"' not in command
    assert split_hook_command_line(command, windows=True) == argv
    assert hook_command_launchable(command, windows=True)


@pytest.mark.parametrize("argv", [[], [_PYTHON, "-I", "line\nbreak"]])
def test_windows_rendering_rejects_unrepresentable_arguments(argv: list[str]) -> None:
    with pytest.raises(ValueError):
        render_hook_command(argv, windows=True)


def test_bridge_accepts_encoded_and_plain_config_arguments(tmp_path: Path) -> None:
    plain = json.dumps(_CONFIG, separators=(",", ":"))
    encoded = encode_hook_config_argument(plain, windows=True)

    assert decode_bridge_config_argument(encoded) == plain
    assert decode_bridge_config_argument(plain) == plain
    installed_json = decode_bridge_config_argument(codex_adapter._hook_command_parts(_context(tmp_path))[-1])
    bridge_argument = encode_hook_config_argument(installed_json, windows=True)
    parsed = bridge_config_from_argv(["bridge.py", bridge_argument], timeout_grace_seconds=1)
    assert (parsed["query"], parsed["config_json"]) == (json.loads(installed_json)["query"], bridge_argument)
    for invalid in ("not base64!", encode_hook_config_argument("[1]", windows=True)):
        with pytest.raises(ValueError):
            decode_bridge_config_argument(invalid)


def test_windows_treats_legacy_posix_entries_as_guard_but_not_launchable() -> None:
    legacy = _legacy_command()

    assert split_hook_command(legacy, windows=True) == _legacy_argv()
    assert not hook_command_launchable(legacy, windows=True)
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(legacy, ownership="unmanaged", windows=True)


@pytest.mark.parametrize("windows", [False, True])
def test_health_and_ownership_recognise_rendered_guard_hooks(windows: bool) -> None:
    hooks = _hooks(render_hook_command(_argv(windows=windows), windows=windows))

    assert live_guard_codex_hooks_intercept(hooks, windows=windows)
    assert all(live_owned_codex_event_matches(hooks, windows=windows).values())
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(
            render_hook_command(_argv(windows=windows), windows=windows), ownership="unmanaged", windows=windows
        )


def test_windows_health_fails_while_legacy_posix_hooks_cannot_launch() -> None:
    hooks = _hooks(_legacy_command())

    assert not live_guard_codex_hooks_intercept(hooks, windows=True)
    assert all(live_owned_codex_event_matches(hooks, windows=True).values())


@pytest.mark.parametrize("legacy", [False, True])
def test_windows_legacy_adoption_matches_current_and_plain_json_entries(legacy: bool) -> None:
    argv = _argv(windows=True)
    command = _legacy_command() if legacy else render_hook_command(argv, windows=True)
    hooks = _hooks(command)
    expected = [{"event": event, "group": {"matcher": "Bash"}} for event in MANAGED_CODEX_HOOK_EVENTS]

    bindings = exact_legacy_hook_bindings(
        hooks,
        expected_bindings=expected,
        current_argv=argv,
        legacy_argv=["C:\\old\\python.exe", *argv[1:]],
        legacy_status_messages={_STATUS},
        windows=True,
    )

    assert [binding["event"] for binding in bindings] == list(MANAGED_CODEX_HOOK_EVENTS)
    assert not exact_legacy_hook_bindings(
        hooks,
        expected_bindings=expected,
        current_argv=argv,
        legacy_argv=argv,
        legacy_status_messages={_STATUS},
        windows=False,
    )


@pytest.mark.skipif(os.name == "nt", reason="installs on Windows hosts render the Windows form")
def test_installed_posix_hook_command_is_byte_identical(tmp_path: Path) -> None:
    context = _context(tmp_path)
    parts = codex_adapter._hook_command_parts(context)

    assert codex_adapter._hook_command(context) == shlex.join(parts)
    assert parts[-1] == json.dumps(json.loads(parts[-1]), separators=(",", ":"))


@pytest.mark.parametrize("windows", [False, True])
def test_frozen_bridge_tokens_accept_the_platform_config_form(windows: bool) -> None:
    argument = encode_hook_config_argument(json.dumps(_CONFIG), windows=windows)

    assert frozen_codex_bridge_tokens_are_live(["hol-guard.exe", FROZEN_CODEX_BRIDGE_ARG, argument])
    assert not frozen_codex_bridge_tokens_are_live(["hol-guard.exe", FROZEN_CODEX_BRIDGE_ARG, "not-json!"])
