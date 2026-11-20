from __future__ import annotations

import base64
import json
import os
import re
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_harness_client as codex_adapter
from codex_plugin_scanner.guard.codex_hook_manifest import MANAGED_CODEX_HOOK_EVENTS
from codex_plugin_scanner.guard.codex_hook_registration import (
    exact_legacy_hook_bindings,
    is_live_guard_codex_hook_command,
    live_guard_codex_hooks_intercept,
    live_owned_codex_event_matches,
    require_codex_hook_owner,
)
from codex_plugin_scanner.guard.frozen_runtime_commands import FROZEN_CODEX_BRIDGE_ARG
from codex_plugin_scanner.guard.harness_context import HarnessContext

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


def encode_hook_config_argument(config_json: str, *, windows: bool) -> str:
    """The config argument as the native renderer writes it: base64url on Windows."""

    if not windows:
        return config_json
    return base64.urlsafe_b64encode(config_json.encode("utf-8")).decode("ascii").rstrip("=")


def decode_bridge_config_argument(argument: str) -> str:
    """Test-side inverse of the renderer; the runtime's own decoder is native."""

    if argument.startswith("{"):
        return argument
    return base64.urlsafe_b64decode(argument + "=" * (-len(argument) % 4)).decode("utf-8")


def _rendered(argv: list[str], *, windows: bool) -> str:
    """The native renderer's line for an argv of plain tokens."""

    return " ".join(argv) if windows else shlex.join(argv)


def _powershell_call(argv: list[str]) -> str:
    return "& " + " ".join("'" + argument.replace("'", "''") + "'" for argument in argv)


def _config_json(*, windows: bool) -> str:
    return encode_hook_config_argument(json.dumps(_CONFIG, separators=(",", ":")), windows=windows)


def _argv(*, windows: bool) -> list[str]:
    if windows:
        return [_PYTHON, "-I", _BRIDGE, _config_json(windows=True)]
    return [_POSIX_PYTHON, "-I", _POSIX_BRIDGE, _config_json(windows=False)]


def _launchable_argv(tmp_path: Path, *, windows: bool) -> list[str]:
    """The rendered argv, with programs that exist when the form is this host's own."""

    argv = _argv(windows=windows)
    if windows != (os.name == "nt"):
        return argv
    programs = [tmp_path / "venv" / "python3", tmp_path / "site" / "codex_daemon_hook_bridge.py"]
    for program in programs:
        program.parent.mkdir(parents=True, exist_ok=True)
        program.touch()
    return [str(programs[0]), "-I", str(programs[1]), argv[-1]]


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
    assert json.loads(decode_bridge_config_argument(argv[-1])) == _CONFIG


def test_the_config_argument_is_plain_json_on_posix_and_a_plain_token_on_windows() -> None:
    assert _argv(windows=False)[-1] == json.dumps(_CONFIG, separators=(",", ":"))
    command = _rendered(_argv(windows=True), windows=True)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", _argv(windows=True)[-1])
    assert not any(character in command for character in "\"'%!^&|<>$`;")


def test_windows_powershell_call_commands_parse_back() -> None:
    argv = [_SPACED_PYTHON, *_argv(windows=True)[1:]]
    command = _powershell_call(argv)

    assert command.startswith("& 'C:\\Program Files\\HOL Guard''s\\")
    assert '"' not in command
    assert live_guard_codex_hooks_intercept(_hooks(command), windows=True)


def test_bridge_accepts_encoded_and_plain_config_arguments(tmp_path: Path) -> None:
    plain = json.dumps(_CONFIG, separators=(",", ":"))
    encoded = encode_hook_config_argument(plain, windows=True)

    assert decode_bridge_config_argument(encoded) == plain
    assert decode_bridge_config_argument(plain) == plain
    installed_json = decode_bridge_config_argument(codex_adapter._hook_command_parts(_context(tmp_path))[-1])
    bridge_argument = encode_hook_config_argument(installed_json, windows=True)
    assert json.loads(decode_bridge_config_argument(bridge_argument)) == json.loads(installed_json)


def test_windows_treats_legacy_posix_entries_as_guard_but_not_launchable() -> None:
    legacy = _legacy_command()

    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(legacy, ownership="unmanaged", windows=True)


@pytest.mark.parametrize("windows", [False, True])
def test_health_and_ownership_recognise_rendered_guard_hooks(windows: bool, tmp_path: Path) -> None:
    argv = _launchable_argv(tmp_path, windows=windows)
    hooks = _hooks(_rendered(argv, windows=windows))

    assert live_guard_codex_hooks_intercept(hooks, windows=windows)
    assert all(live_owned_codex_event_matches(hooks, windows=windows).values())
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(_rendered(argv, windows=windows), ownership="unmanaged", windows=windows)


def test_windows_health_fails_while_legacy_posix_hooks_cannot_launch() -> None:
    hooks = _hooks(_legacy_command())

    assert not live_guard_codex_hooks_intercept(hooks, windows=True)
    assert all(live_owned_codex_event_matches(hooks, windows=True).values())


@pytest.mark.parametrize("legacy", [False, True])
def test_windows_legacy_adoption_matches_current_and_plain_json_entries(legacy: bool) -> None:
    argv = _argv(windows=True)
    command = _legacy_command() if legacy else _rendered(argv, windows=True)
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

    groups = json.loads(json.dumps(codex_adapter._managed_hook_groups(context)))
    assert {group["hooks"][0]["command"] for group in groups.values()} == {shlex.join(parts)}
    assert parts[-1] == json.dumps(json.loads(parts[-1]), separators=(",", ":"))


@pytest.mark.parametrize("windows", [False, True])
def test_frozen_bridge_tokens_accept_the_platform_config_form(windows: bool) -> None:
    argument = encode_hook_config_argument(json.dumps(_CONFIG), windows=windows)

    def command(config: str) -> str:
        return _rendered(["hol-guard.exe", FROZEN_CODEX_BRIDGE_ARG, config], windows=windows)

    assert is_live_guard_codex_hook_command(command(argument), windows=windows)
    assert not is_live_guard_codex_hook_command(command("not-json!"), windows=windows)
