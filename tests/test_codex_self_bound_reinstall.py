"""A reinstall replaces the handlers this same installation wrote before."""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter, _unmanaged_migration_payload
from codex_plugin_scanner.guard.codex_config import dump_toml, read_toml_payload
from codex_plugin_scanner.guard.codex_hook_compatibility import NATIVE_CODEX_HOOK_COMMAND
from codex_plugin_scanner.guard.codex_hook_self_binding import (
    codex_hook_binds_guard_home,
    codex_hook_guard_home,
    install_package_root,
    self_bound_hook_bindings,
)


def _install(home: Path, guard_home: Path) -> None:
    CodexHarnessAdapter().install(HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home))


def _config_path(home: Path) -> Path:
    return home / ".codex" / "config.toml"


def _handlers(home: Path) -> list[dict[str, object]]:
    payload = read_toml_payload(_config_path(home))
    hooks = payload.get("hooks")
    found: list[dict[str, object]] = []
    for groups in hooks.values() if isinstance(hooks, dict) else []:
        for group in groups if isinstance(groups, list) else []:
            if isinstance(group, dict):
                found.extend(handler for handler in group.get("hooks", []) if isinstance(handler, dict))
    return found


def _rewrite_commands(home: Path, rewrite) -> None:
    payload = read_toml_payload(_config_path(home))
    for groups in payload["hooks"].values():
        for group in groups if isinstance(groups, list) else []:
            for handler in group.get("hooks", []) if isinstance(group, dict) else []:
                command = handler.get("command")
                if isinstance(command, str):
                    handler["command"] = rewrite(command)
    _config_path(home).write_text(dump_toml(payload), encoding="utf-8")


def test_reinstall_replaces_a_stale_generation_of_this_install(tmp_path):
    home = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    _install(home, guard_home)
    before = [handler["command"] for handler in _handlers(home)]
    assert before

    # An upgrade, a moved virtualenv or a reinstalled package changes the
    # launcher, so the signed manifest stops matching what is registered.
    _rewrite_commands(home, lambda command: command.replace(sys.executable, "/usr/bin/python3", 1))

    _install(home, guard_home)

    # Claiming is not adopting: the slot holds the command this install
    # generates, byte for byte, not the bytes that were found in it.
    assert [handler["command"] for handler in _handlers(home)] == before


def test_reinstall_refuses_a_guard_handler_bound_to_another_guard_home(tmp_path):
    home = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    _install(home, guard_home)
    other = str(tmp_path / "other-guard-home")
    _rewrite_commands(home, lambda command: command.replace(str(guard_home), other))
    before = read_toml_payload(_config_path(home))

    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        _install(home, guard_home)

    assert read_toml_payload(_config_path(home)) == before


def test_reinstall_keeps_a_foreign_handler_sharing_a_group_with_a_stale_one(tmp_path):
    home = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    _install(home, guard_home)
    foreign = {"type": "command", "command": "/usr/bin/true audit"}
    payload = read_toml_payload(_config_path(home))
    group = payload["hooks"]["PreToolUse"][0]
    group["hooks"] = [
        {**handler, "command": handler["command"].replace(sys.executable, "/usr/bin/python3", 1)}
        for handler in group["hooks"]
    ]
    group["hooks"].append(foreign)
    _config_path(home).write_text(dump_toml(payload), encoding="utf-8")

    _install(home, guard_home)

    commands = [handler["command"] for handler in _handlers(home)]
    assert foreign["command"] in commands
    assert not [command for command in commands if command.startswith("/usr/bin/python3")]


def _cli_command(*arguments: str) -> str:
    """The isolated CLI fallback spelling the installer writes."""

    bootstrap = "import sys;sys.path.insert(0, '/opt/guard');from codex_plugin_scanner.cli import main"
    return shlex.join(("/usr/bin/python3", "-I", "-c", bootstrap, "guard", "hook", "--harness", "codex", *arguments))


def _bridge_command(payload: dict[str, object], *extra: str) -> str:
    """The bridge launcher spelling the installer writes."""

    return shlex.join(
        ("/opt/guard/python", "-I", "/opt/guard/codex_daemon_hook_bridge.py", json.dumps(payload), *extra)
    )


_BRIDGE_PAYLOAD: dict[str, object] = {
    "state_path": "/srv/guard/daemon-state.json",
    "query": "guard-home=/srv/guard&home=/home/dev",
    "fallback_command": ["python", "-m", "codex_plugin_scanner.cli", "--guard-home", "/srv/guard"],
}

_PACKAGED_BRIDGE = install_package_root() / "guard" / "adapters" / "codex_daemon_hook_bridge.py"


def _bridge_launch(script: Path, guard_home: Path, *, program: str = "/usr/bin/python3") -> str:
    payload = {"state_path": str(guard_home / "daemon-state.json"), "query": f"guard-home={guard_home}"}
    return shlex.join((program, "-I", str(script), json.dumps(payload)))


def _native_launch(program: str, script: Path, guard_home: Path) -> str:
    return f"{shlex.join((program, NATIVE_CODEX_HOOK_COMMAND))} {_bridge_launch(script, guard_home)}"


def _bridge_script(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "codex_daemon_hook_bridge.py"
    script.write_text("", encoding="utf-8")
    return script


def test_native_bridge_payload_identifies_the_installation():
    assert codex_hook_guard_home(_bridge_command(_BRIDGE_PAYLOAD)) == Path("/srv/guard")


def test_the_native_bridge_wrapper_identifies_the_installation():
    wrapped = shlex.join(("/opt/guard/hol-guard-runtime", NATIVE_CODEX_HOOK_COMMAND))
    assert codex_hook_guard_home(f"{wrapped} {_bridge_command(_BRIDGE_PAYLOAD)}") == Path("/srv/guard")


@pytest.mark.parametrize(
    "command",
    (
        "/usr/local/bin/hol-guard-codex-hook.sh",
        # A bridge payload whose fields disagree names no one installation.
        _bridge_command({**_BRIDGE_PAYLOAD, "state_path": "/srv/other/daemon-state.json"}),
    ),
)
def test_a_command_naming_no_single_guard_home_identifies_nothing(command):
    assert codex_hook_guard_home(command) is None


@pytest.mark.parametrize(
    "command",
    (
        # An argument the installer never writes.
        _bridge_command(_BRIDGE_PAYLOAD, "--tampered"),
        # A wrapper of someone else's around a launcher of ours.
        "/usr/bin/env " + _bridge_command(_BRIDGE_PAYLOAD),
    ),
)
def test_a_tampered_command_is_not_this_installations_own(command):
    assert codex_hook_guard_home(command) is None


def test_the_packaged_bridge_script_is_this_installations_own(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert codex_hook_binds_guard_home(_bridge_launch(_PACKAGED_BRIDGE, guard_home), guard_home)


def test_the_native_bridge_under_the_guard_home_is_this_installations_own(tmp_path):
    guard_home = tmp_path / "guard-home"
    runtime = guard_home / "native-runtime"
    runtime.mkdir(parents=True)
    program = runtime / "hol-guard-runtime"
    program.write_text("", encoding="utf-8")
    # The script is somewhere this install does not own; the program is not,
    # and the program is what survives a moved virtualenv.
    foreign = _bridge_script(tmp_path / "elsewhere")
    assert codex_hook_binds_guard_home(_native_launch(str(program), foreign, guard_home), guard_home)


def test_a_bridge_outside_this_installation_stays_unowned(tmp_path):
    """The shape `test_install_rejects_unowned_guard_bridge_without_committing` guards.

    Only an argument names this Guard home. The program lives somewhere this
    install has no control over, so the command proves nothing about who
    wrote it.
    """

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    script = _bridge_script(tmp_path / "pipx" / "hol-guard" / "adapters")
    assert codex_hook_guard_home(_bridge_launch(script, guard_home)) == guard_home
    assert not codex_hook_binds_guard_home(_bridge_launch(script, guard_home), guard_home)


def test_a_symlink_out_of_the_guard_home_is_not_inside_it(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    target = tmp_path / "evil" / "hol-guard-runtime"
    target.parent.mkdir()
    target.write_text("", encoding="utf-8")
    link = guard_home / "hol-guard-runtime"
    link.symlink_to(target)
    assert not codex_hook_binds_guard_home(
        _native_launch(str(link), _PACKAGED_BRIDGE.parent / "nowhere.py", guard_home), guard_home
    )


def test_a_sibling_root_sharing_a_name_prefix_is_not_inside(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    evil = tmp_path / "guard-home-evil"
    evil.mkdir()
    program = evil / "hol-guard-runtime"
    program.write_text("", encoding="utf-8")
    assert not codex_hook_binds_guard_home(_native_launch(str(program), _bridge_script(evil), guard_home), guard_home)


@pytest.mark.parametrize("program", ("hol-guard-runtime", "./hol-guard-runtime"))
def test_a_program_that_is_not_absolute_is_never_claimed(tmp_path, program):
    """A bare name is resolved through PATH at launch, so it names no file to own."""

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    assert not codex_hook_binds_guard_home(
        _native_launch(program, _bridge_script(tmp_path / "elsewhere"), guard_home), guard_home
    )


def test_a_program_that_does_not_exist_is_never_claimed(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    missing = guard_home / "native-runtime" / "hol-guard-runtime"
    assert not codex_hook_binds_guard_home(
        _native_launch(str(missing), _bridge_script(tmp_path / "elsewhere"), guard_home), guard_home
    )


def test_a_python_launcher_is_reported_rather_than_claimed(tmp_path):
    """Anyone can spell Guard's CLI fallback, so Guard never claims one."""

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    command = _cli_command("--guard-home", str(guard_home))
    assert codex_hook_guard_home(command) is None
    assert not codex_hook_binds_guard_home(command, guard_home)


def test_self_bound_bindings_name_the_group_by_matcher_alone(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    handler = {"type": "command", "command": _bridge_launch(_PACKAGED_BRIDGE, guard_home)}
    hooks = {"PreToolUse": [{"matcher": "Bash", "hooks": [handler, {"type": "command", "command": "other"}]}]}
    bindings = self_bound_hook_bindings(hooks, guard_home=guard_home)
    assert bindings == [{"event": "PreToolUse", "group": {"matcher": "Bash"}, "handler": handler}]


def test_a_handler_still_running_a_recorded_command_is_reported_not_claimed(tmp_path):
    """An edit Guard did not make is surfaced, even inside a slot Guard owns.

    The command here is one the authenticated manifest records, so Guard wrote
    those exact bytes. Whatever now differs from the recorded entry was changed
    by something else, and rewriting the slot would repair that edit without
    ever telling the person at the keyboard it happened.
    """

    guard_home = tmp_path / "guard-home"
    command = _bridge_launch(_PACKAGED_BRIDGE, guard_home)
    hooks = {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": command}]}]}

    assert self_bound_hook_bindings(hooks, guard_home=guard_home)
    assert self_bound_hook_bindings(hooks, guard_home=guard_home, recorded_commands=[command]) == []


def test_a_stale_generation_is_still_claimed_alongside_a_recorded_command(tmp_path):
    """A recorded command holds back only the handler running it.

    An upgrade or a moved virtualenv changes the launcher, so a stale handler's
    command is not one the manifest recorded and containment still decides it.
    """

    guard_home = tmp_path / "guard-home"
    recorded = _bridge_launch(_PACKAGED_BRIDGE, guard_home)
    stale = _bridge_launch(_PACKAGED_BRIDGE, guard_home, program="/opt/python3.12/bin/python3")
    hooks = {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": stale}]}]}

    claimed = self_bound_hook_bindings(hooks, guard_home=guard_home, recorded_commands=[recorded])

    assert [binding["handler"]["command"] for binding in claimed] == [stale]


def test_the_json_migration_path_does_not_hold_back_a_recorded_command(tmp_path):
    """The manifest authenticates the config entry, not one in hooks.json.

    A JSON handler that happens to run a recorded command is not Guard's
    recorded registration, so the holdback does not apply to it. Migration
    claims it the same way the JSON inventory does, instead of copying it into
    the config as a user hook.
    """

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    command = _bridge_launch(_PACKAGED_BRIDGE, guard_home)
    handler = {"type": "command", "command": command}
    hooks = {"PreToolUse": [{"matcher": "*", "hooks": [handler]}]}
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    recorded = [{"event": "PreToolUse", "group": {"matcher": "Bash", "hooks": [handler]}, "handler": dict(handler)}]

    assert _unmanaged_migration_payload({"hooks": hooks}, context=context, owned_bindings=()) == {}
    assert _unmanaged_migration_payload({"hooks": hooks}, context=context, owned_bindings=recorded) == {}
