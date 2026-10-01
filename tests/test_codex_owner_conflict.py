"""An unowned Guard-looking handler must not be removed or accepted as healthy."""

from __future__ import annotations

import json
import shlex
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_config import dump_toml, read_toml_payload
from codex_plugin_scanner.guard.codex_hook_registration import require_codex_hook_owner


@pytest.mark.parametrize("scope", ("group", "handler"))
@pytest.mark.parametrize("activation", ({"enabled": False}, {"disabled": True}))
def test_install_preserves_inactive_unowned_handlers(tmp_path, scope, activation):
    home = tmp_path / "home"
    config = home / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    handler = {"type": "command", "command": "python -m codex_plugin_scanner.cli guard hook --harness codex"}
    group = {"matcher": "Bash", "hooks": [handler]}
    (group if scope == "group" else handler).update(activation)
    config.write_text(dump_toml({"hooks": {"PreToolUse": [group]}}), encoding="utf-8")
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")
    CodexHarnessAdapter().install(context)
    groups = read_toml_payload(config)["hooks"]["PreToolUse"]
    assert group in groups
    assert len(groups) == 2


@pytest.mark.parametrize("argument", ("--harness codex-other", "--harness=codexevil", "--harness claude"))
@pytest.mark.parametrize("python_options", ("", "-W ignore -X dev"))
def test_other_harness_module_hook_is_not_a_codex_conflict(argument, python_options):
    require_codex_hook_owner(
        "python " + python_options + " -m codex_plugin_scanner.cli guard hook " + argument,
        ownership="unmanaged",
    )


@pytest.mark.parametrize("argument", ("--harness codex", "--harness=codex"))
@pytest.mark.parametrize(
    "python_options",
    (
        "",
        "-W ignore",
        "-X dev",
        "--check-hash-based-pycs always",
        "-I -W ignore -X dev",
        "-Wignore",
        "-Xdev",
        "-IW ignore",
    ),
)
def test_exact_codex_module_hook_requires_ownership(argument, python_options):
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(
            "python " + python_options + " -m codex_plugin_scanner.cli guard hook " + argument,
            ownership="unmanaged",
        )


@pytest.mark.parametrize("python_options", ("-W ignore", "-X dev", "--check-hash-based-pycs always", "--"))
def test_codex_bridge_with_python_option_operand_requires_ownership(python_options):
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(
            "python " + python_options + " /opt/guard/codex_daemon_hook_bridge.py",
            ownership="unmanaged",
        )


def test_python_option_terminator_does_not_execute_module():
    require_codex_hook_owner(
        "python -- -m codex_plugin_scanner.cli guard hook --harness codex",
        ownership="unmanaged",
    )


@pytest.mark.parametrize("python_options", ("", "-W ignore", "-X dev", "-I"))
@pytest.mark.parametrize("harness", ("codex", "claude"))
@pytest.mark.parametrize("attached", (True, False))
def test_inline_python_hook_checks_exact_harness(python_options, harness, attached):
    script = "from codex_plugin_scanner.cli import main; main(['guard','hook','--harness','" + harness + "'])"
    command = "python " + python_options + " -c" + ("" if attached else " ") + shlex.quote(script)
    if harness == "codex":
        with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
            require_codex_hook_owner(command, ownership="unmanaged")
    else:
        require_codex_hook_owner(command, ownership="unmanaged")


@pytest.mark.parametrize("launcher", ("-mcodex_plugin_scanner.cli", "-Im codex_plugin_scanner.cli"))
@pytest.mark.parametrize("command_prefix", ("guard hook", "hook"))
def test_python_attached_module_and_short_hook_commands_require_ownership(launcher, command_prefix):
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(
            "python " + launcher + " " + command_prefix + " --harness codex",
            ownership="unmanaged",
        )


@pytest.mark.parametrize("python_options", ("-I", "-W ignore", "-IW ignore"))
@pytest.mark.parametrize("attached", (True, False))
@pytest.mark.parametrize(
    "script",
    (
        "import sys; from codex_plugin_scanner.cli import main; raise SystemExit(main(sys.argv[1:]))",
        "from codex_plugin_scanner.cli import main; raise SystemExit(main())",
        "from sys import argv; from codex_plugin_scanner.cli import main; main(argv[1:])",
        "import sys as s; from codex_plugin_scanner.cli import main; main(s.argv[1:])",
    ),
)
def test_inline_bootstrap_hook_argv_requires_ownership(python_options, attached, script):
    command = "python " + python_options + " -c" + ("" if attached else " ") + shlex.quote(script)
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner(command + " guard hook --harness codex", ownership="unmanaged")
    require_codex_hook_owner(command + " guard hook --harness claude", ownership="unmanaged")


def test_later_script_argument_is_not_the_executed_bridge():
    require_codex_hook_owner(
        "python third-party.py /opt/guard/codex_daemon_hook_bridge.py",
        ownership="unmanaged",
    )


def test_inline_dynamic_harness_cannot_establish_unrelated_ownership():
    script = "from codex_plugin_scanner.cli import main; main(['guard','hook','--harness',harness_var])"
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner("python -c " + shlex.quote(script), ownership="unmanaged")


def test_static_codex_harness_with_dynamic_later_argument_requires_ownership():
    script = (
        "from codex_plugin_scanner.cli import main; extra = '--json'; main(['guard','hook','--harness','codex',extra])"
    )
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner("python -c " + shlex.quote(script), ownership="unmanaged")


@pytest.mark.parametrize(
    "script",
    (
        "# from codex_plugin_scanner.cli import main\nprint(['guard','hook','--harness','codex'])",
        "module = 'codex_plugin_scanner.cli'; print(['guard','hook','--harness','codex'])",
    ),
)
def test_module_name_in_comment_or_string_is_not_a_guard_import(script):
    require_codex_hook_owner("python -c " + shlex.quote(script), ownership="unmanaged")


def test_inline_cli_import_alias_with_trailing_arguments_requires_ownership():
    script = "from codex_plugin_scanner import cli; cli.main()"
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner("python -c " + shlex.quote(script) + " hook --harness codex", ownership="unmanaged")


@pytest.mark.parametrize(
    "script",
    (
        "import runpy,sys; sys.argv[1:]=['hook','--harness','codex']; "
        "runpy.run_module('codex_plugin_scanner.cli',run_name='__main__')",
        "import importlib; importlib.import_module('codex_plugin_scanner.cli').main(['hook','--harness','codex'])",
        "__import__('codex_plugin_scanner.cli',fromlist=['main']).main(['hook','--harness','codex'])",
    ),
)
def test_dynamic_cli_import_with_static_module_requires_ownership(script):
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        require_codex_hook_owner("python -c " + shlex.quote(script), ownership="unmanaged")


@pytest.mark.parametrize("binding_kind", ("same_home_bridge", "foreign_home_guard_cli"))
@pytest.mark.parametrize("source_format", ("toml", "json"))
@pytest.mark.parametrize("feature_enabled", (True, False))
def test_install_rejects_unowned_guard_bridge_without_committing(
    tmp_path: Path, binding_kind: str, source_format: str, feature_enabled: bool
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    config_path = home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    if binding_kind == "same_home_bridge":
        old_command = "python -I /opt/pipx/hol-guard/adapters/codex_daemon_hook_bridge.py " + shlex.quote(
            '{"state_path":"' + str(guard_home / "daemon-state.json") + '"}'
        )
    else:
        foreign_home = tmp_path / "other-guard-home"
        old_command = (
            "python -m codex_plugin_scanner.cli guard hook --harness codex "
            f"--guard-home {shlex.quote(str(foreign_home))}"
        )
    old_bridge = {"matcher": "Bash", "hooks": [{"type": "command", "command": old_command}]}
    third_party = {"matcher": "Bash", "hooks": [{"type": "command", "command": "lean-ctx hook observe"}]}
    events = ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")
    hook_payload = {"hooks": {event: [deepcopy(old_bridge), deepcopy(third_party)] for event in events}}
    hooks_path = config_path.with_name("hooks.json")
    config_payload = {"features": {"hooks": feature_enabled}, **(hook_payload if source_format == "toml" else {})}
    config_path.write_text(dump_toml(config_payload), encoding="utf-8")
    if source_format == "json":
        hooks_path.write_text(json.dumps(hook_payload), encoding="utf-8")
    before_json = hooks_path.read_bytes() if hooks_path.exists() else None
    before = config_path.read_bytes()
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
    result: dict[str, object] | None = None
    failure: Exception | None = None
    try:
        result = CodexHarnessAdapter().install(context)
    except Exception as error:
        failure = error

    installed = (
        read_toml_payload(config_path)
        if source_format == "toml"
        else json.loads(hooks_path.read_text(encoding="utf-8"))
    )
    hooks = installed.get("hooks")
    assert isinstance(hooks, dict)
    group_counts = {event: len(groups) for event in events if isinstance((groups := hooks.get(event)), list)}
    pretool_groups = hooks.get("PreToolUse")
    assert isinstance(pretool_groups, list)
    commands = [
        handler["command"]
        for group in pretool_groups
        if isinstance(group, dict)
        for handler in group.get("hooks", [])
        if isinstance(handler, dict) and isinstance(handler.get("command"), str)
    ]
    manifest_path = codex_adapter.hook_manifest_path(guard_home, config_path)
    assert failure is not None, (
        "Install accepted an unowned Guard bridge; "
        f"event group counts are {group_counts}, active={result.get('active') if result else None}, "
        f"integrity={result.get('managed_hook_integrity') if result else None}, manifest={manifest_path.exists()}, "
        f"old_present={old_command in commands}, third_party_present={'lean-ctx hook observe' in commands}"
    )
    expected_reason = "codex_hook_owner_conflict" if feature_enabled else "codex_hook_inventory_unmanaged_executable"
    assert expected_reason in str(failure)
    assert config_path.read_bytes() == before
    if before_json is not None:
        assert hooks_path.read_bytes() == before_json
    assert not manifest_path.exists()
