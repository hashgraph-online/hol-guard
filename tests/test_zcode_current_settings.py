"""Hooks install onto both ZCode surfaces: config.json and setting.json.

Current ZCode splits hook loading per surface: the Desktop app reads user
hooks from ``~/.zcode/cli/config.json`` while the npm CLI reads them from its
``~/.zcode/cli/setting.json`` file-config, and each surface requires an
explicit ``hooks.enabled: true`` opt-in before any entry executes. Guard
maintains managed hooks in both files and restores each file's prior state on
uninstall.
"""

import json

import pytest

from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.zcode_config import GUARD_MANAGED_MARKER, is_guard_managed_hook_command
from tests.test_zcode_adapter import _ctx, _write_cli_config


def _file_config(home):
    path = home / ".zcode" / "cli" / "setting.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _managed_handlers(payload):
    return [
        handler
        for group in (payload.get("hooks", {}).get("events", {}).get("PreToolUse") or [])
        for handler in group.get("hooks", [])
        if is_guard_managed_hook_command(handler.get("command"))
    ]


def test_install_writes_both_surfaces_with_opt_in(tmp_path):
    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {"hooks": {}, "legacy": True})
    settings = _file_config(context.home_dir)
    settings.write_text(json.dumps({"ui": {"theme": "dark"}}))
    manifest = ZCodeHarnessAdapter().install(context)

    assert manifest["config_path"] == str(config)
    installed_config = json.loads(config.read_text())
    installed_settings = json.loads(settings.read_text())
    for installed in (installed_config, installed_settings):
        assert installed["hooks"]["enabled"] is True
        assert _managed_handlers(installed)
    assert installed_config["legacy"] is True
    assert installed_settings["ui"] == {"theme": "dark"}


def test_install_refreshes_misdirected_setting_json_install(tmp_path):
    """Installs that only wrote setting.json get the Desktop surface too."""

    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {})
    settings = _file_config(context.home_dir)
    managed = f"echo guard # {GUARD_MANAGED_MARKER}"
    settings.write_text(
        json.dumps(
            {
                "ui": {"theme": "dark"},
                "hooks": {
                    "enabled": True,
                    "events": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": managed}]}]},
                },
            }
        )
    )

    manifest = ZCodeHarnessAdapter().install(context)

    assert manifest["config_path"] == str(config)
    migrated = json.loads(settings.read_text())
    assert migrated["ui"] == {"theme": "dark"}
    commands = [handler["command"] for handler in _managed_handlers(migrated)]
    assert commands and managed not in commands
    assert _managed_handlers(json.loads(config.read_text()))


def test_install_preserves_user_handlers_on_both_surfaces(tmp_path):
    context = _ctx(tmp_path)
    user_handler = {"type": "command", "command": "echo user"}
    config = _write_cli_config(
        context.home_dir,
        {"hooks": {"events": {"PreToolUse": [{"matcher": "Read", "hooks": [dict(user_handler)]}]}}},
    )
    settings = _file_config(context.home_dir)
    cli_user = {"type": "command", "command": "echo cli-user"}
    settings.write_text(
        json.dumps({"locale": "en", "hooks": {"enabled": True, "events": {"Stop": [{"hooks": [cli_user]}]}}})
    )
    ZCodeHarnessAdapter().install(context)

    installed_config = json.loads(config.read_text())
    handlers = [h for g in installed_config["hooks"]["events"]["PreToolUse"] for h in g["hooks"]]
    assert dict(user_handler) in handlers
    installed_settings = json.loads(settings.read_text())
    cli_handlers = [h for g in installed_settings["hooks"]["events"]["Stop"] for h in g["hooks"]]
    assert cli_user in cli_handlers
    assert installed_settings["locale"] == "en"


@pytest.mark.parametrize("contents", ["[]", "not json"])
def test_invalid_config_json_is_rejected(tmp_path, contents):
    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {})
    config.write_text(contents)
    settings = _file_config(context.home_dir)
    settings.write_text(json.dumps({"ui": {"theme": "dark"}}))
    with pytest.raises(ValueError):
        ZCodeHarnessAdapter().prepare_install(context)
    assert config.read_text() == contents
    assert json.loads(settings.read_text()) == {"ui": {"theme": "dark"}}


@pytest.mark.parametrize("contents", ["[]", "null", "not json"])
def test_invalid_file_config_is_never_clobbered(tmp_path, contents):
    context = _ctx(tmp_path)
    _write_cli_config(context.home_dir, {})
    settings = _file_config(context.home_dir)
    settings.write_text(contents)
    with pytest.raises(ValueError):
        ZCodeHarnessAdapter().prepare_install(context)
    assert settings.read_text() == contents


def test_absent_file_config_is_not_created(tmp_path):
    """The CLI's one-time migration must stay available to carry hooks over."""

    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {})
    ZCodeHarnessAdapter().install(context)
    settings = _file_config(context.home_dir)
    assert not settings.exists()
    assert _managed_handlers(json.loads(config.read_text()))


def test_uninstall_preserves_user_root_hook_settings(tmp_path):
    context = _ctx(tmp_path)
    _write_cli_config(context.home_dir, {})
    settings = _file_config(context.home_dir)
    settings.write_text(json.dumps({"hooks": {"timeoutMs": 9000, "events": {}}}))
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    adapter.uninstall(context)

    hooks = json.loads(settings.read_text())["hooks"]
    assert hooks == {"timeoutMs": 9000}


def test_uninstall_restores_each_surface(tmp_path):
    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {"hooks": {"enabled": False}})
    settings = _file_config(context.home_dir)
    settings.write_text(json.dumps({"hooks": {"enabled": True}}))
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    adapter.uninstall(context)

    remaining_config = json.loads(config.read_text())
    remaining_settings = json.loads(settings.read_text())
    assert remaining_config["hooks"]["enabled"] is False
    assert remaining_settings["hooks"]["enabled"] is True


def test_uninstall_removes_guard_introduced_enabled(tmp_path):
    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {})
    settings = _file_config(context.home_dir)
    settings.write_text(json.dumps({"locale": "en"}))
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    adapter.uninstall(context)

    assert "hooks" not in json.loads(config.read_text())
    assert json.loads(settings.read_text()) == {"locale": "en"}


def test_uninstall_prunes_both_surfaces(tmp_path):
    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {})
    settings = _file_config(context.home_dir)
    settings.write_text("{}")
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    adapter.uninstall(context)

    assert "hooks" not in json.loads(config.read_text())
    assert "hooks" not in json.loads(settings.read_text())


def test_uninstall_handles_removed_file_config(tmp_path):
    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {"legacy": True})
    settings = _file_config(context.home_dir)
    settings.write_text("{}")
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    settings.unlink()
    adapter.uninstall(context)
    assert not settings.exists()
    assert json.loads(config.read_text()) == {"legacy": True, "mcp": {}, "plugins": {}}


def test_install_does_not_enable_disabled_user_handlers(tmp_path):
    context = _ctx(tmp_path)
    legacy = _write_cli_config(context.home_dir, {})
    settings = legacy.with_name("setting.json")
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "enabled": False,
                    "events": {
                        "PreToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": "echo user"}]}],
                    },
                }
            }
        )
    )
    before = settings.read_bytes()
    with pytest.raises(ValueError, match="user hooks are disabled"):
        ZCodeHarnessAdapter().prepare_install(context)
    assert settings.read_bytes() == before


def test_uninstall_restores_disabled_empty_hooks_after_reinstall(tmp_path):
    context = _ctx(tmp_path)
    legacy = _write_cli_config(context.home_dir, {})
    settings = legacy.with_name("setting.json")
    settings.write_text('{"hooks":{"enabled":false}}')
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    adapter.install(context)
    adapter.uninstall(context)
    assert json.loads(settings.read_text())["hooks"]["enabled"] is False


@pytest.mark.parametrize("contents", ["[]", "null", "not json"])
def test_reinstall_recovers_invalid_install_state(tmp_path, contents):
    context = _ctx(tmp_path)
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    state = context.guard_home / "managed/zcode/install.state.json"
    state.write_text(contents)
    adapter.install(context)
    assert isinstance(json.loads(state.read_text()), dict)


@pytest.mark.parametrize(
    "recorded_enabled",
    [
        None,
        False,
        "disabled",
        [],
        1,
        {},
        {"present": True},
        {"present": False},
        {"value": True},
        {"present": "yes", "value": True},
        {"present": True, "value": "yes"},
        {"present": True, "value": None},
    ],
)
@pytest.mark.parametrize("reinstall", [True, False])
def test_invalid_saved_hook_preference_preserves_current_setting(tmp_path, recorded_enabled, reinstall):
    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {"hooks": {"enabled": True}})
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    state = context.guard_home / "managed/zcode/install.state.json"
    saved = json.loads(state.read_text())
    saved["hooks_enabled_before"] = recorded_enabled
    state.write_text(json.dumps(saved))

    if reinstall:
        adapter.install(context)
        refreshed = json.loads(state.read_text())["hooks_enabled_before"]
        assert refreshed[str(config)] == {"present": True, "value": True}
    adapter.uninstall(context)
    assert json.loads(config.read_text())["hooks"]["enabled"] is True


def test_uninstall_keeps_user_preference_after_external_hook_cleanup(tmp_path):
    """Once Guard's entries are gone, the user's live value is the freshest."""

    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {"hooks": {"enabled": False}})
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    config.write_text(json.dumps({"hooks": {"enabled": True, "events": {}}}))
    adapter.uninstall(context)
    assert json.loads(config.read_text())["hooks"]["enabled"] is True


def test_legacy_setting_json_state_maps_onto_file_config(tmp_path):
    """Upgrading a setting.json-only install restores that file's prior."""

    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {})
    settings = _file_config(context.home_dir)
    settings.write_text(json.dumps({"hooks": {"enabled": False}}))
    state = context.guard_home / "managed/zcode/install.state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        json.dumps(
            {
                "managed_config_path": str(settings),
                "hooks_enabled_before": {"present": True, "value": False},
            }
        )
    )
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    adapter.uninstall(context)

    assert json.loads(settings.read_text())["hooks"]["enabled"] is False
    assert "hooks" not in json.loads(config.read_text())


def test_detect_inventories_both_hook_surfaces(tmp_path):
    context = _ctx(tmp_path)
    config = _write_cli_config(context.home_dir, {})
    settings = _file_config(context.home_dir)
    settings.write_text(json.dumps({"hooks": {"enabled": True}}))
    detected = ZCodeHarnessAdapter().detect(context)
    assert str(config) in detected.config_paths
    assert str(settings) in detected.config_paths
