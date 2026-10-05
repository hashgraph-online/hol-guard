"""Current CLI settings take precedence over one-time migration input."""

import json

import pytest

from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.zcode_config import is_guard_managed_hook_command
from tests.test_zcode_adapter import _ctx, _write_cli_config


def test_install_and_uninstall_preserve_current_settings(tmp_path):
    context = _ctx(tmp_path)
    legacy = _write_cli_config(context.home_dir, {"hooks": {}, "legacy": True})
    legacy_before = legacy.read_bytes()
    settings = legacy.with_name("setting.json")
    user_handler = {"type": "command", "command": "echo user"}
    payload = {
        "ui": {"theme": "dark"},
        "hooks": {
            "enabled": True,
            "events": {
                "PreToolUse": [{"matcher": "Read", "hooks": [user_handler]}],
            },
        },
    }
    settings.write_text(json.dumps(payload))
    adapter = ZCodeHarnessAdapter()
    manifest = adapter.install(context)
    installed = json.loads(settings.read_text())
    assert manifest["config_path"] == str(settings)
    assert installed["hooks"]["enabled"] is True
    assert installed["ui"] == payload["ui"]
    handlers = [handler for group in installed["hooks"]["events"]["PreToolUse"] for handler in group["hooks"]]
    assert user_handler in handlers
    assert any(is_guard_managed_hook_command(handler["command"]) for handler in handlers)
    assert legacy.read_bytes() == legacy_before
    detected = adapter.detect(context)
    assert str(settings) in detected.config_paths
    assert str(legacy) not in detected.config_paths
    adapter.install(context)
    adapter.uninstall(context)
    remaining = json.loads(settings.read_text())
    assert remaining["ui"] == payload["ui"]
    handlers = [handler for group in remaining["hooks"]["events"]["PreToolUse"] for handler in group["hooks"]]
    assert handlers == [user_handler]
    assert remaining["hooks"]["enabled"] is True
    assert legacy.read_bytes() == legacy_before


@pytest.mark.parametrize("contents", ["[]", "not json"])
def test_invalid_current_settings_do_not_fall_back_to_legacy(tmp_path, contents):
    context = _ctx(tmp_path)
    legacy = _write_cli_config(context.home_dir, {"legacy": True})
    settings = legacy.with_name("setting.json")
    settings.write_text(contents)
    with pytest.raises(ValueError):
        ZCodeHarnessAdapter().prepare_install(context)
    assert settings.read_text() == contents
    assert json.loads(legacy.read_text()) == {"legacy": True}


def test_uninstall_prunes_hooks_copied_by_cli_migration(tmp_path):
    context = _ctx(tmp_path)
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    legacy = context.home_dir / ".zcode/cli/config.json"
    settings = legacy.with_name("setting.json")
    settings.write_bytes(legacy.read_bytes())
    adapter.uninstall(context)
    for path in (legacy, settings):
        assert "hooks" not in json.loads(path.read_text())


def test_uninstall_handles_removed_current_settings(tmp_path):
    context = _ctx(tmp_path)
    legacy = _write_cli_config(context.home_dir, {"legacy": True})
    settings = legacy.with_name("setting.json")
    settings.write_text("{}")
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    settings.unlink()
    adapter.uninstall(context)
    assert not settings.exists()
    assert json.loads(legacy.read_text()) == {"legacy": True}


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
    legacy = _write_cli_config(context.home_dir, {})
    settings = legacy.with_name("setting.json")
    settings.write_text('{"hooks":{"enabled":true}}')
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    state = context.guard_home / "managed/zcode/install.state.json"
    saved = json.loads(state.read_text())
    saved["hooks_enabled_before"] = recorded_enabled
    state.write_text(json.dumps(saved))

    if reinstall:
        adapter.install(context)
        assert json.loads(state.read_text())["hooks_enabled_before"] == {"present": True, "value": True}
    adapter.uninstall(context)
    assert json.loads(settings.read_text())["hooks"]["enabled"] is True


def test_uninstall_restores_preference_after_external_hook_cleanup(tmp_path):
    context = _ctx(tmp_path)
    legacy = _write_cli_config(context.home_dir, {})
    settings = legacy.with_name("setting.json")
    settings.write_text('{"hooks":{"enabled":false}}')
    adapter = ZCodeHarnessAdapter()
    adapter.install(context)
    settings.write_text('{"hooks":{"enabled":true}}')
    adapter.uninstall(context)
    assert json.loads(settings.read_text())["hooks"]["enabled"] is False
