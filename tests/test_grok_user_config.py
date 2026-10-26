"""Durable user settings retain native coverage and unrelated TOML on migration."""

from pathlib import Path

import pytest
import tomlkit

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter, grok_runtime_hooks_verified
from codex_plugin_scanner.guard.adapters.grok_config import MANAGED_DENY_RULES, build_managed_config_block
from codex_plugin_scanner.guard.adapters.grok_user_config import prepare_user_config_text, remove_user_config_settings
from codex_plugin_scanner.guard.cli.native_install_checks import _grok_protection_checks
from codex_plugin_scanner.guard.codex_config import tomllib
from codex_plugin_scanner.guard.shims import PreparedGuardShim


def test_merge_preserves_comments_existing_permissions_and_hooks() -> None:
    existing = """# User preferences
model = "synthetic-provider-model" # keep model
[permission]
allow = ["Bash(git status*)"]
deny = ["Read(custom-private-file)"] # user deny
[compat.claude]
skills = true
hooks = true # previous setting
[[hooks.PreToolUse]]
matcher = "custom_tool"
hooks = [{type = "command", command = "custom-check"}]
"""
    merged, state = prepare_user_config_text(existing, "guard hook --json", previous_state={})
    parsed = tomllib.loads(merged)
    assert parsed["model"] == "synthetic-provider-model"
    assert "# keep model" in merged and "# User preferences" in merged and "# user deny" in merged
    assert parsed["permission"]["allow"] == ["Bash(git status*)"]
    assert parsed["permission"]["deny"] == ["Read(custom-private-file)", *MANAGED_DENY_RULES]
    assert parsed["compat"]["claude"] == {"skills": True, "hooks": False}
    assert parsed["hooks"]["PreToolUse"][0]["matcher"] == "custom_tool"
    assert parsed["hooks"]["PreToolUse"][1]["hooks"][0]["command"] == "guard hook --json"
    added_events = state["added_hook_events"]
    assert isinstance(added_events, list)
    assert set(added_events) == {"PreToolUse", "UserPromptSubmit", "SessionStart", "SubagentStart"}
    restored = tomllib.loads(remove_user_config_settings(merged, state))
    assert restored["permission"]["deny"] == ["Read(custom-private-file)"]
    assert restored["hooks"]["PreToolUse"] == tomllib.loads(existing)["hooks"]["PreToolUse"]
    assert restored["compat"]["claude"]["hooks"] is True


def test_reinstall_replaces_old_hook_without_duplication_and_preserves_original_state() -> None:
    first, state = prepare_user_config_text("[compat.claude]\nhooks=true\n", "old guard hook", previous_state={})
    second, state = prepare_user_config_text(first, "new guard hook", previous_state=state)
    third, state = prepare_user_config_text(second, "new guard hook", previous_state=state)
    assert tomllib.loads(second) == tomllib.loads(third)
    assert "old guard hook" not in third
    for groups in tomllib.loads(third)["hooks"].values():
        assert len(groups) == 1
    assert tomllib.loads(remove_user_config_settings(third, state))["compat"]["claude"]["hooks"] is True


def test_uninstall_retains_preexisting_guard_rules_and_later_user_changes() -> None:
    existing = '[permission]\ndeny=["Read(**/.env)"]\n[compat.claude]\nhooks=true\n'
    merged, state = prepare_user_config_text(existing, "guard hook", previous_state={})
    document = tomlkit.parse(merged)
    document["permission"]["deny"].append("Read(new-user-rule)")
    document["compat"]["claude"]["hooks"] = True
    restored = tomllib.loads(remove_user_config_settings(tomlkit.dumps(document), state))
    assert restored["permission"]["deny"] == ["Read(**/.env)", "Read(new-user-rule)"]
    assert restored["compat"]["claude"]["hooks"] is True


def test_later_identical_user_rule_and_hook_survive_uninstall() -> None:
    merged, state = prepare_user_config_text("", "guard hook", previous_state={})
    document = tomlkit.parse(merged)
    document["permission"]["deny"].append("Read(**/.env)")
    original = document["hooks"]["PreToolUse"][0].unwrap()
    document["hooks"]["PreToolUse"].append(tomlkit.item(original))
    restored = tomllib.loads(remove_user_config_settings(tomlkit.dumps(document), state))
    assert restored["permission"]["deny"] == ["Read(**/.env)"]
    assert restored["hooks"]["PreToolUse"] == [original]


def test_inline_hook_array_round_trips_without_losing_user_handler() -> None:
    existing = '[hooks]\nPreToolUse=[{matcher="custom_tool",hooks=[{type="command",command="custom-check"}]}]\n'
    merged, state = prepare_user_config_text(existing, "guard hook", previous_state={})
    parsed = tomllib.loads(merged)
    assert len(parsed["hooks"]["PreToolUse"]) == 2
    restored = tomllib.loads(remove_user_config_settings(merged, state))
    assert restored == tomllib.loads(existing)


@pytest.mark.parametrize(
    "text",
    [
        '[permission]\ndeny="invalid"\n',
        '[hooks]\nPreToolUse="invalid"\n',
        '[compat.claude]\nhooks="invalid"\n',
        "[permission]\npermission=",
    ],
)
def test_malformed_user_config_is_rejected_without_overwrite(text: str) -> None:
    with pytest.raises(ValueError):
        prepare_user_config_text(text, "guard hook", previous_state={})


def test_vendor_refresh_cannot_remove_durable_protection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = HarnessContext(tmp_path / "home", None, tmp_path / "guard")
    monkeypatch.delenv("GROK_HOME", raising=False)
    shim = context.guard_home / "bin" / "guard-grok"
    shim.parent.mkdir(parents=True)
    shim.write_text("#!/bin/sh\n")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.grok.prepare_guard_shim",
        lambda *args, **kwargs: PreparedGuardShim((), {"shim_path": str(shim), "notes": []}),
    )
    vendor = context.home_dir / ".grok" / "managed_config.toml"
    vendor.parent.mkdir(parents=True)
    enterprise = '# Enterprise settings\nmodel="synthetic-enterprise-model"\n'
    vendor.write_text(enterprise)
    adapter = GrokHarnessAdapter()
    manifest = adapter.install(context)
    artifacts = manifest["protection_artifact_paths"]
    assert isinstance(artifacts, list)
    assert str(adapter._protection_config_path(context)) in artifacts
    assert vendor.read_text() == enterprise
    vendor.unlink()  # Grok's authenticated configuration refresh owns this file.
    assert _grok_protection_checks(context)["ready"] is True
    durable = context.home_dir / ".grok" / "config.toml"
    document = tomlkit.parse(durable.read_text())
    document["model"] = "synthetic-user-model"
    document["permission"]["deny"].append("Read(~/.ssh/**)")
    durable.write_text(tomlkit.dumps(document) + "# Read(~/.grok/auth/**) is a user comment.\n")
    assert _grok_protection_checks(context)["ready"] is True
    assert grok_runtime_hooks_verified(context) is True
    payload = tomllib.loads(durable.read_text())
    assert set(MANAGED_DENY_RULES) <= set(payload["permission"]["deny"])
    for event in ("PreToolUse", "UserPromptSubmit", "SessionStart", "SubagentStart"):
        assert len(payload["hooks"][event]) == 1


def test_legacy_backup_hooks_migrate_without_changing_vendor_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = HarnessContext(tmp_path / "home", None, tmp_path / "guard")
    monkeypatch.delenv("GROK_HOME", raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.grok.prepare_guard_shim",
        lambda *args, **kwargs: PreparedGuardShim((), {"notes": []}),
    )
    vendor = context.home_dir / ".grok" / "managed_config.toml"
    vendor.parent.mkdir(parents=True)
    enterprise = '# Enterprise settings\nmodel="synthetic-enterprise-model"\n'
    vendor.write_text(enterprise + build_managed_config_block("old guard hook"))
    GrokHarnessAdapter().install(context)
    assert tomllib.loads(vendor.read_text()) == tomllib.loads(enterprise)
    assert "old guard hook" not in vendor.read_text()


def test_malformed_config_leaves_uninstall_artifacts_intact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import Mock

    context = HarnessContext(tmp_path / "home", None, tmp_path / "guard")
    monkeypatch.delenv("GROK_HOME", raising=False)
    shim = context.guard_home / "bin" / "guard-grok"
    shim.parent.mkdir(parents=True)
    shim.write_text("#!/bin/sh\n")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.grok.prepare_guard_shim",
        lambda *args, **kwargs: PreparedGuardShim((), {"shim_path": str(shim), "notes": []}),
    )
    remove_shim = Mock()
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.grok.remove_guard_shim", remove_shim)
    adapter = GrokHarnessAdapter()
    adapter.install(context)
    hooks = adapter._hooks_dir(context) / "hol-guard-pretooluse.json"
    before = hooks.read_bytes()
    config = adapter._protection_config_path(context)
    config.write_text("[permission\n")
    with pytest.raises(ValueError):
        adapter.uninstall(context)
    remove_shim.assert_not_called()
    assert shim.is_file() and hooks.read_bytes() == before
    assert config.read_text() == "[permission\n"


def test_missing_ownership_warns_without_deleting_user_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = HarnessContext(tmp_path / "home", None, tmp_path / "guard")
    monkeypatch.delenv("GROK_HOME", raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.grok.prepare_guard_shim",
        lambda *args, **kwargs: PreparedGuardShim((), {"notes": []}),
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.grok.remove_guard_shim", lambda *args, **kwargs: {})
    adapter = GrokHarnessAdapter()
    adapter.install(context)
    config = adapter._protection_config_path(context)
    before = config.read_bytes()
    adapter._state_path(context).unlink()
    result = adapter.uninstall(context)
    assert config.read_bytes() == before
    assert not (adapter._hooks_dir(context) / "hol-guard-pretooluse.json").exists()
    notes = result["notes"]
    assert isinstance(notes, list)
    assert any(isinstance(note, str) and "ownership records are missing" in note for note in notes)
