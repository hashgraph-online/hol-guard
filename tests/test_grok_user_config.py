"""Durable user settings retain native coverage and unrelated TOML on migration."""

from pathlib import Path

import pytest
import tomlkit

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.native_install_checks import (
    _grok_protection_checks,
    grok_protection,
    grok_runtime_hooks_verified,
)
from codex_plugin_scanner.guard.codex_config import tomllib
from codex_plugin_scanner.guard.shims import PreparedGuardShim

from .grok_test_support import grok_paths

_LEGACY_MANAGED_BLOCK = (
    "# BEGIN HOL GUARD MANAGED GROK\n"
    "# Permission rules below are managed by HOL Guard. Do not edit manually.\n"
    "[permission]\n"
    'deny = ["Read(~/.grok/auth/**)"]\n'
    "\n"
    "[[hooks.PreToolUse]]\n"
    'hooks = [{ type = "command", command = "old guard hook", timeout = 30 }]\n'
    "# END HOL GUARD MANAGED GROK"
)


def test_vendor_refresh_cannot_remove_durable_protection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = HarnessContext(tmp_path / "home", None, tmp_path / "guard")
    monkeypatch.delenv("GROK_HOME", raising=False)
    shim = context.guard_home / "bin" / "guard-grok"
    shim.parent.mkdir(parents=True)
    shim.write_text("#!/bin/sh\n")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.shims.prepare_guard_shim",
        lambda *args, **kwargs: PreparedGuardShim((), {"shim_path": str(shim), "notes": []}),
    )
    vendor = context.home_dir / ".grok" / "managed_config.toml"
    vendor.parent.mkdir(parents=True)
    enterprise = '# Enterprise settings\nmodel="synthetic-enterprise-model"\n'
    vendor.write_text(enterprise)
    adapter = get_adapter("grok")
    manifest = adapter.install(context)
    artifacts = manifest["protection_artifact_paths"]
    assert isinstance(artifacts, list)
    assert str(grok_paths(context)["config"]) in artifacts
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
    assert set(grok_protection(context)["managed_deny_rules"]) <= set(payload["permission"]["deny"])
    for event in ("PreToolUse", "UserPromptSubmit", "SessionStart", "SubagentStart"):
        assert len(payload["hooks"][event]) == 1


def test_legacy_backup_hooks_migrate_without_changing_vendor_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = HarnessContext(tmp_path / "home", None, tmp_path / "guard")
    monkeypatch.delenv("GROK_HOME", raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.shims.prepare_guard_shim",
        lambda *args, **kwargs: PreparedGuardShim((), {"notes": []}),
    )
    vendor = context.home_dir / ".grok" / "managed_config.toml"
    vendor.parent.mkdir(parents=True)
    enterprise = '# Enterprise settings\nmodel="synthetic-enterprise-model"\n'
    vendor.write_text(enterprise + _LEGACY_MANAGED_BLOCK)
    get_adapter("grok").install(context)
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
        "codex_plugin_scanner.guard.shims.prepare_guard_shim",
        lambda *args, **kwargs: PreparedGuardShim((), {"shim_path": str(shim), "notes": []}),
    )
    remove_shim = Mock()
    monkeypatch.setattr("codex_plugin_scanner.guard.shims.remove_guard_shim", remove_shim)
    adapter = get_adapter("grok")
    adapter.install(context)
    hooks = grok_paths(context)["pretool"]
    before = hooks.read_bytes()
    config = grok_paths(context)["config"]
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
        "codex_plugin_scanner.guard.shims.prepare_guard_shim",
        lambda *args, **kwargs: PreparedGuardShim((), {"notes": []}),
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.shims.remove_guard_shim", lambda *args, **kwargs: {})
    adapter = get_adapter("grok")
    adapter.install(context)
    config = grok_paths(context)["config"]
    before = config.read_bytes()
    grok_paths(context)["state"].unlink()
    result = adapter.uninstall(context)
    assert config.read_bytes() == before
    assert not grok_paths(context)["pretool"].exists()
    notes = result["notes"]
    assert isinstance(notes, list)
    assert any(isinstance(note, str) and "ownership records are missing" in note for note in notes)
