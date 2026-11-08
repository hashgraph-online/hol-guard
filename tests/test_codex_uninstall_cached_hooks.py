"""Uninstall revokes cached hooks without allowing them to restart Guard."""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.render import _managed_install_notes
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path
from codex_plugin_scanner.guard.codex_install_notices import codex_install_notices


@pytest.mark.parametrize("active", [True, False])
def test_codex_scope_and_restart_notices_are_rendered(active):
    manifest = codex_install_notices(active=active)
    assert manifest["installation_scope"] == "user"
    assert manifest["runtime_restart_required"] is True
    notes = " ".join(_managed_install_notes({"active": active}, manifest))
    assert "all Codex sessions" in notes
    assert "--workspace" in notes
    assert "does not make the installation project-only" in notes
    assert "Fully quit and reopen Codex Desktop" in notes
    if not active:
        assert "cached Guard hooks may deny calls" in notes
        assert "stopping the daemon alone does not unload hooks" in notes


def test_repeated_cached_bridge_calls_after_uninstall_cannot_restart_guard(tmp_path):
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
        home_override_explicit=True,
    )
    adapter = codex.CodexHarnessAdapter()
    installed = adapter.install(context)
    assert installed["installation_scope"] == "user"
    assert installed["runtime_restart_required"] is True
    argv = codex._hook_command_parts(context)
    config = context.home_dir / ".codex/config.toml"
    manifest = hook_manifest_path(context.guard_home, config)
    removed = adapter.uninstall(context)
    assert removed["installation_scope"] == "user"
    assert removed["runtime_restart_required"] is True
    assert not manifest.exists()
    before_config = config.read_bytes() if config.exists() else None
    for _ in range(3):
        result = subprocess.run(
            argv,
            input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "true"}}),
            capture_output=True,
            text=True,
            timeout=15,
            env={**os.environ, "HOME": str(context.home_dir), "USERPROFILE": str(context.home_dir)},
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
        diagnostic = json.loads(result.stderr)
        reasons = {cause["reason_code"] for cause in diagnostic["causes"]}
        assert reasons & {"codex_hook_manifest_missing", "codex_hook_manifest_secret_missing"}
        assert not manifest.exists()
        assert not (context.guard_home / "daemon-state.json").exists()
        assert (config.read_bytes() if config.exists() else None) == before_config
