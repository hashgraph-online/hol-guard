"""Tests for the OpenCode pretool plugin installer."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.opencode import OpenCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.opencode_pretool import (
    _HOOK_ARGV_ENV,
    _pretool_hook_env,
    _pretool_hook_launcher_code,
    global_plugin_path,
    install_pretool_plugin,
    managed_plugin_path,
    opencode_config_has_mcp_servers,
    opencode_config_uses_guard_proxy,
    pretool_plugin_source,
    remove_pretool_plugin,
)
from codex_plugin_scanner.guard.cli import install_commands as install_commands_module


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    home = tmp_path / "home"
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=home,
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def test_pretool_plugin_source_embeds_guard_paths(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    source = pretool_plugin_source(ctx)
    assert str(ctx.guard_home.resolve()) in source
    assert "tool.execute.before" in source
    assert "Blob([JSON.stringify(payload)]).stream()" in source
    assert "stdoutPromise" in source
    assert "try {" in source
    assert 'source_scope: directory?.trim() ? "project" : "global"' in source
    assert "GUARD_HOOK_LAUNCHER" in source
    assert "HOL_GUARD_HOOK_ARGV" in source
    assert "cwd: GUARD_HOME" in source
    spawn_block = source.split("Bun.spawn(", 1)[1].split("});", 1)[0]
    assert "cwd: workspace" not in spawn_block
    assert '"-m",' not in source
    assert '-m",' not in source


def test_pretool_hook_launcher_ignores_workspace_package_hijack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: workspace must not precede trusted Guard on sys.path."""
    import subprocess

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fake_pkg = workspace / "codex_plugin_scanner"
    fake_pkg.mkdir()
    (fake_pkg / "__init__.py").write_text("", encoding="utf-8")
    (fake_pkg / "cli.py").write_text("import sys\nsys.stderr.write('hijacked')\nraise SystemExit(99)\n", encoding="utf-8")

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    ctx = HarnessContext(home_dir=tmp_path / "home", workspace_dir=workspace, guard_home=guard_home)
    launcher = _pretool_hook_launcher_code()
    env = {**_pretool_hook_env(), _HOOK_ARGV_ENV: '["guard","hook","--json"]'}
    completed = subprocess.run(
        [sys.executable, "-c", launcher],
        cwd=workspace,
        env={**os.environ, **env},
        input="{}",
        capture_output=True,
        text=True,
        check=False,
    )
    assert "hijacked" not in completed.stderr
    assert completed.returncode != 99


def test_install_pretool_plugin_writes_managed_and_global_copies(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    manifest = install_pretool_plugin(ctx)
    assert Path(manifest["managed_plugin_path"]).is_file()
    assert Path(manifest["global_plugin_path"]).is_file()
    assert managed_plugin_path(ctx).read_text(encoding="utf-8") == global_plugin_path(ctx).read_text(
        encoding="utf-8"
    )


def test_remove_pretool_plugin_deletes_installed_files(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    install_pretool_plugin(ctx)
    removed = remove_pretool_plugin(ctx)
    assert removed["removed_plugin_paths"]
    assert not global_plugin_path(ctx).exists()
    assert not managed_plugin_path(ctx).exists()


def test_opencode_install_includes_pretool_plugin_paths(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('{"mcp": {}}', encoding="utf-8")
    result = OpenCodeHarnessAdapter().install(ctx)
    assert Path(result["managed_plugin_path"]).is_file()
    assert Path(result["global_plugin_path"]).is_file()


def test_opencode_config_uses_guard_proxy_parses_jsonc_comments(tmp_path: Path) -> None:
    config = tmp_path / "opencode.jsonc"
    config.write_text(
        """
        {
          // Guard-managed MCP proxy
          "mcp": {
            "playwright": {
              "command": ["hol-guard", "guard", "opencode-mcp-proxy"]
            }
          }
        }
        """,
        encoding="utf-8",
    )
    assert opencode_config_uses_guard_proxy(config) is True


def test_opencode_config_uses_guard_proxy_detects_managed_command(tmp_path: Path) -> None:
    config = tmp_path / "opencode.json"
    config.write_text(
        json.dumps(
            {
                "mcp": {
                    "playwright": {
                        "type": "local",
                        "command": ["python", "-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    assert opencode_config_uses_guard_proxy(config) is True


def test_opencode_verification_ready_without_mcp_servers(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    ctx = _ctx(tmp_path)
    config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('{"mcp": {}}', encoding="utf-8")
    install_pretool_plugin(ctx)
    (ctx.guard_home / "bin").mkdir(parents=True, exist_ok=True)
    (ctx.guard_home / "bin" / "guard-opencode").write_text("#!/bin/sh\n", encoding="utf-8")
    store = GuardStore(ctx.guard_home)
    store.set_managed_install("opencode", True, None, {}, "2026-06-04T00:00:00+00:00")
    payload = install_commands_module.build_harness_verification("opencode", ctx, store=store)
    verification = payload["verification"]
    assert verification["pretool_plugin_installed"] is True
    assert verification["mcp_proxy_configured"] is False
    assert opencode_config_has_mcp_servers(config) is False
    assert verification["ready"] is True
    assert not verification["warnings"]


def test_opencode_verification_reports_missing_plugin(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    ctx = _ctx(tmp_path)
    store = GuardStore(ctx.guard_home)
    store.set_managed_install("opencode", True, None, {}, "2026-06-04T00:00:00+00:00")
    payload = install_commands_module.build_harness_verification("opencode", ctx, store=store)
    verification = payload["verification"]
    assert verification["managed_install_active"] is True
    assert verification["pretool_plugin_installed"] is False
    assert verification["ready"] is False
    assert verification["warnings"]
