"""Tests for the OpenCode pretool plugin installer."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.hook_python import package_root_from_python, resolve_guard_hook_python
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


def _run_generated_guard_block_message(tmp_path: Path, *, stdout: str, stderr: str = "") -> str:
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("bun not installed")
    source = pretool_plugin_source(_ctx(tmp_path))
    plugin_path = tmp_path / "guard-block-plugin.ts"
    plugin_path.write_text(source, encoding="utf-8")
    script_path = tmp_path / "guard-block-runner.ts"
    script_path.write_text(
        "import { guardBlockMessage } from './guard-block-plugin';\n"
        + "console.log(guardBlockMessage("
        + json.dumps(stdout)
        + ", "
        + json.dumps(stderr)
        + "));\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [bun, str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def test_pretool_plugin_source_embeds_guard_paths(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    source = pretool_plugin_source(ctx)
    assert str(ctx.guard_home.resolve()) in source
    assert "tool.execute.before" in source
    assert "spawnGuardProcess" in source
    assert 'import { spawn as nodeSpawn } from "node:child_process"' in source
    assert "normalizeCommand" in source
    spawn_block = source.split("async function spawnGuardProcess", 1)[1].split("async function runGuardHook", 1)[0]
    assert "nodeSpawn" in spawn_block
    assert "globalThis" not in spawn_block
    assert "Bun" not in spawn_block
    assert ".stream()" not in spawn_block
    assert "try {" in source
    assert 'source_scope: directory?.trim() ? "project" : "global"' in source
    assert "GUARD_HOOK_LAUNCHER" in source
    assert "hookProcessEnv" in source
    assert "GUARD_INHERIT_ENV_KEYS" in source
    assert "HOL_GUARD_HOOK_ARGV" in source
    assert "cwd: GUARD_HOME" in source
    run_block = source.split("async function runGuardHook", 1)[1].split("function parseGuardPayload", 1)[0]
    assert "cwd: workspace" not in run_block
    assert '"-m",' not in source
    assert '-m",' not in source


def test_pretool_plugin_source_normalizes_argv_array_commands(tmp_path: Path) -> None:
    source = pretool_plugin_source(_ctx(tmp_path))
    assert "Array.isArray(command)" in source


def test_pretool_plugin_guard_block_message_appends_primary_approval_url(tmp_path: Path) -> None:
    message = _run_generated_guard_block_message(
        tmp_path,
        stdout=json.dumps(
            {
                "decision_v2_json": {
                    "harness_message": "HOL Guard blocked this OpenCode action.",
                },
                "primary_approval_url": "http://127.0.0.1:4455/requests/req-opencode",
            }
        ),
    )
    assert "http://127.0.0.1:4455/requests/req-opencode" in message
    assert "Open HOL Guard to approve or keep this blocked" in message


def test_pretool_plugin_guard_block_message_recovers_last_json_line(tmp_path: Path) -> None:
    message = _run_generated_guard_block_message(
        tmp_path,
        stdout="Guard queued approval request\n"
        + json.dumps(
            {
                "review_hint": "HOL Guard queued this OpenCode action for review.",
                "approval_requests": [
                    {"approval_url": "http://127.0.0.1:4455/approvals/req-opencode"},
                ],
            }
        ),
    )
    assert "http://127.0.0.1:4455/requests/req-opencode" in message
    assert message.count("http://127.0.0.1:4455/requests/req-opencode") == 1


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
    (fake_pkg / "cli.py").write_text(
        "import sys\nsys.stderr.write('hijacked')\nraise SystemExit(99)\n",
        encoding="utf-8",
    )

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    ctx = HarnessContext(home_dir=tmp_path / "home", workspace_dir=workspace, guard_home=guard_home)
    guard_python = resolve_guard_hook_python(ctx)
    package_root = package_root_from_python(guard_python)
    launcher = _pretool_hook_launcher_code(package_root=package_root)
    inherit_env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
    env = {**inherit_env, **_pretool_hook_env(package_root=package_root), _HOOK_ARGV_ENV: '["guard","hook","--json"]'}
    completed = subprocess.run(
        [sys.executable, "-c", launcher],
        cwd=workspace,
        env=env,
        input="{}",
        capture_output=True,
        text=True,
        check=False,
    )
    assert "hijacked" not in completed.stderr
    assert completed.returncode != 99


def test_pretool_hook_env_blocks_workspace_import_shadowing(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    guard_python = resolve_guard_hook_python(ctx)
    package_root = package_root_from_python(guard_python)
    env = _pretool_hook_env(package_root=package_root)
    assert env["PYTHONSAFEPATH"] == "1"
    assert env["PYTHONNOUSERSITE"] == "1"
    assert package_root in env["PYTHONPATH"]


def test_pretool_plugin_source_does_not_spawn_python_m_module(tmp_path: Path) -> None:
    source = pretool_plugin_source(_ctx(tmp_path))
    run_block = source.split("return spawnGuardProcess({", 1)[1].split("});", 1)[0]
    assert "codex_plugin_scanner.cli" not in run_block
    assert '"-c"' in run_block or "'-c'" in run_block or "-c" in run_block
    assert "GUARD_HOOK_LAUNCHER" in run_block


def test_pretool_plugin_source_includes_node_spawn_fallback(tmp_path: Path) -> None:
    spawn_block = (
        pretool_plugin_source(_ctx(tmp_path))
        .split("async function spawnGuardProcess", 1)[1]
        .split(
            "async function runGuardHook",
            1,
        )[0]
    )
    assert "nodeSpawn" in spawn_block
    assert "await import(" not in spawn_block
    assert "Bun" not in spawn_block
    assert 'proc.stdout?.setEncoding("utf8")' in spawn_block
    assert 'proc.stdin?.on("error", () => {})' in spawn_block
    assert "proc.stdin?.end(options.stdin)" in spawn_block


def test_pretool_plugin_source_has_no_bun_identifier(tmp_path: Path) -> None:
    source = pretool_plugin_source(_ctx(tmp_path))
    assert "Bun" not in source


def test_install_pretool_plugin_writes_managed_and_global_copies(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    manifest = install_pretool_plugin(ctx)
    assert Path(manifest["managed_plugin_path"]).is_file()
    assert Path(manifest["global_plugin_path"]).is_file()
    assert managed_plugin_path(ctx).read_text(encoding="utf-8") == global_plugin_path(ctx).read_text(encoding="utf-8")


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


def test_opencode_config_uses_guard_proxy_rejects_invalid_companion_command(tmp_path: Path) -> None:
    config = tmp_path / "opencode.json"
    config.write_text(
        json.dumps(
            {
                "mcp": {
                    "hol-guard::chrome-devtools": {
                        "type": "local",
                        "command": ["node", "not-a-proxy.js"],
                    },
                    "chrome-devtools": {
                        "type": "local",
                        "command": ["npx", "-y", "chrome-devtools-mcp@latest"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    assert opencode_config_uses_guard_proxy(config) is False


def test_opencode_config_uses_guard_proxy_detects_companion_server_name(tmp_path: Path) -> None:
    config = tmp_path / "opencode.json"
    config.write_text(
        json.dumps(
            {
                "mcp": {
                    "hol-guard::chrome-devtools": {
                        "type": "local",
                        "command": ["python", "-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy"],
                    }
                }
            }
        ),
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


def test_opencode_config_uses_guard_proxy_requires_companion_for_each_native_server(tmp_path: Path) -> None:
    config = tmp_path / "opencode.json"
    config.write_text(
        json.dumps(
            {
                "mcp": {
                    "hol-guard::old-server": {
                        "type": "local",
                        "command": ["python", "-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy"],
                    },
                    "new-server": {
                        "type": "local",
                        "command": ["node", "new-server.js"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    assert opencode_config_uses_guard_proxy(config) is False


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


def test_opencode_verification_ready_with_guard_companion_servers(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    ctx = _ctx(tmp_path)
    config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        json.dumps(
            {
                "mcp": {
                    "chrome-devtools": {
                        "type": "local",
                        "command": ["npx", "-y", "chrome-devtools-mcp@latest"],
                    },
                    "hol-guard::chrome-devtools": {
                        "type": "local",
                        "command": ["python", "-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    install_pretool_plugin(ctx)
    (ctx.guard_home / "bin").mkdir(parents=True, exist_ok=True)
    (ctx.guard_home / "bin" / "guard-opencode").write_text("#!/bin/sh\n", encoding="utf-8")
    store = GuardStore(ctx.guard_home)
    store.set_managed_install("opencode", True, None, {}, "2026-06-04T00:00:00+00:00")
    payload = install_commands_module.build_harness_verification("opencode", ctx, store=store)
    verification = payload["verification"]
    assert verification["mcp_proxy_configured"] is True
    assert verification["ready"] is True
    assert not verification["warnings"]


def test_refresh_opencode_pretool_plugin_rewrites_stale_plugin(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli import update_commands
    from codex_plugin_scanner.guard.store import GuardStore

    ctx = _ctx(tmp_path)
    store = GuardStore(ctx.guard_home)
    store.set_managed_install("opencode", True, None, {}, "2026-06-04T00:00:00+00:00")
    install_pretool_plugin(ctx)
    stale_path = global_plugin_path(ctx)
    stale_path.write_text("// stale plugin\n", encoding="utf-8")

    note = update_commands._refresh_opencode_pretool_plugin(context=ctx, store=store)

    assert note is not None
    assert "Refreshed the OpenCode pretool plugin" in note
    refreshed = stale_path.read_text(encoding="utf-8")
    assert "Bun" not in refreshed
    assert 'import { spawn as nodeSpawn } from "node:child_process"' in refreshed
    refreshed_managed = managed_plugin_path(ctx).read_text(encoding="utf-8")
    assert "Bun" not in refreshed_managed
    assert 'import { spawn as nodeSpawn } from "node:child_process"' in refreshed_managed


def test_refresh_opencode_pretool_plugin_handles_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.cli import update_commands
    from codex_plugin_scanner.guard.store import GuardStore

    ctx = _ctx(tmp_path)
    store = GuardStore(ctx.guard_home)
    store.set_managed_install("opencode", True, None, {}, "2026-06-04T00:00:00+00:00")

    def _raise_runtime_error(_context: HarnessContext) -> str:
        raise RuntimeError("no guard python")

    monkeypatch.setattr(update_commands, "pretool_plugin_source", _raise_runtime_error)

    note = update_commands._refresh_opencode_pretool_plugin(context=ctx, store=store)

    assert note is not None
    assert "Could not inspect OpenCode pretool plugin during update" in note


def test_refresh_opencode_pretool_plugin_handles_install_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.cli import update_commands
    from codex_plugin_scanner.guard.store import GuardStore

    ctx = _ctx(tmp_path)
    store = GuardStore(ctx.guard_home)
    store.set_managed_install("opencode", True, None, {}, "2026-06-04T00:00:00+00:00")
    install_pretool_plugin(ctx)
    global_plugin_path(ctx).write_text("// stale plugin\n", encoding="utf-8")

    def _raise_runtime_error(_context: HarnessContext) -> dict[str, object]:
        raise RuntimeError("write failed")

    monkeypatch.setattr(update_commands, "install_pretool_plugin", _raise_runtime_error)

    note = update_commands._refresh_opencode_pretool_plugin(context=ctx, store=store)

    assert note is not None
    assert "Could not refresh OpenCode pretool plugin during update" in note


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
