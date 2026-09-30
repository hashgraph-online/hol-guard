from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.opencode import OpenCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.opencode_pretool import pretool_plugin_source
from tests.test_opencode_pretool import _bun_executable, _ctx


def _stale_companion(tmp_path: Path):
    ctx = _ctx(tmp_path)
    config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "mcp": {
                    "test": {
                        "type": "local",
                        "command": ["python3", "server.py"],
                        "enabled": True,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    OpenCodeHarnessAdapter().install(ctx)
    payload = json.loads(config.read_text(encoding="utf-8"))
    companion = payload["mcp"]["hol-guard::test"]
    argv = companion["command"]
    companion["command"] = ["/removed/versions/3.12.0/hol-guard", *argv[argv.index("opencode-mcp-proxy") :]]
    config.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return ctx, config, payload


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode contract")
def test_refresh_preserves_jsonc_comments_and_existing_mode(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.opencode_proxy_refresh import refresh_opencode_proxy_launchers
    from codex_plugin_scanner.guard.runtime.jsonc import loads_jsonc

    ctx, config, payload = _stale_companion(tmp_path)
    text = config.read_text(encoding="utf-8")
    text = "// user configuration\n" + text.replace(
        '"/removed/versions/3.12.0/hol-guard",',
        '"/removed/versions/3.12.0/hol-guard", // launcher note\n',
    )
    config.write_text(text, encoding="utf-8")
    config.chmod(0o640)
    assert refresh_opencode_proxy_launchers(ctx) == 1
    result = config.read_text(encoding="utf-8")
    assert "// user configuration" in result
    assert "// launcher note" in result
    assert stat.S_IMODE(config.stat().st_mode) == 0o640
    expected = payload["mcp"]["hol-guard::test"]["command"]
    actual = loads_jsonc(result)
    actual["mcp"]["hol-guard::test"]["command"] = expected
    assert actual == payload


def test_invalid_workspace_config_does_not_block_valid_global_refresh(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.opencode_artifacts import config_paths
    from codex_plugin_scanner.guard.adapters.opencode_proxy_refresh import refresh_opencode_proxy_launchers

    ctx, config, _ = _stale_companion(tmp_path)
    other = next(path for path in config_paths(ctx) if path != config)
    other.parent.mkdir(parents=True, exist_ok=True)
    other.write_text("{invalid", encoding="utf-8")
    warnings: list[str] = []
    assert refresh_opencode_proxy_launchers(ctx, warnings=warnings) == 1
    assert len(warnings) == 1
    assert other.read_text(encoding="utf-8") == "{invalid"
    assert "/removed/versions/" not in config.read_text(encoding="utf-8")


def test_refresh_skips_changed_transport(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.opencode_proxy_refresh import refresh_opencode_proxy_launchers

    ctx, config, payload = _stale_companion(tmp_path)
    payload["mcp"]["test"]["type"] = "remote"
    config.write_text(json.dumps(payload), encoding="utf-8")
    before = config.read_bytes()
    assert refresh_opencode_proxy_launchers(ctx) == 0
    assert config.read_bytes() == before


def test_refresh_does_not_overwrite_concurrent_config_edit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.adapters import opencode_proxy_refresh

    ctx, config, payload = _stale_companion(tmp_path)
    original = opencode_proxy_refresh.guard_cli_command
    user_edit = json.dumps({**payload, "user_note": "edited concurrently"}).encode()

    def changed(context, args):
        config.write_bytes(user_edit)
        return original(context, args)

    monkeypatch.setattr(opencode_proxy_refresh, "guard_cli_command", changed)
    with pytest.raises(ValueError, match="changed during launcher refresh"):
        opencode_proxy_refresh.refresh_opencode_proxy_launchers(ctx)
    assert config.read_bytes() == user_edit


def test_invalid_config_does_not_prevent_independent_plugin_refresh(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.opencode_pretool import global_plugin_path, install_pretool_plugin
    from codex_plugin_scanner.guard.cli.update_opencode import _refresh_opencode_pretool_plugin
    from codex_plugin_scanner.guard.store import GuardStore

    ctx = _ctx(tmp_path)
    install_pretool_plugin(ctx)
    global_plugin_path(ctx).write_text("// stale plugin", encoding="utf-8")
    config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
    config.write_text("{invalid", encoding="utf-8")
    store = GuardStore(ctx.guard_home)
    store.set_managed_install("opencode", True, None, {}, "2026-09-01T00:00:00+00:00")
    note = _refresh_opencode_pretool_plugin(context=ctx, store=store)
    assert note is not None
    assert "Could not refresh OpenCode MCP companion launchers" in note
    assert "Refreshed the OpenCode pretool plugin" in note
    assert global_plugin_path(ctx).read_text(encoding="utf-8") == pretool_plugin_source(ctx)
    assert config.read_text(encoding="utf-8") == "{invalid"


@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_pretool_v2_registers_and_preserves_guard_decisions(tmp_path: Path, exit_code: int) -> None:
    bun = _bun_executable()
    if bun is None:
        pytest.skip("bun not installed")
    source = pretool_plugin_source(_ctx(tmp_path)).replace(
        "result = await runGuardHook(", "result = await globalThis.guardTestHook("
    )
    (tmp_path / "plugin.ts").write_text(source, encoding="utf-8")
    runner = tmp_path / "runner.ts"
    runner.write_text(
        "import plugin, { HolGuardPretoolPlugin } from './plugin';\n"
        "let handler; let calls = 0; let registered = 0;\n"
        "globalThis.guardTestHook = async (directory, payload) => {\n"
        "  calls++;\n"
        "  if (directory !== '/project' || payload.cwd !== '/project' ||\n"
        "      payload.tool_name !== 'bash' || payload.tool_input.command !== 'pwd')\n"
        "    throw new Error('incorrect Guard action');\n"
        f"  return {{ exitCode: {exit_code}, stdout: '', stderr: 'test rejection' }};\n"
        "};\n"
        "if (typeof plugin !== 'object' || plugin.id !== 'hol-guard-pretool' ||\n"
        "    plugin.server !== HolGuardPretoolPlugin)\n"
        "  throw new Error('incorrect entrypoint');\n"
        "await plugin.setup({ location: { directory: '/project' }, tool: {\n"
        "  async hook(name, callback) {\n"
        "    if (name !== 'execute.before') throw new Error('incorrect hook');\n"
        "    registered++; handler = callback;\n"
        "  }\n"
        "} });\n"
        "if (registered !== 1) throw new Error('duplicate registration');\n"
        "let blocked = false;\n"
        "try { await handler({ tool: 'bash', input: { command: ['pwd'] } }); }\n"
        "catch (error) { blocked = true; }\n"
        f"if (blocked !== {str(exit_code != 0).lower()}) throw new Error('decision lost');\n"
        "await handler({ tool: 'unrelated', input: { command: 'pwd' } });\n"
        "if (calls !== 1) throw new Error('incorrect interception count');\n"
        "console.log('ok');\n",
        encoding="utf-8",
    )
    completed = subprocess.run([bun, str(runner)], capture_output=True, text=True, timeout=15, check=False)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "ok"


@pytest.mark.parametrize("mismatched_binding", [False, True])
@pytest.mark.parametrize("frozen_runtime", [False, True])
def test_refresh_companion_launcher_preserves_permissions_and_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatched_binding: bool,
    frozen_runtime: bool,
) -> None:
    from codex_plugin_scanner.guard.adapters.opencode_proxy_refresh import refresh_opencode_proxy_launchers

    ctx = _ctx(tmp_path)
    config = ctx.home_dir / ".config" / "opencode" / "opencode.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "mcp": {
                    "test": {
                        "type": "local",
                        "command": ["python3", "server.py"],
                        "enabled": True,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    OpenCodeHarnessAdapter().install(ctx)
    payload = json.loads(config.read_text(encoding="utf-8"))
    companion = payload["mcp"]["hol-guard::test"]
    proxy_index = companion["command"].index("opencode-mcp-proxy")
    companion["command"] = ["/removed/versions/3.12.0/hol-guard", *companion["command"][proxy_index:]]
    companion["enabled"] = False
    companion["environment"] = {"TEST_CONFIGURED_VALUE": "retained"}
    payload["permission"] = {"bash": "deny", "hol-guard::*": "ask"}
    if mismatched_binding:
        payload["mcp"]["test"]["command"] = ["python3", "changed-server.py"]
    config.write_text(json.dumps(payload), encoding="utf-8")
    before = json.loads(config.read_text(encoding="utf-8"))

    if frozen_runtime:
        from codex_plugin_scanner.guard.adapters import hook_python

        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(
            hook_python, "resolve_guard_hook_python", lambda _context: Path("/durable/current-hol-guard")
        )

    assert refresh_opencode_proxy_launchers(ctx) == (0 if mismatched_binding else 1)
    after = json.loads(config.read_text(encoding="utf-8"))
    if not mismatched_binding:
        refreshed = after["mcp"]["hol-guard::test"]["command"]
        assert refreshed[0] != "/removed/versions/3.12.0/hol-guard"
        if frozen_runtime:
            assert refreshed[:2] == ["/durable/current-hol-guard", "opencode-mcp-proxy"]
        else:
            assert refreshed[1:4] == ["-m", "codex_plugin_scanner.cli", "guard"]
        assert refreshed[refreshed.index("opencode-mcp-proxy") :] == before["mcp"]["hol-guard::test"]["command"][1:]
        after["mcp"]["hol-guard::test"]["command"] = before["mcp"]["hol-guard::test"]["command"]
    assert after == before
    assert refresh_opencode_proxy_launchers(ctx) == 0
