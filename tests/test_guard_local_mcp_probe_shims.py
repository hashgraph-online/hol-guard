from __future__ import annotations

import os
from pathlib import Path

from codex_plugin_scanner.guard.runtime.local_mcp_probe import probe_stdio_mcp_server
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import (
    is_package_shim_executable,
    probe_env,
    probe_search_path,
)

_FAKE_NPX_MCP = """#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "real"}},
        }), flush=True)
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [{"name": "list_pages", "description": "List"}]},
        }), flush=True)
        break
"""


def _shim_first_npx_path(tmp_path: Path, monkeypatch) -> Path:
    shim_dir = tmp_path / "package-shims" / "bin"
    real_dir = tmp_path / "real"
    shim_dir.mkdir(parents=True)
    real_dir.mkdir()
    shim = shim_dir / "npx"
    shim.write_text("#!/bin/sh\nsleep 20\nexit 1\n", encoding="utf-8")
    shim.chmod(0o755)
    real = real_dir / "npx"
    real.write_text(_FAKE_NPX_MCP, encoding="utf-8")
    real.chmod(0o755)
    monkeypatch.setenv(
        "PATH",
        os.pathsep.join((str(shim_dir), str(real_dir), "/usr/bin", "/bin")),
    )
    return shim


def test_probe_search_path_omits_package_shim_dirs(tmp_path: Path, monkeypatch) -> None:
    shim = tmp_path / "package-shims" / "bin"
    real = tmp_path / "real"
    shim.mkdir(parents=True)
    real.mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join((str(shim), str(real))))
    path_entries = probe_search_path().split(os.pathsep)
    assert str(shim) not in path_entries
    assert str(real) in path_entries
    env = probe_env(str(tmp_path / "tmp"))
    assert str(shim) not in env["PATH"].split(os.pathsep)


def test_probe_search_path_does_not_restore_shim_only_path(tmp_path: Path, monkeypatch) -> None:
    shim = tmp_path / "package-shims" / "bin"
    shim.mkdir(parents=True)
    monkeypatch.setenv("PATH", str(shim))
    path_entries = [entry for entry in probe_search_path().split(os.pathsep) if entry]
    assert str(shim) not in path_entries


def test_probe_skips_package_shim_npx(tmp_path: Path, monkeypatch) -> None:
    _shim_first_npx_path(tmp_path, monkeypatch)
    probed = probe_stdio_mcp_server(
        "npx -y chrome-devtools-mcp@latest",
        cwd=tmp_path,
        home_dir=tmp_path,
        timeout=3.0,
    )
    assert probed is not None
    assert probed.status == "ok"
    assert "package-shims" not in probed.argv[0]
    assert any(tool.name == "list_pages" for tool in probed.tools)


def test_probe_skips_absolute_package_shim_npx(tmp_path: Path, monkeypatch) -> None:
    shim = _shim_first_npx_path(tmp_path, monkeypatch)
    assert is_package_shim_executable(str(shim))
    probed = probe_stdio_mcp_server(
        f"{shim} -y chrome-devtools-mcp@latest",
        cwd=tmp_path,
        home_dir=tmp_path,
        timeout=3.0,
    )
    assert probed is not None
    assert "package-shims" not in probed.argv[0]
    assert any(tool.name == "list_pages" for tool in probed.tools)


def test_probe_preserves_relative_executable_path(tmp_path: Path, monkeypatch) -> None:
    nested = tmp_path / "servers"
    nested.mkdir()
    server = nested / "mcp"
    server.write_text(_FAKE_NPX_MCP, encoding="utf-8")
    server.chmod(0o755)
    thief_dir = tmp_path / "bin"
    thief_dir.mkdir()
    thief = thief_dir / "mcp"
    thief.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    thief.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join((str(thief_dir), "/usr/bin", "/bin")))
    probed = probe_stdio_mcp_server("./servers/mcp", cwd=tmp_path, home_dir=tmp_path, timeout=3.0)
    assert probed is not None
    assert "servers" in probed.argv[0]
    assert any(tool.name == "list_pages" for tool in probed.tools)


def test_probe_returns_none_when_shim_has_no_real_launcher(tmp_path: Path, monkeypatch) -> None:
    shim_dir = tmp_path / "package-shims" / "bin"
    shim_dir.mkdir(parents=True)
    shim = shim_dir / "npx"
    shim.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.local_mcp_probe.probe_search_path",
        lambda: str(tmp_path / "empty"),
    )
    probed = probe_stdio_mcp_server(
        f"{shim} -y chrome-devtools-mcp@latest",
        cwd=tmp_path,
        home_dir=tmp_path,
        timeout=1.0,
    )
    assert probed is None
