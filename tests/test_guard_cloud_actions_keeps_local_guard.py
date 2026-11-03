"""Cloud actions setup leaves Guard's own local protection alone.

An AI tool that already runs Guard locally keeps it: Codex keeps its hooks
feature and Guard's hook command, and Cursor keeps the `hol-guard::` server
that routes its tools through Guard. The preview writes nothing, applying adds
only the Cloud actions entry, and restoring returns the exact earlier bytes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli.cloud_actions_host_apply import backups_dir
from codex_plugin_scanner.guard.cli.cloud_actions_host_config import CLOUD_ACTIONS_SERVER_NAME
from codex_plugin_scanner.guard.codex_hook_sources import parse_toml_object

WS = "11111111-1111-4111-8111-111111111111"

CODEX_WITH_GUARD = """[features]
codex_hooks = true

[[hooks.PreToolUse]]
matcher = "*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "hol-guard hook --harness codex"

[mcp_servers.docs]
command = "hol-guard"
args = ["mcp-proxy", "--server", "docs", "--", "docs-mcp", "--stdio"]
"""

CURSOR_WITH_GUARD: dict[str, Any] = {
    "mcpServers": {
        "hol-guard::docs": {
            "command": "hol-guard",
            "args": ["mcp-proxy", "--server", "docs", "--", "docs-mcp", "--stdio"],
        },
    },
}

SEEDS = {
    "codex": (".codex/config.toml", CODEX_WITH_GUARD),
    "cursor": (".cursor/mcp.json", json.dumps(CURSOR_WITH_GUARD, indent=2) + "\n"),
}


def _seed(home: Path, tool: str) -> Path:
    relative, text = SEEDS[tool]
    path = home / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _run(capsys: pytest.CaptureFixture[str], home: Path, guard_home: Path, *argv: str) -> tuple[int, dict[str, Any]]:
    try:
        code = cli.main(["cloud-actions", *argv, "--home", str(home), "--guard-home", str(guard_home), "--json"])
    except SystemExit as exit_:
        code = int(exit_.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _guard_parts(tool: str, path: Path) -> dict[str, Any]:
    if tool == "codex":
        payload: dict[str, Any] = parse_toml_object(path.read_bytes(), path=path, label="Codex config file")
        servers = {name: value for name, value in payload["mcp_servers"].items() if name != CLOUD_ACTIONS_SERVER_NAME}
        return {"features": payload["features"], "hooks": payload["hooks"], "mcp_servers": servers}
    servers = json.loads(path.read_bytes())["mcpServers"]
    return {name: value for name, value in servers.items() if name != CLOUD_ACTIONS_SERVER_NAME}


@pytest.mark.parametrize("tool", sorted(SEEDS))
def test_preview_apply_and_restore_keep_guards_local_setup(
    tool: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home, guard_home = tmp_path / "home", tmp_path / "guard"
    path = _seed(home, tool)
    before = path.read_bytes()
    guard_parts = _guard_parts(tool, path)
    stamp = path.stat().st_mtime_ns

    code, preview = _run(capsys, home, guard_home, "ai-tools", "configure", tool, "--cloud-workspace", WS, "--dry-run")

    assert code == 0
    assert preview["state"] == "preview"
    assert preview["written"] is False
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == stamp
    assert not backups_dir(guard_home, tool).exists()

    code, applied = _run(capsys, home, guard_home, "ai-tools", "configure", tool, "--cloud-workspace", WS, "--apply")

    assert code == 0
    assert applied["state"] == "applied"
    assert _guard_parts(tool, path) == guard_parts
    if tool == "codex":
        # The new entry is added after the existing text, which stays byte for byte.
        assert path.read_bytes().startswith(before)

    code, restored = _run(capsys, home, guard_home, "ai-tools", "restore", tool)

    assert code == 0
    assert restored["state"] == "restored"
    assert path.read_bytes() == before
