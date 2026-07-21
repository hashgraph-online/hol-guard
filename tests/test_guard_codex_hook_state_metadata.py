"""Regression coverage for Codex-owned TOML hook-state metadata."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import tomllib

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.codex_config import dump_toml
from codex_plugin_scanner.guard.codex_hook_inventory import (
    CODEX_HOOK_INVENTORY_UNSUPPORTED_EVENT,
    enumerate_codex_hooks,
)


def _install_args(home_dir: Path, workspace_dir: Path) -> list[str]:
    return [
        "guard",
        "install",
        "codex",
        "--home",
        str(home_dir),
        "--workspace",
        str(workspace_dir),
        "--json",
    ]


def test_guard_install_codex_preserves_codex_hook_state_metadata(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    state = {
        "fixture:pre_tool_use:0:0": {
            "trusted_hash": f"sha256:{'a' * 64}",
        }
    }
    config_path = home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(dump_toml({"hooks": {"state": state}}), encoding="utf-8")

    rc = main(_install_args(home_dir, workspace_dir))
    output = json.loads(capsys.readouterr().out)
    installed = tomllib.loads(config_path.read_text(encoding="utf-8"))

    assert rc == 0
    assert output["managed_install"]["active"] is True
    assert installed["hooks"]["state"] == state
    assert isinstance(installed["hooks"]["PreToolUse"], list)


def test_uppercase_codex_hook_state_hash_is_recognized(tmp_path: Path) -> None:
    inventory = enumerate_codex_hooks(
        {"hooks": {"state": {"fixture": {"trusted_hash": f"sha256:{'A' * 64}"}}}},
        source_path=tmp_path / "config.toml",
        source_scope="global",
        source_format="toml",
        source_hooks_enabled=False,
    )

    assert inventory.complete is True


@pytest.mark.parametrize(
    "state",
    (
        "not-a-metadata-table",
        {"fixture": {"trusted_hash": "not-a-sha256-hash"}},
    ),
)
def test_malformed_codex_hook_state_metadata_remains_fail_closed(tmp_path: Path, state: object) -> None:
    inventory = enumerate_codex_hooks(
        {"hooks": {"state": state}},
        source_path=tmp_path / "config.toml",
        source_scope="global",
        source_format="toml",
        source_hooks_enabled=False,
    )

    assert inventory.complete is False
    assert inventory.issues[0].reason_code == CODEX_HOOK_INVENTORY_UNSUPPORTED_EVENT
