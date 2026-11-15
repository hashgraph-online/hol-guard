"""Codex uninstall undoes the install and keeps what the user changed after it."""

from __future__ import annotations

import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.codex_config import dump_toml

_GLOBAL_TOOLS = {"command": "python3", "args": ["-m", "http.server", "9000"]}


def _guard(capsys, *args: str) -> dict[str, object]:
    rc = main(["guard", *args, "--json"])
    output = json.loads(capsys.readouterr().out)
    assert rc == 0
    return output


def test_guard_uninstall_codex_keeps_settings_added_after_install(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    config_path = home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(dump_toml({"mcp_servers": {"global_tools": _GLOBAL_TOOLS}}), encoding="utf-8")

    _guard(capsys, "install", "codex", "--home", str(home_dir), "--workspace", str(workspace_dir))
    installed_bytes = config_path.read_bytes()
    installed = tomllib.loads(installed_bytes.decode("utf-8"))
    assert installed["mcp_servers"]["global_tools"] != _GLOBAL_TOOLS
    installed["model"] = "o3"
    installed["mcp_servers"]["added_later"] = {"command": "uvx", "args": ["added-later"]}
    installed["profiles"] = {"work": {"model": "o4-mini"}}
    config_path.write_text(dump_toml(installed, original=installed_bytes), encoding="utf-8")

    _guard(capsys, "uninstall", "codex", "--home", str(home_dir), "--workspace", str(workspace_dir))

    restored = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert restored == {
        "mcp_servers": {
            "global_tools": _GLOBAL_TOOLS,
            "added_later": {"command": "uvx", "args": ["added-later"]},
        },
        "model": "o3",
        "profiles": {"work": {"model": "o4-mini"}},
    }


def test_guard_uninstall_codex_deletes_a_config_install_created(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    home_dir.mkdir()

    _guard(capsys, "install", "codex", "--home", str(home_dir), "--workspace", str(workspace_dir))
    _guard(capsys, "uninstall", "codex", "--home", str(home_dir), "--workspace", str(workspace_dir))

    assert not (home_dir / ".codex" / "config.toml").exists()
