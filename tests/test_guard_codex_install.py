from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from codex_plugin_scanner.cli import main


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python3"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
env = { API_BASE = "https://hol.org", FEATURE_FLAG = "1" }
""".strip()
        + "\n",
    )


def test_guard_install_codex_rewrites_workspace_config_with_proxy_entries(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    managed_install = output["managed_install"]
    manifest = managed_install["manifest"]
    config_text = (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")

    assert rc == 0
    assert managed_install["active"] is True
    assert manifest["mode"] == "codex-mcp-proxy"
    assert manifest["managed_config_path"] == str(workspace_dir / ".codex" / "config.toml")
    assert set(manifest["managed_servers"]) == {"global_tools", "workspace_skill"}
    assert "--server-name" in config_text
    assert "guard" in config_text
    assert "codex-mcp-proxy" in config_text
    assert 'approval_policy = "never"' in config_text
    assert 'API_BASE = "https://hol.org"' in config_text
    assert 'FEATURE_FLAG = "1"' in config_text


def test_guard_uninstall_codex_restores_original_workspace_config(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    original_text = (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")

    install_rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    uninstall_output = json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert uninstall_rc == 0
    assert uninstall_output["managed_install"]["active"] is False
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_text


def test_guard_install_codex_encodes_dash_prefixed_server_args_safely(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.flagged_tool]
command = "python3"
args = ["server.py", "--marker-path", "marker.json"]
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    config_text = (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")

    assert rc == 0
    assert "--arg=--marker-path" in config_text


def test_guard_reinstall_codex_preserves_original_backup(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    original_text = (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")

    first_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    second_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    backup_path = Path(first_output["managed_install"]["manifest"]["backup_path"])

    assert first_install == 0
    assert second_install == 0
    assert uninstall_rc == 0
    assert backup_path.exists() is False
    assert (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8") == original_text


def test_guard_install_codex_preserves_inline_tables_inside_arrays(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"
profiles = [{ name = "default", mode = "safe" }, { name = "strict", mode = "review" }]

[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)

    assert rc == 0
    assert payload["profiles"] == [
        {"name": "default", "mode": "safe"},
        {"name": "strict", "mode": "review"},
    ]


def test_guard_reinstall_codex_refreshes_backup_after_completed_uninstall(tmp_path, capsys):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    first_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    uninstall_rc = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[mcp_servers.workspace_skill]
command = "node"
args = ["edited-workspace-skill.js"]
""".strip()
        + "\n",
    )

    second_install = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)
    second_uninstall = main(
        [
            "guard",
            "uninstall",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)
    backup_path = Path(first_output["managed_install"]["manifest"]["backup_path"])

    assert first_install == 0
    assert uninstall_rc == 0
    assert second_install == 0
    assert second_uninstall == 0
    assert backup_path == Path(second_output["managed_install"]["manifest"]["backup_path"])
    assert backup_path.exists() is False
    assert "edited-workspace-skill.js" in (workspace_dir / ".codex" / "config.toml").read_text(encoding="utf-8")


def test_guard_install_codex_proxy_entry_boots_outside_dev_shell_when_pythonpath_is_required(
    tmp_path, capsys, monkeypatch
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    marker_path = tmp_path / "marker.json"
    canary_path = Path(__file__).resolve().parent / "fixtures" / "mcp-canary-server.py"
    source_root = Path(__file__).resolve().parents[1] / "src"
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("PYTHONPATH", "src")
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        f"""
[mcp_servers.danger_lab]
command = "python3"
args = [{str(canary_path)!r}, "--marker-path", {str(marker_path)!r}]
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    proxy_entry = payload["mcp_servers"]["danger_lab"]
    proxy_env = dict(proxy_entry.get("env", {}))
    result = subprocess.run(
        [proxy_entry["command"], *proxy_entry["args"]],
        input='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}\n',
        text=True,
        capture_output=True,
        cwd=workspace_dir,
        env={
            "PATH": os.environ["PATH"],
            "HOME": str(home_dir),
            **proxy_env,
        },
        check=False,
    )

    assert rc == 0
    assert proxy_env["PYTHONPATH"] == str(source_root)
    assert result.returncode == 0
    assert json.loads(result.stdout)["result"]["serverInfo"]["name"] == "danger-lab"


def test_guard_install_codex_preserves_server_relative_pythonpath_entries(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    source_root = Path(__file__).resolve().parents[1] / "src"
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("PYTHONPATH", "src")
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.danger_lab]
command = "python3"
args = ["danger-lab.py"]
env = { PYTHONPATH = "app/src", API_BASE = "https://hol.org" }
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    proxy_env = payload["mcp_servers"]["danger_lab"]["env"]

    assert rc == 0
    assert proxy_env["PYTHONPATH"] == os.pathsep.join((str(source_root), "app/src"))


def test_guard_install_codex_allows_server_to_clear_launcher_pythonpath(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("PYTHONPATH", "src")
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.danger_lab]
command = "python3"
args = ["danger-lab.py"]
env = { PYTHONPATH = "" }
""".strip()
        + "\n",
    )

    rc = main(
        [
            "guard",
            "install",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    json.loads(capsys.readouterr().out)

    with (workspace_dir / ".codex" / "config.toml").open("rb") as handle:
        payload = tomllib.load(handle)
    proxy_env = payload["mcp_servers"]["danger_lab"]["env"]

    assert rc == 0
    assert proxy_env["PYTHONPATH"] == ""
