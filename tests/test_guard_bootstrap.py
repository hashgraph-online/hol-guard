"""Behavior tests for Guard bootstrap onboarding."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.cli import main


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_guard_bootstrap_starts_daemon_and_installs_recommended_harness(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.bootstrap.ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4781",
    )

    rc = main(
        [
            "guard",
            "bootstrap",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["recommended_harness"] == "codex"
    assert output["approval_center_url"] == "http://127.0.0.1:4781"
    assert output["approval_center_reachable"] is True
    assert output["bootstrap_install"]["installed"] is True
    assert output["bootstrap_install"]["harness"] == "codex"
    assert output["shell_alias"]["snippet"] == "alias guardp='hol-guard protect'"
    assert output["next_steps"][0]["command"] == "hol-guard run codex --dry-run"


def test_guard_bootstrap_can_skip_install_and_write_shell_alias(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.bootstrap.ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4781",
    )

    rc = main(
        [
            "guard",
            "bootstrap",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--skip-install",
            "--alias-name",
            "guardwrap",
            "--write-shell-alias",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    alias_path = Path(output["shell_alias"]["path"])

    assert rc == 0
    assert output["bootstrap_install"]["installed"] is False
    assert output["bootstrap_install"]["reason"] == "skipped_by_flag"
    assert output["shell_alias"]["written"] is True
    assert alias_path.read_text(encoding="utf-8").strip() == "alias guardwrap='hol-guard protect'"


def test_guard_bootstrap_handles_missing_harnesses(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.bootstrap.ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4781",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.product.detect_all",
        lambda _context: [],
    )

    rc = main(
        [
            "guard",
            "bootstrap",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["recommended_harness"] is None
    assert output["bootstrap_install"]["reason"] == "no_harness_detected"
    assert output["next_steps"][0]["command"] == "hol-guard detect"


def test_guard_bootstrap_invalid_harness_returns_cli_error(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.bootstrap.ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4781",
    )

    rc = main(
        [
            "guard",
            "bootstrap",
            "not-a-real-harness",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
        ]
    )
    stderr = capsys.readouterr().err

    assert rc == 2
    assert "Unsupported harness" in stderr


def test_guard_bootstrap_installs_copilot_when_it_is_the_detected_harness(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    (home_dir / ".copilot").mkdir(parents=True, exist_ok=True)
    (workspace_dir / ".github" / "hooks").mkdir(parents=True, exist_ok=True)
    _write_text(
        home_dir / ".copilot" / "mcp-config.json",
        '{"servers":{"global-tool":{"command":"npx","args":["server.js"]}}}\n',
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.bootstrap.ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4781",
    )
    monkeypatch.setattr("shutil.which", lambda _command: None)

    rc = main(
        [
            "guard",
            "bootstrap",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["recommended_harness"] == "copilot"
    assert output["bootstrap_install"]["harness"] == "copilot"
    assert output["next_steps"][0]["command"] == "hol-guard run copilot --dry-run"


def test_guard_bootstrap_skip_install_still_rejects_invalid_harness(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.bootstrap.ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4781",
    )

    rc = main(
        [
            "guard",
            "bootstrap",
            "not-a-real-harness",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--skip-install",
        ]
    )
    stderr = capsys.readouterr().err

    assert rc == 2
    assert "Unsupported harness" in stderr


def test_hol_guard_hermes_bootstrap_alias_installs_hermes(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".hermes" / "config.yaml",
        'mcp_servers:\n  github:\n    command: "npx"\n    args: ["-y", "@modelcontextprotocol/server-github"]\n',
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.bootstrap.ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4781",
    )
    monkeypatch.setattr(sys, "argv", ["hol-guard"])

    rc = main(
        [
            "hermes",
            "bootstrap",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["recommended_harness"] == "hermes"
    assert output["bootstrap_install"]["harness"] == "hermes"
    assert output["next_steps"][0]["command"] == "hol-guard run hermes --dry-run"


def test_guard_bootstrap_repairs_managed_hermes_install_when_overlay_is_missing(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(
        home_dir / ".hermes" / "config.yaml",
        'mcp_servers:\n  github:\n    command: "npx"\n    args: ["-y", "@modelcontextprotocol/server-github"]\n',
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.bootstrap.ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4781",
    )

    first_rc = main(
        [
            "guard",
            "bootstrap",
            "hermes",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    first_output = json.loads(capsys.readouterr().out)
    overlay_path = Path(first_output["bootstrap_install"]["managed_install"]["manifest"]["mcp_overlay_path"])
    overlay_path.unlink()

    second_rc = main(
        [
            "guard",
            "bootstrap",
            "hermes",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    second_output = json.loads(capsys.readouterr().out)

    assert first_rc == 0
    assert second_rc == 0
    assert second_output["bootstrap_install"]["reason"] == "repaired_managed_install"
    assert overlay_path.exists() is True
