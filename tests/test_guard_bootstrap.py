"""Behavior tests for Guard bootstrap onboarding."""

from __future__ import annotations

import json
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
