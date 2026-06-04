"""Tests for default install/uninstall workspace resolution."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.commands import (
    _resolve_default_install_workspace,
    _resolve_guard_workspace,
)
from codex_plugin_scanner.guard.config import resolve_guard_home


def _install_args(*, harness: str = "cursor", workspace: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        workspace=workspace,
        guard_command="install",
        harness=harness,
        all=False,
    )


def test_resolve_default_install_workspace_uses_git_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    nested = repo / "src" / "pkg"
    nested.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(nested)
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    guard_home = resolve_guard_home(None)
    resolved = _resolve_default_install_workspace(_install_args(), guard_home=guard_home)
    assert resolved == repo.resolve()


def test_resolve_default_install_workspace_uses_cursor_project_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "cursor-project"
    project.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(project))
    guard_home = resolve_guard_home(None)
    resolved = _resolve_default_install_workspace(_install_args(), guard_home=guard_home)
    assert resolved == project.resolve()


def test_resolve_guard_workspace_explicit_flag_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    other = tmp_path / "other"
    repo.mkdir()
    other.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(repo)
    guard_home = resolve_guard_home(None)
    args = _install_args(workspace=str(other))
    assert _resolve_guard_workspace(args, guard_home=guard_home) == other.resolve()


def test_install_cursor_without_workspace_writes_project_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    home_dir = tmp_path / "home"
    repo.mkdir()
    home_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(repo)
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)

    rc = main(
        [
            "guard",
            "install",
            "cursor",
            "--home",
            str(home_dir),
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    hooks_path = repo / ".cursor" / "hooks.json"
    assert hooks_path.is_file()
    managed_install = output["managed_install"]
    assert managed_install["harness"] == "cursor"
    assert Path(str(managed_install["workspace"])).resolve() == repo.resolve()
    editor_manifest = managed_install["manifest"]["editor"]
    assert Path(str(editor_manifest["managed_hooks_path"])).resolve() == hooks_path.resolve()
