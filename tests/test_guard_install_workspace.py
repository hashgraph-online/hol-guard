"""Tests for default install/uninstall workspace resolution."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.commands import (
    _resolve_default_install_workspace,
    _resolve_guard_workspace,
)
from codex_plugin_scanner.guard.config import resolve_guard_home
from codex_plugin_scanner.guard.launcher import merge_guard_launcher_env
from codex_plugin_scanner.guard.store import GuardStore


def _install_args(*, harness: str = "cursor", workspace: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        workspace=workspace,
        guard_command="install",
        harness=harness,
        all=False,
    )


def test_resolve_default_install_workspace_prefers_cwd_markers_over_git_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monorepo = tmp_path / "monorepo"
    monorepo.mkdir()
    package = monorepo / "hol-guard"
    package.mkdir()
    (package / "pyproject.toml").write_text("[project]\nname='hol-guard'\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=monorepo, check=True, capture_output=True)
    monkeypatch.chdir(package)
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    guard_home = resolve_guard_home(None)
    resolved = _resolve_default_install_workspace(_install_args(), guard_home=guard_home)
    assert resolved == package.resolve()


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


def test_install_and_uninstall_omp_survive_unavailable_current_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()

    def unavailable_cwd() -> Path:
        raise FileNotFoundError("current directory was removed")

    monkeypatch.setattr(Path, "cwd", staticmethod(unavailable_cwd))

    install_rc = main(["guard", "install", "omp", "--home", str(home_dir), "--json"])
    install_capture = capsys.readouterr()
    assert install_rc == 0, install_capture.err
    install_output = json.loads(install_capture.out)
    uninstall_rc = main(["guard", "uninstall", "omp", "--home", str(home_dir), "--json"])
    uninstall_capture = capsys.readouterr()
    assert uninstall_rc == 0, uninstall_capture.err
    uninstall_output = json.loads(uninstall_capture.out)

    assert install_output["managed_install"]["harness"] == "omp"
    assert install_output["managed_install"]["workspace"] is None
    assert uninstall_output["managed_install"]["harness"] == "omp"
    assert uninstall_output["managed_install"]["workspace"] is None


def test_install_omp_preserves_legacy_pi_record(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    store = GuardStore(home_dir)
    store.set_managed_install("pi", True, None, {"legacy_combined": True}, "2026-08-05T00:00:00Z")

    rc = main(["guard", "install", "omp", "--home", str(home_dir), "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["managed_install"]["harness"] == "omp"
    assert store.get_managed_install("pi") == {
        "harness": "pi",
        "active": True,
        "workspace": None,
        "manifest": {"legacy_combined": True},
        "updated_at": "2026-08-05T00:00:00Z",
    }
    assert store.get_managed_install("omp") is not None


def test_update_migrates_verified_legacy_omp_extension_to_its_own_record(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
    store = GuardStore(guard_home)
    pi_extension_path = home_dir / ".pi" / "agent" / "extensions" / "hol-guard.ts"
    omp_settings_path = home_dir / ".omp" / "agent" / "settings.json"
    omp_extension_path = omp_settings_path.parent / "extensions" / "hol-guard.ts"
    omp_extension_path.parent.mkdir(parents=True)
    omp_extension_path.write_text(
        managed_extension_source(
            guard_home=guard_home,
            home_dir=home_dir,
            settings_path=omp_settings_path,
            harness="pi",
        ),
        encoding="utf-8",
    )
    omp_settings_path.parent.mkdir(parents=True, exist_ok=True)
    omp_settings_path.write_text(json.dumps({"extensions": [str(omp_extension_path)]}), encoding="utf-8")
    store.set_managed_install("pi", True, None, {"config_path": str(pi_extension_path)}, "2026-08-05T00:00:00Z")

    repaired, notes = update_commands._repair_supported_harnesses_in_process(
        context=context,
        store=store,
        workspace=None,
        now="2026-08-05T00:00:01Z",
        dry_run=False,
    )

    assert notes == []
    assert {item["harness"] for item in repaired} == {"pi", "omp"}
    omp_install = store.get_managed_install("omp")
    assert omp_install is not None and omp_install["active"] is True
    omp_source = omp_extension_path.read_text(encoding="utf-8")
    assert '"--harness", "omp"' in omp_source
    assert "Oh My Pi hook failed before completing review" in omp_source


def test_update_does_not_migrate_unverified_omp_extension(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
    store = GuardStore(guard_home)
    pi_extension_path = home_dir / ".pi" / "agent" / "extensions" / "hol-guard.ts"
    omp_settings_path = home_dir / ".omp" / "agent" / "settings.json"
    omp_extension_path = omp_settings_path.parent / "extensions" / "hol-guard.ts"
    omp_extension_path.parent.mkdir(parents=True)
    omp_extension_path.write_text("export default 'user-managed';\n", encoding="utf-8")
    omp_settings_path.parent.mkdir(parents=True, exist_ok=True)
    omp_settings_path.write_text(json.dumps({"extensions": [str(omp_extension_path)]}), encoding="utf-8")
    store.set_managed_install("pi", True, None, {"config_path": str(pi_extension_path)}, "2026-08-05T00:00:00Z")

    update_commands._repair_supported_harnesses_in_process(
        context=context,
        store=store,
        workspace=None,
        now="2026-08-05T00:00:01Z",
        dry_run=False,
    )

    assert store.get_managed_install("omp") is None
    assert omp_extension_path.read_text(encoding="utf-8") == "export default 'user-managed';\n"


def test_launcher_drops_relative_pythonpath_when_current_directory_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    absolute_entry = tmp_path / "trusted"
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(("relative-package", str(absolute_entry))))

    def unavailable_cwd() -> Path:
        raise FileNotFoundError("current directory was removed")

    monkeypatch.setattr(Path, "cwd", staticmethod(unavailable_cwd))

    assert merge_guard_launcher_env() == {"PYTHONPATH": str(absolute_entry)}


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


def test_install_cursor_writes_global_hooks_not_project_hooks(
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
    hooks_path = home_dir / ".cursor" / "hooks.json"
    assert hooks_path.is_file()
    assert not (repo / ".cursor" / "hooks.json").exists()
    managed_install = output["managed_install"]
    assert managed_install["harness"] == "cursor"
    assert Path(str(managed_install["workspace"])).resolve() == repo.resolve()
    editor_manifest = managed_install["manifest"]["editor"]
    assert Path(str(editor_manifest["managed_hooks_path"])).resolve() == hooks_path.resolve()


def test_resolve_default_install_workspace_ignores_global_cursor_dir_in_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """~/.cursor is global Cursor state, not proof that $HOME is a project root."""

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".cursor").mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.chdir(fake_home)
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    guard_home = resolve_guard_home(None)
    resolved = _resolve_default_install_workspace(_install_args(), guard_home=guard_home)
    assert resolved is None


def test_resolve_default_install_workspace_ignores_cursor_dir_without_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "not-a-repo"
    project.mkdir()
    (project / ".cursor").mkdir()
    monkeypatch.chdir(project)
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    guard_home = resolve_guard_home(None)
    resolved = _resolve_default_install_workspace(_install_args(), guard_home=guard_home)
    assert resolved is None


def test_install_cursor_hook_script_allows_benign_shell_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
    assert rc == 0
    hook_script = home_dir / ".cursor" / "hooks" / "hol-guard-cursor-hook.py"
    assert hook_script.is_file()
    payload = json.dumps({"hook_event_name": "beforeShellExecution", "command": "echo guard-e2e"})
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(hook_script)],
        input=payload,
        text=True,
        capture_output=True,
        cwd=repo,
        env=env,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    response = json.loads(completed.stdout)
    assert response.get("permission") == "allow"
