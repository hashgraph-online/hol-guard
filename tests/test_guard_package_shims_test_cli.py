"""CLI tests for `package-shims test` intercept proofs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands as cli_commands
from codex_plugin_scanner.guard.shims import install_package_shims
from tests.test_guard_package_shims_cli import _seed_paid_oauth_entitlement


def test_package_shims_test_probes_with_the_calling_shell_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    guard_home = tmp_path / "guard-home"
    _seed_paid_oauth_entitlement(guard_home)
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
    install_package_shims(context, managers=("npm",))
    shim_dir = guard_home / "package-shims" / "bin"

    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    rc = main(["guard", "package-shims", "test", "--manager", "npm", "--home", str(guard_home), "--json"])
    inactive = json.loads(capsys.readouterr().out)

    monkeypatch.setenv("PATH", f"{shim_dir}:/usr/bin:/bin")
    active_rc = main(["guard", "package-shims", "test", "--manager", "npm", "--home", str(guard_home), "--json"])
    active = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert inactive["path_repair_required"] == ["npm"]
    assert inactive["manager_results"][0]["skipped_reason"] == "path_inactive"
    assert active_rc == 0
    assert active["path_repair_required"] == []
    assert active["manager_results"][0]["evaluator_invoked"] is True
    assert active["intercept_proved"] is True


def test_package_shims_test_runs_from_the_calling_project_without_workspace_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.chdir(project_dir)
    guard_home = tmp_path / "guard-home"
    _seed_paid_oauth_entitlement(guard_home)
    probed: dict[str, object] = {}

    def fake_probe(_context: object, *, managers: object, workspace_dir: Path | None) -> dict[str, object]:
        probed["workspace_dir"] = workspace_dir
        return {"intercept_proved": False, "manager_results": [], "path_repair_required": []}

    monkeypatch.setattr(cli_commands, "probe_package_shim_intercepts", fake_probe)
    rc = main(["guard", "package-shims", "test", "--manager", "npm", "--home", str(guard_home), "--json"])
    capsys.readouterr()

    assert rc == 0
    assert probed["workspace_dir"] == project_dir.resolve()
