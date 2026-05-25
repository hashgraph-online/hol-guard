"""Regression coverage for package-manager shim lifecycle commands."""

from __future__ import annotations

import json
import os
from pathlib import Path

from codex_plugin_scanner.cli import main


def test_guard_package_shims_install_status_uninstall_roundtrip(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)

    install_rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--manager",
            "pip",
            "--json",
        ]
    )
    install_payload = json.loads(capsys.readouterr().out)

    assert install_rc == 0
    assert install_payload["installed_count"] == 2
    assert install_payload["installed_managers"] == ["npm", "pip"]
    assert install_payload["installed_now"] == ["npm", "pip"]
    shim_dir = Path(str(install_payload["shim_dir"]))
    manifest_path = Path(str(install_payload["manifest_path"]))
    assert (shim_dir / "npm").exists()
    assert (shim_dir / "pip").exists()
    assert manifest_path.exists()

    status_rc = main(
        [
            "guard",
            "package-shims",
            "status",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    status_payload = json.loads(capsys.readouterr().out)

    assert status_rc == 0
    assert status_payload["installed_managers"] == ["npm", "pip"]
    assert status_payload["active_managers"] == ["npm", "pip"]
    assert status_payload["missing_managers"] == []

    uninstall_rc = main(
        [
            "guard",
            "package-shims",
            "uninstall",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
        ]
    )
    uninstall_payload = json.loads(capsys.readouterr().out)

    assert uninstall_rc == 0
    assert sorted(uninstall_payload["removed_managers"]) == ["npm", "pip"]
    assert uninstall_payload["remaining_managers"] == []
    assert manifest_path.exists() is False


def test_guard_package_shims_install_merges_manifest_entries(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)

    first_rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--json",
        ]
    )
    first_payload = json.loads(capsys.readouterr().out)
    second_rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "pip",
            "--json",
        ]
    )
    second_payload = json.loads(capsys.readouterr().out)

    assert first_rc == 0
    assert second_rc == 0
    assert first_payload["installed_managers"] == ["npm"]
    assert second_payload["installed_managers"] == ["npm", "pip"]
    assert second_payload["installed_now"] == ["pip"]


def test_guard_package_shims_install_does_not_mutate_path_environment(
    tmp_path: Path,
    capsys,
    monkeypatch,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    original_path = "/tmp/guard-a:/tmp/guard-b"
    monkeypatch.setenv("PATH", original_path)

    rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--json",
        ]
    )
    capsys.readouterr()

    assert rc == 0
    assert os.environ["PATH"] == original_path


def test_guard_package_shim_wrapper_routes_commands_through_guard_protect(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)

    rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--manager",
            "npm",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    shim_path = Path(str(payload["shim_dir"])) / "npm"
    shim_source = shim_path.read_text(encoding="utf-8")
    assert "guard" in shim_source
    assert "protect" in shim_source
    assert "'npm'" in shim_source
