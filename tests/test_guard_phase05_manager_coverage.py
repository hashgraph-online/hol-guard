"""Phase 05 package-manager shim lifecycle and detection proofs."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.daemon.server import _build_snapshot_payload
from codex_plugin_scanner.guard.shims import (
    install_package_shims,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
    uninstall_package_shims,
)
from tests.shim_execution_helpers import write_fake_manager_script

PHASE05_MANAGERS = package_shim_supported_managers()


def _harness_context(tmp_path: Path) -> MagicMock:
    home_dir = tmp_path / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True, exist_ok=True)
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = MagicMock()
    context.home_dir = home_dir
    context.workspace_dir = workspace_dir
    context.guard_home = guard_home
    return context


@pytest.mark.parametrize("manager", PHASE05_MANAGERS)
def test_package_shim_lifecycle_install_status_remove(manager: str, tmp_path: Path) -> None:
    context = _harness_context(tmp_path)
    install_payload = install_package_shims(context, managers=(manager,))
    assert manager in install_payload["installed_managers"]

    status = package_shim_status(context)
    assert manager in status["installed_managers"]
    assert manager in status["active_managers"]
    detail = next(item for item in status["manager_details"] if item["manager"] == manager)
    assert detail["integrity"] == "ok"
    assert detail["shim_path"]

    remove_payload = uninstall_package_shims(context, managers=(manager,))
    assert manager in remove_payload["removed_managers"]
    assert manager not in package_shim_status(context)["installed_managers"]


@pytest.mark.parametrize("manager", ["npm", "pip", "npx", "pnpm", "uv"])
def test_package_shim_probe_records_last_test_timestamp(
    manager: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _harness_context(tmp_path)
    install_package_shims(context, managers=(manager,))
    shim_dir = context.guard_home / "package-shims" / "bin"
    command = manager
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True)
    write_fake_manager_script(
        fake_bin=fake_bin,
        manager=command,
        marker_path=tmp_path / f"{manager}-probe-marker.json",
        exit_code=0,
    )
    monkeypatch.setenv("PATH", os.pathsep.join([str(shim_dir), str(fake_bin)]))

    result = probe_package_shim_intercepts(context, managers=(manager,), workspace_dir=context.workspace_dir)
    status = package_shim_status(context)
    detail = next(item for item in status["manager_details"] if item["manager"] == manager)

    assert result["intercept_proved"] is True
    assert isinstance(detail["last_test_at"], str)
    assert detail["last_test_at"] == status["last_test_at"][manager]


def test_package_shim_status_marks_undetected_managers_honestly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _harness_context(tmp_path)
    install_package_shims(context, managers=("npm", "pip"))

    def fake_which(command: str, path: str | None = None) -> str | None:
        if command in {"npm", "pip"}:
            return f"/usr/local/bin/{command}"
        return None

    monkeypatch.setattr("codex_plugin_scanner.guard.shims.shutil.which", fake_which)

    status = package_shim_status(context)

    assert status["detected_managers"] == ["npm", "pip"]
    assert "cargo" in status["undetected_managers"]
    npm_detail = next(item for item in status["manager_details"] if item["manager"] == "npm")
    pip_detail = next(item for item in status["manager_details"] if item["manager"] == "pip")
    assert npm_detail["system_binary_detected"] is True
    assert pip_detail["system_binary_detected"] is True


def test_daemon_snapshot_includes_detected_manager_subset(tmp_path: Path) -> None:
    context = _harness_context(tmp_path)
    install_package_shims(context, managers=("npm",))
    snapshot = _build_snapshot_payload(context)

    coverage = snapshot["package_manager_coverage"]
    assert "detected_managers" in coverage
    assert "undetected_managers" in coverage
    assert isinstance(coverage["detected_managers"], list)
    assert isinstance(coverage["undetected_managers"], list)


def test_npx_shim_installs_alongside_npm(tmp_path: Path) -> None:
    context = _harness_context(tmp_path)
    install_package_shims(context, managers=("npm", "npx"))
    shim_dir = context.guard_home / "package-shims" / "bin"
    assert (shim_dir / "npm").exists()
    assert (shim_dir / "npx").exists()
    manifest = json.loads((context.guard_home / "package-shims" / "manifest.json").read_text(encoding="utf-8"))
    assert "npx" in manifest["installed_managers"]
