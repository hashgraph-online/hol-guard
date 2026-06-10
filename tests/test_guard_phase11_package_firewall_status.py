"""Phase 11 package firewall status API field proofs."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.shims import (
    install_package_shims,
    package_shim_status,
    probe_package_shim_intercepts,
    record_package_shim_audit_result,
)
from tests.shim_execution_helpers import write_fake_manager_script


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


def test_package_shim_status_exposes_phase11_alias_fields(tmp_path: Path) -> None:
    context = _harness_context(tmp_path)
    install_package_shims(context, managers=("npm",))
    status_before = package_shim_status(context)
    assert status_before["lastAuditProofAt"] is None
    record_package_shim_audit_result(context, audited_at="2026-06-10T01:00:00+00:00")

    status = package_shim_status(context)

    assert status["detectedManagers"] == status["detected_managers"]
    assert status["protectedManagers"] == status["protected_managers"]
    assert status["installedManagers"] == status["installed_managers"]
    assert status["pathBrokenManagers"] == status["path_broken_managers"]
    assert status["lastAuditProofAt"] == "2026-06-10T01:00:00+00:00"
    assert status["last_audit_proof_at"] == "2026-06-10T01:00:00+00:00"
    assert isinstance(status["lastInterceptProofAt"], dict)
    assert status["lastInterceptProofAt"] == status["last_intercept_proof_at"] == status["last_test_at"]


def test_package_shim_status_lists_tested_managers_after_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _harness_context(tmp_path)
    install_package_shims(context, managers=("npm",))
    shim_dir = context.guard_home / "package-shims" / "bin"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True)
    write_fake_manager_script(
        fake_bin=fake_bin,
        manager="npm",
        marker_path=tmp_path / "npm-probe-marker.json",
        exit_code=0,
    )
    monkeypatch.setenv("PATH", os.pathsep.join([str(shim_dir), str(fake_bin)]))

    probe_package_shim_intercepts(context, managers=("npm",), workspace_dir=context.workspace_dir)
    status = package_shim_status(context)

    assert "npm" in status["testedManagers"]
    assert status["lastInterceptProofAt"]["npm"] == status["last_test_at"]["npm"]


def test_package_shim_status_lists_path_broken_managers_from_bypasses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _harness_context(tmp_path)
    install_package_shims(context, managers=("npm",))
    shim_dir = context.guard_home / "package-shims" / "bin"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True)
    write_fake_manager_script(
        fake_bin=fake_bin,
        manager="npm",
        marker_path=tmp_path / "npm-path-marker.json",
        exit_code=0,
    )
    monkeypatch.setenv("PATH", os.pathsep.join([str(fake_bin), str(shim_dir)]))

    status = package_shim_status(context)

    assert "npm" in status["pathBrokenManagers"]
    assert status["path_broken_managers"] == status["pathBrokenManagers"]
