"""Regression coverage for persistent package-shim runtime ownership."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.shims import install_package_shims, package_shim_status


def test_guard_package_shims_status_is_stable_across_home_override_contexts(tmp_path: Path) -> None:
    home_dir = Path.home()
    guard_home = tmp_path / "guard-home"
    install_package_shims(
        HarnessContext(
            home_dir=home_dir,
            workspace_dir=None,
            guard_home=guard_home,
            home_override_explicit=True,
        ),
        managers=("npm",),
    )

    status = package_shim_status(
        HarnessContext(
            home_dir=home_dir,
            workspace_dir=None,
            guard_home=guard_home,
            home_override_explicit=False,
        ),
    )

    assert status["manager_details"][0]["integrity"] == "ok"


def test_package_shim_does_not_freeze_installer_pythonpath(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    installer_pythonpath = tmp_path / "installer-only-imports"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
    monkeypatch.setenv("PYTHONPATH", str(installer_pythonpath))

    install_package_shims(context, managers=("npm",))

    shim_dir = guard_home / "package-shims" / "bin"
    wrapper = (shim_dir / "npm").read_text(encoding="utf-8")
    sidecar = shim_dir / ".npm.py"
    generated = sidecar.read_text(encoding="utf-8") if sidecar.is_file() else wrapper
    assert str(installer_pythonpath) not in generated
