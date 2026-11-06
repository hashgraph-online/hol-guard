"""Regression coverage for persistent package-shim runtime ownership."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import shims as guard_shims_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.shims import install_guard_shim, install_package_shims, package_shim_status


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


def test_harness_shim_does_not_persist_appimage_mount_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    workspace_dir = tmp_path / "workspace"
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
    appimage_runtime = "/tmp/.mount_HOLGUARD/usr/lib/hol-guard-core/hol-guard"
    monkeypatch.setattr(guard_shims_module.sys, "executable", appimage_runtime)

    payload = install_guard_shim("pi", context, launcher_name="omp", display_name="Oh My Pi")

    shim = Path(str(payload["shim_path"]))
    persisted = "\n".join(path.read_text(encoding="utf-8") for path in (shim, Path(str(payload["windows_shim_path"]))))
    assert ".mount_" not in persisted
    assert "guard_cli=''" in persisted
    assert "# base_command = ['hol-guard'," in persisted
    assert "command -v hol-guard" not in persisted
    assert "--arg=$arg" in persisted
    assert "pipx install --force hol-guard" in persisted


def test_appimage_harness_shim_executes_durable_official_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    workspace_dir = tmp_path / "workspace"
    capture_path = tmp_path / "args.txt"
    official_cli = home_dir / ".local" / "bin" / "hol-guard"
    official_cli.parent.mkdir(parents=True)
    official_cli.write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {str(capture_path)!r}\n",
        encoding="utf-8",
    )
    official_cli.chmod(0o755)
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
    monkeypatch.setattr(
        guard_shims_module.sys,
        "executable",
        "/tmp/.mount_HOLGUARD/usr/lib/hol-guard-core/hol-guard",
    )
    monkeypatch.setattr(
        guard_shims_module,
        "_is_transient_path",
        lambda path: ".mount_" in str(path),
    )
    payload = install_guard_shim("pi", context, launcher_name="omp", display_name="Oh My Pi")

    subprocess.run(
        [str(payload["shim_path"]), "hello world", "--flag=value"],
        check=True,
        text=True,
        capture_output=True,
    )

    assert capture_path.read_text(encoding="utf-8").splitlines() == [
        "run",
        "pi",
        "--guard-home",
        str(guard_home),
        "--home",
        str(home_dir),
        "--workspace",
        str(workspace_dir),
        "--arg=hello world",
        "--arg=--flag=value",
    ]


def test_appimage_harness_shim_rejects_transient_official_cli_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    transient_cli = tmp_path / "tmp" / ".mount_HOLGUARD" / "hol-guard"
    transient_cli.parent.mkdir(parents=True)
    transient_cli.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    transient_cli.chmod(0o755)
    official_cli = home_dir / ".local" / "bin" / "hol-guard"
    official_cli.parent.mkdir(parents=True)
    official_cli.symlink_to(transient_cli)
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
    monkeypatch.setattr(
        guard_shims_module.sys,
        "executable",
        "/tmp/.mount_HOLGUARD/usr/lib/hol-guard-core/hol-guard",
    )
    monkeypatch.setattr(
        guard_shims_module,
        "_is_transient_path",
        lambda path: ".mount_" in str(path),
    )
    payload = install_guard_shim("pi", context, launcher_name="omp", display_name="Oh My Pi")

    result = subprocess.run(
        [str(payload["shim_path"])],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 127
    assert "pipx install --force hol-guard" in result.stderr
