"""Regression coverage for pipx updater recovery."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_subprocess as update_subprocess_module
from codex_plugin_scanner.guard.cli.update_subprocess import (
    _TRUSTED_MODULE_BOOTSTRAP,
    FilesystemIdentity,
    UpdateSubprocessError,
)
from codex_plugin_scanner.guard.shims import _trusted_python_flags


def _pipx_style_venv(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    pipx_home = tmp_path / "pipx"
    venv_dir = pipx_home / "venvs" / "hol-guard"
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(venv_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    site_packages = Path(
        subprocess.check_output(
            [python, "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            text=True,
        ).strip()
    )
    shared_packages = pipx_home / "shared" / "lib" / "guard-test" / "site-packages"
    shared_packages.mkdir(parents=True)
    (site_packages / "pipx_shared.pth").write_text(f"{shared_packages}\n", encoding="utf-8")
    return python, site_packages, shared_packages, pipx_home


def _resolve_shared_identity(
    site_packages: Path,
    pipx_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> FilesystemIdentity | None:
    monkeypatch.setattr(
        update_subprocess_module,
        "_manager_home_from_prefix",
        lambda _installer_kind: (pipx_home, pipx_home.parent / "bin"),
    )
    return update_subprocess_module._trusted_pipx_shared_import_identity((site_packages,))


def _run_trusted_module(
    python: Path,
    site_packages: Path,
    extra_import_paths: tuple[Path, ...],
    module: str,
    *args: str,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONSAFEPATH"] = "1"
    return subprocess.run(
        [
            str(python),
            *_trusted_python_flags(),
            "-S",
            "-c",
            _TRUSTED_MODULE_BOOTSTRAP,
            json.dumps([str(site_packages)], separators=(",", ":")),
            json.dumps([str(path) for path in extra_import_paths], separators=(",", ":")),
            module,
            *args,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_trusted_pip_bootstrap_uses_validated_pipx_shared_path_without_site_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    python, site_packages, shared_packages, pipx_home = _pipx_style_venv(tmp_path)
    pip_package = shared_packages / "pip"
    pip_package.mkdir()
    (pip_package / "__init__.py").write_text("", encoding="utf-8")
    (pip_package / "__main__.py").write_text(
        "import json, sys\nprint(json.dumps({'marker': 'pipx-shared-pip', 'argv': sys.argv[1:]}))\n",
        encoding="utf-8",
    )
    hook_marker = tmp_path / "pth-hook-ran"
    (site_packages / "hostile.pth").write_text(
        f"import pathlib; pathlib.Path({str(hook_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )

    shared_identity = _resolve_shared_identity(site_packages, pipx_home, monkeypatch)

    assert shared_identity is not None
    assert shared_identity.canonical_path == shared_packages.resolve()
    result = _run_trusted_module(
        python,
        site_packages,
        (shared_identity.canonical_path,),
        "pip",
        "install",
        "--dry-run",
        "hol-guard==2.2.15",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["marker"] == "pipx-shared-pip"
    assert payload["argv"] == ["install", "--dry-run", "hol-guard==2.2.15"]
    assert not hook_marker.exists()


def test_pipx_shared_path_rejects_executable_pth_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _python, site_packages, _shared_packages, pipx_home = _pipx_style_venv(tmp_path)
    hook_marker = tmp_path / "pth-hook-ran"
    (site_packages / "pipx_shared.pth").write_text(
        f"import pathlib; pathlib.Path({str(hook_marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )

    with pytest.raises(UpdateSubprocessError, match="update_installer_untrusted"):
        _resolve_shared_identity(site_packages, pipx_home, monkeypatch)

    assert not hook_marker.exists()


def test_pipx_shared_path_rejects_target_outside_shared_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _python, site_packages, _shared_packages, pipx_home = _pipx_style_venv(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (site_packages / "pipx_shared.pth").write_text(f"{outside}\n", encoding="utf-8")

    with pytest.raises(UpdateSubprocessError, match="update_installer_untrusted"):
        _resolve_shared_identity(site_packages, pipx_home, monkeypatch)
