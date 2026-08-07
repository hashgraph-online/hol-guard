"""Regression coverage for pipx updater recovery."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from codex_plugin_scanner.guard.cli.update_subprocess import _TRUSTED_MODULE_BOOTSTRAP
from codex_plugin_scanner.guard.shims import _trusted_python_flags


def _pipx_style_venv(tmp_path: Path) -> tuple[Path, Path, Path]:
    venv_dir = tmp_path / "hol-guard"
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
    shared_packages = tmp_path / "shared"
    shared_packages.mkdir()
    (site_packages / "pipx_shared.pth").write_text(f"{shared_packages}\n", encoding="utf-8")
    return python, site_packages, shared_packages


def _run_trusted_module(
    python: Path,
    site_packages: Path,
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
            module,
            *args,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_trusted_pip_bootstrap_processes_pipx_shared_path(tmp_path: Path) -> None:
    python, site_packages, shared_packages = _pipx_style_venv(tmp_path)
    pip_package = shared_packages / "pip"
    pip_package.mkdir()
    (pip_package / "__init__.py").write_text("", encoding="utf-8")
    (pip_package / "__main__.py").write_text(
        "import json, sys\nprint(json.dumps({'marker': 'pipx-shared-pip', 'argv': sys.argv[1:]}))\n",
        encoding="utf-8",
    )

    result = _run_trusted_module(
        python,
        site_packages,
        "pip",
        "install",
        "--dry-run",
        "hol-guard==2.2.15",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["marker"] == "pipx-shared-pip"
    assert payload["argv"] == ["install", "--dry-run", "hol-guard==2.2.15"]


def test_trusted_module_bootstrap_does_not_enable_site_for_other_modules(tmp_path: Path) -> None:
    python, site_packages, shared_packages = _pipx_style_venv(tmp_path)
    probe_package = shared_packages / "guard_site_probe"
    probe_package.mkdir()
    (probe_package / "__init__.py").write_text("", encoding="utf-8")
    (probe_package / "__main__.py").write_text("print('unexpected')\n", encoding="utf-8")

    result = _run_trusted_module(python, site_packages, "guard_site_probe")

    assert result.returncode != 0
    assert "No module named guard_site_probe" in result.stderr
