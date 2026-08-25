"""Frozen Core package-shim CLI dispatch."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main


def test_frozen_package_shim_script_runs_before_argument_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_exe = tmp_path / "hol-guard"
    fake_exe.write_text("", encoding="utf-8")
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(fake_exe))
    shim_dir = tmp_path / "package-shims" / "bin"
    shim_dir.mkdir(parents=True)
    shim_path = shim_dir / "npm"
    shim_path.write_text(
        "\n".join(
            (
                f"#!{fake_exe}",
                "HOL_GUARD_PACKAGE_SHIM_SENTINEL = True",
                "raise SystemExit(17)",
                "",
            )
        ),
        encoding="utf-8",
    )

    assert main([str(shim_path)]) == 17


def test_frozen_package_shim_script_is_not_available_from_python_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr("sys.frozen", raising=False)
    shim_dir = tmp_path / "package-shims" / "bin"
    shim_dir.mkdir(parents=True)
    shim_path = shim_dir / "npm"
    shim_path.write_text("raise SystemExit(17)\n", encoding="utf-8")

    assert main([str(shim_path)]) != 17
