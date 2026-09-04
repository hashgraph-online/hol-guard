from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.durable_harness_launcher import build_windows_script


def test_run_shim_keeps_windows_forwarded_arguments_verbatim() -> None:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(
        [
            "run-shim",
            "--guard-home",
            "guard home",
            "--workspace",
            "project root",
            "omp",
            "--",
            "--help",
            "prompt with spaces",
        ]
    )

    assert args.guard_command == "run-shim"
    assert args.harness == "omp"
    assert args.guard_home == "guard home"
    assert args.workspace == "project root"
    assert args.passthrough_args == ["--help", "prompt with spaces"]


def test_frozen_windows_launcher_invokes_guard_directly(tmp_path: Path) -> None:
    posix_path = tmp_path / "guard-omp"
    guard_cli = r"C:\Program Files\HOL Guard\current-hol-guard.exe"
    posix_path.write_text(
        f"#!/bin/sh\n# base_command = {[guard_cli, 'run', 'omp', '--guard-home', 'guard home']!r}\n",
        encoding="utf-8",
    )

    source = build_windows_script("ignored.exe", posix_path)

    assert guard_cli in source
    assert "run-shim" in source
    assert "--guard-home" in source
    assert "guard home" in source
    assert "omp -- %*" in source
    assert str(posix_path) not in source


@pytest.mark.skipif(os.name != "nt", reason="Windows command execution contract")
def test_frozen_windows_launcher_preserves_multiple_arguments(tmp_path: Path) -> None:
    capture_path = tmp_path / "captured-args"
    guard_cli = tmp_path / "fake guard.cmd"
    guard_cli.write_text(f'@echo off\r\necho %* > "{capture_path}"\r\n', encoding="utf-8")
    posix_path = tmp_path / "guard-omp"
    posix_path.write_text(
        f"#!/bin/sh\n# base_command = {[str(guard_cli), 'run', 'omp', '--guard-home', 'guard home']!r}\n",
        encoding="utf-8",
    )
    launcher = tmp_path / "guard-omp.cmd"
    launcher.write_text(build_windows_script("ignored.exe", posix_path), encoding="utf-8")

    completed = subprocess.run([str(launcher), "--help", "prompt with spaces"], check=False, shell=True)

    assert completed.returncode == 0
    captured = capture_path.read_text(encoding="utf-8").strip()
    assert "run-shim" in captured
    assert '-- --help "prompt with spaces"' in captured
