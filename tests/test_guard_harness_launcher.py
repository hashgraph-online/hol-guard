from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.durable_harness_launcher import build_harness_shim, build_windows_script


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher execution")
def test_python_repair_launcher_uses_desktop_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    desktop = tmp_path / "current-hol-guard"
    desktop.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    desktop.chmod(0o700)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.durable_harness_launcher.durable_desktop_current_hol_guard",
        lambda home: desktop,
    )
    context = SimpleNamespace(home_dir=tmp_path, guard_home=tmp_path / "guard home")
    source = build_harness_shim(
        "/missing/canary/python",
        "omp",
        context,
        ["--workspace", "project root"],
        trusted_python_flags=[],
        trusted_launcher="",
        trusted_import_root=tmp_path,
        launcher_env={},
        home_override_args=[],
        is_transient_path=lambda path: False,
    )
    launcher = tmp_path / "guard-omp"
    launcher.write_text(source)
    launcher.chmod(0o700)
    result = subprocess.run([str(launcher), "--version", "prompt with spaces"], capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        "run",
        "omp",
        "--guard-home",
        str(context.guard_home),
        "--workspace",
        "project root",
        "--arg=--version",
        "--arg=prompt with spaces",
    ]


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
    workspace = r"C:\work\100%\a&b"
    base_command = [guard_cli, "run", "omp", "--guard-home", "guard home", "--workspace", workspace]
    posix_path.write_text(
        f"#!/bin/sh\n# base_command = {base_command!r}\n",
        encoding="utf-8",
    )

    source = build_windows_script("ignored.exe", posix_path)

    assert guard_cli in source
    assert "run-shim" in source
    assert "--guard-home" in source
    assert "guard home" in source
    assert '"C:\\work\\100%%\\a&b"' in source
    assert "setlocal DisableDelayedExpansion" in source
    assert '"omp" "--" %*' in source
    assert str(posix_path) not in source


@pytest.mark.skipif(os.name != "nt", reason="Windows command execution contract")
def test_frozen_windows_launcher_preserves_multiple_arguments(tmp_path: Path) -> None:
    capture_path = tmp_path / "captured-args"
    guard_cli = tmp_path / "fake guard.cmd"
    guard_cli.write_text(f'@echo off\r\necho %* > "{capture_path}"\r\n', encoding="utf-8")
    posix_path = tmp_path / "guard-omp"
    workspace = tmp_path / "a&b"
    base_command = [str(guard_cli), "run", "omp", "--guard-home", "guard home", "--workspace", str(workspace)]
    posix_path.write_text(
        f"#!/bin/sh\n# base_command = {base_command!r}\n",
        encoding="utf-8",
    )
    launcher = tmp_path / "guard-omp.cmd"
    launcher.write_text(build_windows_script("ignored.exe", posix_path), encoding="utf-8")

    completed = subprocess.run([str(launcher), "--help", "prompt with spaces"], check=False, shell=True)

    assert completed.returncode == 0
    captured = capture_path.read_text(encoding="utf-8").strip()
    assert "run-shim" in captured
    assert str(workspace) in captured
    assert '-- --help "prompt with spaces"' in captured


def _generated_shim(executable: str, tmp_path: Path) -> str:
    """The shim Guard writes when there is no durable CLI to delegate to."""

    return build_harness_shim(
        executable,
        "codex",
        SimpleNamespace(home_dir=tmp_path, guard_home=tmp_path / "guard home"),
        [],
        trusted_python_flags=["-I", "-P"],
        trusted_launcher="import importlib.util, os, sys\nraise SystemExit(0)",
        trusted_import_root=tmp_path,
        launcher_env={},
        home_override_args=[],
        is_transient_path=lambda path: False,
    )


def test_the_windows_launcher_hands_the_loader_over_as_separate_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows has no exec, and os.execvpe re-splits the loader into fragments.

    The child then dies on `import` standing alone, which is what the field
    report showed, and the caller still sees success because the spawning
    parent exits 0 of its own accord.
    """

    source = _generated_shim("python.exe", tmp_path)
    calls: list[list[str]] = []

    def record(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        return SimpleNamespace(returncode=7)

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", record)
    monkeypatch.setattr("os.execvpe", lambda *_args: pytest.fail("Windows must not exec"))
    monkeypatch.setattr("sys.argv", ["guard-codex", "prompt with spaces"])

    with pytest.raises(SystemExit) as exit_info:
        exec(compile(source, "guard-codex", "exec"), {"__name__": "__main__"})

    assert exit_info.value.code == 7
    argv = calls[0]
    assert argv[:3] == ["python.exe", "-I", "-P"]
    assert argv[3] == "-c"
    assert "\n" in argv[4]
    assert argv[-1] == "--arg=prompt with spaces"


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher execution")
def test_the_posix_launcher_still_replaces_itself(tmp_path: Path) -> None:
    source = _generated_shim(sys.executable, tmp_path)

    assert "os.execvpe(argv[0], argv, combined_env)" in source


def test_the_plain_windows_launcher_reports_the_hooks_exit_code(tmp_path: Path) -> None:
    """`exit /b` alone returns the status of the command above it.

    `exit /b %ERRORLEVEL%` expands an environment variable of that name when
    the launching shell exports one, so a shell with `ERRORLEVEL=0` set would
    hand the harness a success for every hook Guard denied.
    """

    posix_path = tmp_path / "guard-codex"
    posix_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    script = build_windows_script("python.exe", posix_path)

    assert script.endswith("exit /b\r\n")
    assert "%ERRORLEVEL%" not in script
