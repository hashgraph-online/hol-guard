from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.shims import prepare_guard_shim


@pytest.fixture(autouse=True)
def _no_desktop_core(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("XDG_DATA_HOME", "APPDATA"):
        monkeypatch.delenv(name, raising=False)


def _context(tmp_path: Path, workspace: Path | None = None) -> SimpleNamespace:
    return SimpleNamespace(home_dir=tmp_path, guard_home=tmp_path / "guard home", workspace_dir=workspace)


def _launchers(harness: str, context: SimpleNamespace) -> tuple[str, str]:
    """The POSIX and Windows launchers the native runtime renders for an install."""

    posix, windows = prepare_guard_shim(harness, context).files
    assert posix.after is not None and windows.after is not None
    return posix.after.decode("utf-8"), windows.after.decode("utf-8")


def _desktop_core(root: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
    """Install Desktop's `current-hol-guard`, which outranks the Python launcher.

    ``root`` must be durable: a desktop core under a temporary root is skipped.
    """

    data = root / "data"
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    name = "current-hol-guard.exe" if os.name == "nt" else "current-hol-guard"
    desktop = data / "org.hol.guard.desktop" / "core" / name
    desktop.parent.mkdir(parents=True)
    desktop.write_text(body)
    desktop.chmod(0o700)
    return desktop


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher execution")
def test_python_repair_launcher_uses_desktop_core(
    tmp_path: Path, durable_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _desktop_core(durable_tmp_path, monkeypatch, '#!/bin/sh\nprintf "%s\\n" "$@"\n')
    workspace = tmp_path / "project root"
    context = _context(tmp_path, workspace)
    source, _ = _launchers("omp", context)
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
        "--home",
        str(tmp_path),
        "--workspace",
        str(workspace),
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


def test_desktop_windows_launcher_invokes_guard_directly(
    tmp_path: Path, durable_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    desktop = _desktop_core(durable_tmp_path, monkeypatch, "#!/bin/sh\n")
    workspace = tmp_path / "100%" / "a&b"
    context = _context(tmp_path, workspace)

    _, source = _launchers("omp", context)

    assert str(desktop) in source
    assert "run-shim" in source
    assert "--guard-home" in source
    assert str(context.guard_home) in source
    assert f'"{str(workspace).replace("%", "%%")}"' in source
    assert "setlocal DisableDelayedExpansion" in source
    assert '"omp" "--" %*' in source
    assert "guard-omp" not in source


def test_the_windows_launcher_hands_the_loader_over_as_separate_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows has no exec, and os.execvpe re-splits the loader into fragments.

    The child then dies on `import` standing alone, which is what the field
    report showed, and the caller still sees success because the spawning
    parent exits 0 of its own accord.
    """

    source, _ = _launchers("codex", _context(tmp_path))
    calls: list[list[str]] = []

    def record(argv: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        return SimpleNamespace(returncode=7)

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", record)
    monkeypatch.setattr("os.execvpe", lambda *_args: pytest.fail("Windows must not exec"))
    monkeypatch.setattr("sys.argv", ["guard-codex", "prompt with spaces"])

    with pytest.raises(SystemExit) as exit_info:
        exec(compile(source.replace("\r\n", "\n"), "guard-codex", "exec"), {"__name__": "__main__"})

    assert exit_info.value.code == 7
    argv = calls[0]
    assert argv[0] == sys.executable
    loader = argv.index("-c") + 1
    assert argv[loader].startswith("import importlib.util, os, sys; ")
    assert argv[loader].endswith("raise SystemExit(module.main(sys.argv[1:]))")
    assert argv[-1] == "--arg=prompt with spaces"


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher execution")
def test_the_posix_launcher_still_replaces_itself(tmp_path: Path) -> None:
    source, _ = _launchers("codex", _context(tmp_path))

    assert "os.execvpe(argv[0], argv, combined_env)" in source


def test_the_plain_windows_launcher_reports_the_hooks_exit_code(tmp_path: Path) -> None:
    """`exit /b` alone returns the status of the command above it.

    `exit /b %ERRORLEVEL%` expands an environment variable of that name when
    the launching shell exports one, so a shell with `ERRORLEVEL=0` set would
    hand the harness a success for every hook Guard denied.
    """

    _, script = _launchers("codex", _context(tmp_path))

    assert script.replace("\r", "").endswith("exit /b\n")
    assert "%ERRORLEVEL%" not in script
