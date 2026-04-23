"""Local launcher shims for Guard-managed harness execution."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .launcher import merge_guard_launcher_env

if TYPE_CHECKING:
    from .adapters.base import HarnessContext


def install_guard_shim(
    harness: str,
    context: HarnessContext,
    *,
    launcher_name: str | None = None,
    display_name: str | None = None,
) -> dict[str, object]:
    """Create a local launcher shim that routes harness launches through Guard."""

    shim_dir = context.guard_home / "bin"
    shim_dir.mkdir(parents=True, exist_ok=True)
    shim_name = launcher_name or harness
    harness_label = display_name or harness
    posix_path = shim_dir / f"guard-{shim_name}"
    windows_path = shim_dir / f"guard-{shim_name}.cmd"
    workspace_args = []
    if context.workspace_dir is not None:
        workspace_args = ["--workspace", str(context.workspace_dir)]
    posix_path.write_text(_build_python_shim(harness, context, workspace_args), encoding="utf-8")
    posix_path.chmod(posix_path.stat().st_mode | 0o755)
    windows_path.write_text(_build_windows_script(posix_path), encoding="utf-8")
    return {
        "shim_path": str(posix_path),
        "shim_dir": str(shim_dir),
        "shim_command": posix_path.name,
        "windows_shim_path": str(windows_path),
        "notes": [
            f"Launch {harness_label} through {posix_path.name} so Guard checks changes before the harness starts.",
            f"Add {shim_dir} to PATH to use the wrapper command from any shell.",
        ],
    }


def remove_guard_shim(
    harness: str,
    context: HarnessContext,
    *,
    launcher_name: str | None = None,
    display_name: str | None = None,
) -> dict[str, object]:
    """Remove a previously installed Guard launcher shim."""

    shim_dir = context.guard_home / "bin"
    shim_name = launcher_name or harness
    harness_label = display_name or harness
    posix_path = shim_dir / f"guard-{shim_name}"
    windows_path = shim_dir / f"guard-{shim_name}.cmd"
    removed_paths: list[str] = []
    for path in (posix_path, windows_path):
        if path.exists():
            path.unlink()
            removed_paths.append(str(path))
    return {
        "shim_path": str(posix_path),
        "shim_dir": str(shim_dir),
        "removed_paths": removed_paths,
        "shim_command": posix_path.name,
        "notes": [f"Removed the Guard launcher shim for {harness_label}."],
    }


def _build_python_shim(harness: str, context: HarnessContext, workspace_args: list[str]) -> str:
    command_args = [
        sys.executable,
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "run",
        harness,
        "--guard-home",
        str(context.guard_home),
        *_home_override_args(context),
        *workspace_args,
    ]
    launcher_env = merge_guard_launcher_env()
    return "\n".join(
        (
            f"#!{sys.executable}",
            "from __future__ import annotations",
            "import os",
            "import subprocess",
            "import sys",
            f"base_command = {command_args!r}",
            f"base_env = {launcher_env!r}",
            "combined_env = {**os.environ, **base_env}",
            "if 'PYTHONPATH' in os.environ and 'PYTHONPATH' in base_env:",
            "    pythonpath_entries = []",
            "    os_pythonpath = os.environ['PYTHONPATH'].split(os.pathsep)",
            "    base_pythonpath = base_env['PYTHONPATH'].split(os.pathsep)",
            "    for entry in [*os_pythonpath, *base_pythonpath]:",
            "        normalized = entry.strip()",
            "        if normalized and normalized not in pythonpath_entries:",
            "            pythonpath_entries.append(normalized)",
            "    combined_env['PYTHONPATH'] = os.pathsep.join(pythonpath_entries)",
            'extra_args = [f"--arg={arg}" for arg in sys.argv[1:]]',
            "raise SystemExit(subprocess.call([*base_command, *extra_args], env=combined_env))",
            "",
        )
    )


def _build_windows_script(posix_path: Path) -> str:
    return "\r\n".join(("@echo off", f'"{sys.executable}" "{posix_path}" %*', ""))


def _home_override_args(context: HarnessContext) -> list[str]:
    if context.home_dir.resolve() == Path.home().resolve():
        return []
    return ["--home", str(context.home_dir)]


__all__ = ["install_guard_shim", "remove_guard_shim"]
