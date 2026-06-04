"""Stable Python interpreter resolution for generated harness hook plugins."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .base import HarnessContext

_WORKTREE_MARKERS = ("/.worktrees/", "/worktrees/", "-wt-")


def _path_looks_like_worktree(path: Path) -> bool:
    text = str(path.resolve())
    return any(marker in text for marker in _WORKTREE_MARKERS)


def filter_worktree_path_entries(entries: list[str]) -> list[str]:
    filtered: list[str] = []
    for entry in entries:
        trimmed = entry.strip()
        if not trimmed:
            continue
        if _path_looks_like_worktree(Path(trimmed)):
            continue
        if trimmed not in filtered:
            filtered.append(trimmed)
    return filtered


def _guard_hook_python_candidates(context: HarnessContext) -> list[Path]:
    candidates: list[Path] = []
    if context.workspace_dir is not None:
        for name in (".venv", "venv"):
            python_path = context.workspace_dir / name / "bin" / "python"
            if python_path.is_file() and not _path_looks_like_worktree(python_path):
                candidates.append(python_path.resolve())
    pipx_python = Path.home() / ".local" / "pipx" / "venvs" / "hol-guard" / "bin" / "python"
    if pipx_python.is_file():
        candidates.append(pipx_python.resolve())
    hol_guard = shutil.which("hol-guard")
    if hol_guard:
        shim = Path(hol_guard).resolve()
        if shim.is_file() and not _path_looks_like_worktree(shim):
            interpreter = _python_from_launcher_shim(shim)
            if interpreter is not None and interpreter.is_file():
                candidates.append(interpreter.resolve())
    executable = Path(sys.executable).resolve()
    if executable.is_file() and not _path_looks_like_worktree(executable):
        candidates.append(executable)
    deduped: list[Path] = []
    for candidate in candidates:
        if candidate not in deduped:
            deduped.append(candidate)
    return deduped


def _python_from_launcher_shim(shim: Path) -> Path | None:
    try:
        lines = shim.read_text(encoding="utf-8").splitlines()
        if not lines:
            return None
        first_line = lines[0]
    except (OSError, ValueError):
        return None
    if not first_line.startswith("#!"):
        return None
    parts = first_line[2:].strip().split(maxsplit=1)
    if not parts:
        return None
    interpreter = Path(parts[0])
    return interpreter if interpreter.is_file() else None


def _python_can_import_guard(python: Path) -> bool:
    probe = "import codex_plugin_scanner; import cryptography"
    try:
        completed = subprocess.run(
            [str(python), "-c", probe],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
            env={key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ},
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def resolve_guard_hook_python(context: HarnessContext) -> Path:
    for candidate in _guard_hook_python_candidates(context):
        if _python_can_import_guard(candidate):
            return candidate
    raise RuntimeError(
        "Guard could not find a Python interpreter with codex_plugin_scanner and cryptography. "
        "Install hol-guard with pipx and re-run `hol-guard install opencode`."
    )


def package_root_from_python(python: Path) -> str:
    probe = (
        "import pathlib;"
        "import codex_plugin_scanner;"
        "print(pathlib.Path(codex_plugin_scanner.__file__).resolve().parent.parent)"
    )
    try:
        completed = subprocess.run(
            [str(python), "-c", probe],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
            env={key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Guard could not resolve codex_plugin_scanner from the hook Python.") from exc
    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip() or "Guard could not resolve codex_plugin_scanner from the hook Python."
        )
    root = completed.stdout.strip()
    if not root:
        raise RuntimeError("Guard could not resolve codex_plugin_scanner from the hook Python.")
    return root


__all__ = [
    "filter_worktree_path_entries",
    "package_root_from_python",
    "resolve_guard_hook_python",
]
