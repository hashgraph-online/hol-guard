"""Frozen Core package-shim launch helpers that avoid unreadable shebang paths."""

from __future__ import annotations

import ast
import runpy
import shlex
import sys
from collections.abc import Callable
from pathlib import Path

FROZEN_PACKAGE_SHIM_SENTINEL = "HOL_GUARD_PACKAGE_SHIM_SENTINEL"


def package_shim_needs_shell_wrapper() -> bool:
    return bool(getattr(sys, "frozen", False)) or (" " in sys.executable)


def frozen_package_shim_python_path(shim_dir: Path, command: str) -> Path:
    return shim_dir / f".{command}.py"


def package_shim_shell_wrapper(python_path: Path) -> str:
    return "\n".join(
        (
            "#!/bin/sh",
            f"exec {shlex.quote(sys.executable)} {shlex.quote(str(python_path))} \"$@\"",
            "",
        )
    )


def expected_package_shim_executable_bytes(
    python_source: str,
    shim_dir: Path,
    command: str,
) -> bytes:
    if not package_shim_needs_shell_wrapper():
        return python_source.encode("utf-8")
    python_path = frozen_package_shim_python_path(shim_dir, command)
    return package_shim_shell_wrapper(python_path).encode("utf-8")


def write_package_manager_shim_files(
    *,
    shim_dir: Path,
    command: str,
    python_source: str,
    windows_script: Callable[[Path], str],
) -> Path:
    posix_path = shim_dir / command
    windows_path = shim_dir / f"{command}.cmd"
    if package_shim_needs_shell_wrapper():
        python_path = frozen_package_shim_python_path(shim_dir, command)
        python_path.write_text(python_source, encoding="utf-8")
        posix_path.write_text(package_shim_shell_wrapper(python_path), encoding="utf-8")
        windows_path.write_text(windows_script(python_path), encoding="utf-8")
    else:
        posix_path.write_text(python_source, encoding="utf-8")
        windows_path.write_text(windows_script(posix_path), encoding="utf-8")
    posix_path.chmod(posix_path.stat().st_mode | 0o755)
    return posix_path


def _has_package_shim_layout(candidate: Path) -> bool:
    parent = candidate.parent
    grandparent = parent.parent
    return parent.name == "bin" and grandparent.name == "package-shims"


def resolve_frozen_package_shim_path(argv: list[str]) -> Path | None:
    """Return a trusted generated package shim when frozen Core is the shebang interpreter."""

    if not bool(getattr(sys, "frozen", False)) or not argv:
        return None
    from .shims import _PACKAGE_SHIM_COMMANDS

    trusted_commands = set(_PACKAGE_SHIM_COMMANDS.values())
    try:
        resolved = Path(argv[0]).expanduser().resolve(strict=True)
    except OSError:
        return None
    if resolved.name not in trusted_commands:
        if not (resolved.name.startswith(".") and resolved.name.endswith(".py")):
            return None
        command_name = resolved.name[1:-3]
        if command_name not in trusted_commands:
            return None
    if not _has_package_shim_layout(resolved):
        return None
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError:
        return None
    first_line = text.splitlines()[0] if text else ""
    if first_line != f"#!{sys.executable}":
        return None
    if f"{FROZEN_PACKAGE_SHIM_SENTINEL} = True" not in text:
        return None
    return resolved


def run_frozen_package_shim(shim_path: Path, shim_args: list[str]) -> int:
    """Execute a trusted generated package shim inside frozen Core."""

    original_argv = sys.argv
    try:
        sys.argv = [str(shim_path), *shim_args]
        runpy.run_path(str(shim_path), run_name="__main__")
    except SystemExit as error:
        code = error.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 1
    finally:
        sys.argv = original_argv
    return 0


def normalized_package_shim_content(content: bytes) -> str:
    """Return generated-shim content with install-specific paths masked."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    normalized_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("#!"):
            normalized_lines.append("#!<interpreter>")
            continue
        if line.startswith("exec "):
            normalized_lines.append('exec <python> <shim-python> "$@"')
            continue
        if line.startswith("base_command = "):
            normalized_lines.append(f"base_command = {_normalized_base_command_repr(line)}")
            continue
        if line.startswith("guard_cwd = ") or line.startswith("guard_cli_cwd = "):
            normalized_lines.append("guard_cli_cwd = '<path>'")
            continue
        if line.startswith("guard_home = "):
            normalized_lines.append("guard_home = '<path>'")
            continue
        if line.startswith("guard_workspace = "):
            normalized_lines.append("guard_workspace = <workspace-path>")
            continue
        if line.startswith("guard_has_explicit_workspace = "):
            normalized_lines.append("guard_has_explicit_workspace = <workspace-mode>")
            continue
        if line.startswith("shim_dir = "):
            normalized_lines.append("shim_dir = '<path>'")
            continue
        normalized_lines.append(line)
    return "\n".join(normalized_lines)


def _normalized_base_command_repr(line: str) -> str:
    raw_value = line.split("=", 1)[1].strip()
    try:
        value = ast.literal_eval(raw_value)
    except (SyntaxError, ValueError):
        return raw_value
    if not isinstance(value, list):
        return raw_value
    normalized: list[object] = []
    skip_path_after: str | None = None
    for index, item in enumerate(value):
        if index == 0 and isinstance(item, str):
            normalized.append("<python>")
            continue
        if isinstance(item, str) and index + 1 < len(value) and value[index + 1] == "codex_plugin_scanner.cli":
            normalized.append("<import-root>")
            continue
        if skip_path_after is not None:
            normalized.append(f"<{skip_path_after}>")
            skip_path_after = None
            continue
        normalized.append(item)
        if item in {"--guard-home", "--home", "--workspace"}:
            skip_path_after = str(item).lstrip("-")
    return repr(normalized)


__all__ = [
    "FROZEN_PACKAGE_SHIM_SENTINEL",
    "expected_package_shim_executable_bytes",
    "frozen_package_shim_python_path",
    "package_shim_needs_shell_wrapper",
    "package_shim_shell_wrapper",
    "resolve_frozen_package_shim_path",
    "run_frozen_package_shim",
    "write_package_manager_shim_files",
]
