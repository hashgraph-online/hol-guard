"""Frozen Core package-shim launch helpers that avoid unreadable shebang paths."""

from __future__ import annotations

import ast
import os
import runpy
import shlex
import sys
from collections.abc import Callable
from pathlib import Path

from .stable_guard_cli import resolve_frozen_guard_cli, trusted_frozen_guard_cli_paths

FROZEN_PACKAGE_SHIM_SENTINEL = "HOL_GUARD_PACKAGE_SHIM_SENTINEL"


def package_shim_needs_shell_wrapper() -> bool:
    return bool(getattr(sys, "frozen", False)) or (" " in sys.executable)


def frozen_package_shim_python_path(shim_dir: Path, command: str) -> Path:
    return shim_dir / f".{command}.py"


def package_shim_interpreter() -> str:
    """Return the Guard CLI used to exec package-manager shims.

    Unfrozen installs keep the current Python. Frozen Desktop runtimes use the
    prune-safe launcher so versioned Core paths can disappear safely.
    """

    if bool(getattr(sys, "frozen", False)):
        return resolve_frozen_guard_cli()
    return sys.executable


def package_shim_shell_wrapper(python_path: Path) -> str:
    return "\n".join(
        (
            "#!/bin/sh",
            f'exec {shlex.quote(package_shim_interpreter())} {shlex.quote(str(python_path))} "$@"',
            "",
        )
    )


def package_shim_wrapper_interpreter(wrapper: bytes) -> Path | None:
    """Return the Guard CLI path baked into a package-shim wrapper, if any."""

    try:
        text = wrapper.decode("utf-8")
    except UnicodeDecodeError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("exec "):
            try:
                tokens = shlex.split(stripped)
            except ValueError:
                return None
            if len(tokens) >= 2 and tokens[0] == "exec":
                return Path(tokens[1])
        if stripped.startswith("#!") and not stripped.startswith("#!/bin/sh"):
            interpreter = stripped[2:].strip()
            if interpreter:
                return Path(interpreter)
    return None


def package_shim_interpreter_runnable(wrapper: bytes) -> bool:
    interpreter = package_shim_wrapper_interpreter(wrapper)
    if interpreter is None:
        return True
    if not interpreter.is_file():
        return False
    if os.name == "nt":
        return True
    return os.access(interpreter, os.X_OK)


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


_SIDECAR_ATTESTATION_MARK = b"\n# hol-guard-sidecar\n"


def expected_package_shim_attestation_bytes(python_source: str, shim_dir: Path, command: str) -> bytes:
    wrapper = expected_package_shim_executable_bytes(python_source, shim_dir, command)
    if not package_shim_needs_shell_wrapper():
        return wrapper
    return wrapper + _SIDECAR_ATTESTATION_MARK + python_source.encode("utf-8")


def installed_package_shim_attestation_bytes(shim_dir: Path, command: str, wrapper: bytes) -> bytes:
    if not package_shim_needs_shell_wrapper():
        return wrapper
    sidecar_path = frozen_package_shim_python_path(shim_dir, command)
    if sidecar_path.is_symlink() or not sidecar_path.is_file():
        return wrapper + _SIDECAR_ATTESTATION_MARK
    return wrapper + _SIDECAR_ATTESTATION_MARK + sidecar_path.read_bytes()


def package_shim_integrity_ok(
    *,
    python_source: str,
    shim_dir: Path,
    command: str,
    installed_wrapper: bytes,
) -> bool:
    if not package_shim_interpreter_runnable(installed_wrapper):
        return False
    sidecar_path = frozen_package_shim_python_path(shim_dir, command)
    if (
        package_shim_needs_shell_wrapper()
        and sidecar_path.is_file()
        and not sidecar_path.is_symlink()
        and not package_shim_interpreter_runnable(sidecar_path.read_bytes())
    ):
        return False
    expected = expected_package_shim_attestation_bytes(python_source, shim_dir, command)
    current = installed_package_shim_attestation_bytes(shim_dir, command, installed_wrapper)
    if current == expected:
        return True
    expected_wrapper = expected_package_shim_executable_bytes(python_source, shim_dir, command)
    if normalized_package_shim_content(installed_wrapper) != normalized_package_shim_content(expected_wrapper):
        return False
    if not package_shim_needs_shell_wrapper():
        return True
    sidecar_path = frozen_package_shim_python_path(shim_dir, command)
    if sidecar_path.is_symlink() or not sidecar_path.is_file():
        return False
    return normalized_package_shim_content(sidecar_path.read_bytes()) == normalized_package_shim_content(
        python_source.encode("utf-8")
    )


def classify_installed_package_shim_integrity(
    *,
    python_source: str,
    shim_dir: Path,
    command: str,
    installed_wrapper: bytes,
    stored_hash: str | None,
    hash_content: Callable[[bytes], str],
) -> str:
    current_hash = hash_content(installed_package_shim_attestation_bytes(shim_dir, command, installed_wrapper))
    expected_hash = hash_content(expected_package_shim_attestation_bytes(python_source, shim_dir, command))
    if not package_shim_interpreter_runnable(installed_wrapper):
        return "stale"
    if current_hash == expected_hash or package_shim_integrity_ok(
        python_source=python_source,
        shim_dir=shim_dir,
        command=command,
        installed_wrapper=installed_wrapper,
    ):
        return "ok"
    if stored_hash == current_hash:
        return "stale"
    if stored_hash is None:
        return "unknown"
    return "tampered"


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
    candidate = Path(argv[0]).expanduser()
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return None
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if resolved.parent.resolve() != candidate.parent.resolve():
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
    shebang_interpreter = first_line[2:] if first_line.startswith("#!") else ""
    if shebang_interpreter not in trusted_frozen_guard_cli_paths():
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
    "classify_installed_package_shim_integrity",
    "expected_package_shim_attestation_bytes",
    "expected_package_shim_executable_bytes",
    "frozen_package_shim_python_path",
    "installed_package_shim_attestation_bytes",
    "normalized_package_shim_content",
    "package_shim_integrity_ok",
    "package_shim_interpreter",
    "package_shim_interpreter_runnable",
    "package_shim_needs_shell_wrapper",
    "package_shim_shell_wrapper",
    "package_shim_wrapper_interpreter",
    "resolve_frozen_package_shim_path",
    "run_frozen_package_shim",
    "write_package_manager_shim_files",
]
