"""Durable harness launchers for transient packaged runtimes."""

from __future__ import annotations

import ast
import os
import shlex
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Protocol

from .stable_guard_cli import desktop_core_shim_for_executable


class HarnessContextLike(Protocol):
    @property
    def home_dir(self) -> Path: ...

    @property
    def guard_home(self) -> Path: ...


def is_transient_appimage_path(value: str) -> bool:
    normalized = str(Path(value).expanduser().absolute()).replace("\\", "/").lower()
    return "/tmp/.mount_" in normalized or "/private/tmp/.mount_" in normalized


def build_harness_shim(
    executable: str,
    harness: str,
    context: HarnessContextLike,
    workspace_args: Sequence[str],
    *,
    trusted_python_flags: Sequence[str],
    trusted_launcher: str,
    trusted_import_root: Path,
    launcher_env: Mapping[str, str],
    home_override_args: Sequence[str],
    is_transient_path: Callable[[Path], bool],
) -> str:
    if getattr(sys, "frozen", False) or is_transient_appimage_path(executable):
        return build_durable_cli_shim(
            harness,
            context,
            workspace_args,
            home_override_args=home_override_args,
            is_transient_path=is_transient_path,
            runtime_executable=executable,
        )
    command_args = [
        executable,
        *trusted_python_flags,
        "-c",
        trusted_launcher,
        str(trusted_import_root),
        "codex_plugin_scanner.cli",
        "guard",
        "run",
        harness,
        "--guard-home",
        str(context.guard_home),
        *home_override_args,
        *workspace_args,
    ]
    return "\n".join(
        (
            f"#!{executable}",
            "from __future__ import annotations",
            "import os",
            "import sys",
            f"base_command = {command_args!r}",
            f"base_env = {dict(launcher_env)!r}",
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
            "os.execvpe(base_command[0], [*base_command, *extra_args], combined_env)",
            "",
        )
    )


def build_windows_script(executable: str, posix_path: Path) -> str:
    if is_transient_appimage_path(executable):
        return "\r\n".join(
            (
                "@echo off",
                "echo HOL Guard needs a durable Windows install before this launcher can run. 1>&2",
                "exit /b 127",
                "",
            )
        )
    harness_command = _generated_harness_command(posix_path)
    if harness_command is not None:
        guard_cli, _, harness, *context_args = harness_command
        command = [guard_cli, "run-shim", *context_args, harness, "--"]
        return "\r\n".join(("@echo off", f"{subprocess.list2cmdline(command)} %*", ""))
    return "\r\n".join(("@echo off", f'"{executable}" "{posix_path}" %*', ""))


def _generated_harness_command(posix_path: Path) -> list[str] | None:
    if not posix_path.name.startswith("guard-"):
        return None
    try:
        source = posix_path.read_text(encoding="utf-8")
    except OSError:
        return None
    prefix = "# base_command = "
    command_line = next((line[len(prefix) :] for line in source.splitlines() if line.startswith(prefix)), None)
    if command_line is None:
        return None
    try:
        command = ast.literal_eval(command_line)
    except (SyntaxError, ValueError):
        return None
    if (
        not isinstance(command, list)
        or len(command) < 3
        or not all(isinstance(value, str) for value in command)
        or command[1] != "run"
    ):
        return None
    return command


def build_durable_cli_shim(
    harness: str,
    context: HarnessContextLike,
    workspace_args: Sequence[str],
    *,
    home_override_args: Sequence[str],
    is_transient_path: Callable[[Path], bool],
    runtime_executable: str | None = None,
) -> str:
    fixed_args = [
        "run",
        harness,
        "--guard-home",
        str(context.guard_home),
        *home_override_args,
        *workspace_args,
    ]
    quoted_args = " ".join(shlex.quote(arg) for arg in fixed_args)
    official_cli = durable_guard_cli_path(
        context,
        is_transient_path=is_transient_path,
        runtime_executable=runtime_executable,
    )
    metadata_command = [str(official_cli or "hol-guard"), *fixed_args]
    quoted_cli = shlex.quote(str(official_cli)) if official_cli is not None else "''"
    return "\n".join(
        (
            "#!/bin/sh",
            f"# base_command = {metadata_command!r}",
            f"guard_cli={quoted_cli}",
            'if [ ! -x "$guard_cli" ]; then',
            '        echo "HOL Guard needs the durable official install. Run: pipx install --force hol-guard" >&2',
            "        exit 127",
            "fi",
            "original_count=$#",
            "for arg do",
            '    set -- "$@" "--arg=$arg"',
            "done",
            'shift "$original_count"',
            f'exec "$guard_cli" {quoted_args} "$@"',
            "",
        )
    )


def durable_guard_cli_path(
    context: HarnessContextLike,
    *,
    is_transient_path: Callable[[Path], bool],
    runtime_executable: str | None = None,
) -> Path | None:
    candidates = (
        os.environ.get("HOL_GUARD_DESKTOP_RUNTIME_OWNER"),
        str(context.home_dir / ".local" / "bin" / "hol-guard"),
        runtime_executable,
    )
    for candidate in candidates:
        if not candidate:
            continue
        invocation_path = Path(candidate).expanduser().absolute()
        try:
            resolved_path = invocation_path.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        desktop_shim = desktop_core_shim_for_executable(resolved_path)
        if desktop_shim is not None:
            try:
                resolved_shim = desktop_shim.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if (
                desktop_shim.is_file()
                and os.access(desktop_shim, os.X_OK)
                and not is_transient_path(desktop_shim)
                and not is_transient_path(resolved_shim)
            ):
                return desktop_shim
            continue
        if not invocation_path.is_file() or not os.access(invocation_path, os.X_OK):
            continue
        if is_transient_path(invocation_path) or is_transient_path(resolved_path):
            continue
        return invocation_path
    return None
