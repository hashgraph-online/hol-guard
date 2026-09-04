"""Persistent runtime ownership for generated Pi-family extensions."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from ..stable_guard_cli import desktop_core_shim_for_executable

_DESKTOP_RUNTIME_OWNER_ENV = "HOL_GUARD_DESKTOP_RUNTIME_OWNER"


@dataclass(frozen=True)
class PiExtensionRuntimeOwnership:
    guard_args: tuple[str, ...]
    cli_command: str
    cli_args: tuple[str, ...]
    cli_accepts_json_args: bool
    recovery_command: str
    recovery_args: tuple[str, ...]
    recovery_accepts_failure_kind: bool


def resolve_pi_extension_runtime_ownership(
    *, guard_home: Path, home_dir: Path, harness: str, package_source: Path
) -> PiExtensionRuntimeOwnership:
    guard_args = ["hook", "--json", "--guard-home", str(guard_home), "--harness", harness]
    if home_dir.resolve() != Path.home().resolve():
        guard_args.extend(["--home", str(home_dir)])
    if os.name != "nt":
        cli_command = _stable_guard_cli_command(home_dir)
        recovery_args = ["daemon", "recover", "--guard-home", str(guard_home)]
        if home_dir.resolve() != Path.home().resolve():
            recovery_args.extend(["--home", str(home_dir)])
        return PiExtensionRuntimeOwnership(
            tuple(guard_args),
            cli_command,
            tuple(guard_args),
            False,
            cli_command,
            tuple(recovery_args),
            True,
        )
    package_root = package_source.resolve().parents[3]
    python = str(Path(sys.executable).expanduser().absolute())
    return PiExtensionRuntimeOwnership(
        tuple(guard_args),
        python,
        ("-I", "-c", _windows_cli_bootstrap(package_root, guard_home=guard_home, harness=harness)),
        True,
        python,
        ("-I", "-c", _windows_recovery_bootstrap(package_root, guard_home=guard_home, home_dir=home_dir)),
        True,
    )


def _stable_guard_cli_command(home_dir: Path) -> str:
    # AppImages prepend a transient mount to PATH. The official user install is
    # durable and must own hooks after the desktop process exits.
    candidates = (
        os.environ.get(_DESKTOP_RUNTIME_OWNER_ENV),
        str(home_dir / ".local" / "bin" / "hol-guard"),
        shutil.which("hol-guard"),
    )
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser().absolute()
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        normalized = str(path).replace("\\", "/").lower()
        if "/tmp/.mount_" in normalized or "/private/tmp/.mount_" in normalized:
            continue
        desktop_shim = desktop_core_shim_for_executable(resolved)
        if desktop_shim is not None:
            if desktop_shim.is_file() and os.access(desktop_shim, os.X_OK):
                return str(desktop_shim)
            continue
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return "hol-guard"


def _windows_cli_bootstrap(package_root: Path, *, guard_home: Path, harness: str) -> str:
    return (
        "import json,os,sys;"
        f"sys.path.insert(0,{str(package_root)!r});"
        "from codex_plugin_scanner.guard.codex_hook_windows_job import assign_current_process_to_windows_hook_job;"
        "_windows_job=assign_current_process_to_windows_hook_job() if os.name=='nt' else None;"
        "sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;"
        "sys.stderr.flush() if _windows_job is not None else None;from pathlib import Path;"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import run_bounded_cli_hook;"
        "argv=json.loads(sys.argv[1]);config={'python_executable':sys.executable,"
        f"'package_root':{str(package_root)!r},'guard_home':{str(guard_home)!r},"
        f"'cli_args':argv,'harness':{harness!r},'timeout_seconds':0.75}};"
        "raise SystemExit(run_bounded_cli_hook(config,input_text=sys.stdin.read(1000001)))"
    )


def _windows_recovery_bootstrap(package_root: Path, *, guard_home: Path, home_dir: Path) -> str:
    return (
        "import os,sys;"
        f"sys.path.insert(0,{str(package_root)!r});"
        "from codex_plugin_scanner.guard.codex_hook_windows_job import assign_current_process_to_windows_hook_job;"
        "_windows_job=assign_current_process_to_windows_hook_job(allow_breakaway=True) if os.name=='nt' else None;"
        "sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;"
        "sys.stderr.flush() if _windows_job is not None else None;from pathlib import Path;"
        "from codex_plugin_scanner.guard.daemon.manager import recover_guard_daemon_after_hook_failure;"
        f"recover_guard_daemon_after_hook_failure(Path({str(guard_home)!r}),"
        f"home_dir=Path({str(home_dir)!r}),failure_kind=sys.argv[1])"
    )


__all__ = ["PiExtensionRuntimeOwnership", "resolve_pi_extension_runtime_ownership"]
