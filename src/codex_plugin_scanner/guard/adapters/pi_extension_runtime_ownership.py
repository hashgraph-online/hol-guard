"""Persistent runtime ownership for generated Pi-family extensions."""

from __future__ import annotations

import os
import site
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path

from ..stable_guard_cli import desktop_core_shim_for_executable, durable_desktop_current_hol_guard

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
    # Windows only: the argv that starts the contained-test sink, and the
    # directory its request snapshots must sit in. Empty elsewhere, where the
    # sink starts from the CLI command and requests use the process TEMP.
    contained_sink_command: tuple[str, ...] = ()
    contained_request_root: str = ""


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
    sink_command, request_root = _windows_contained_sink(python, package_root)
    return PiExtensionRuntimeOwnership(
        tuple(guard_args),
        python,
        ("-I", "-c", _windows_cli_bootstrap(package_root, guard_home=guard_home, harness=harness)),
        True,
        python,
        ("-I", "-c", _windows_recovery_bootstrap(package_root, guard_home=guard_home, home_dir=home_dir)),
        True,
        sink_command,
        request_root,
    )


def _windows_contained_sink(python: str, package_root: Path) -> tuple[tuple[str, ...], str]:
    """The sink argv and request directory Claude Code's Windows route uses.
    Without a profile Temp directory, protected runs stay denied."""
    from ..windows_paths import trusted_windows_local_temp
    from .zcode_contained_tests import contained_sink_command_prefix

    try:
        request_root = str(trusted_windows_local_temp())
    except (OSError, RuntimeError, ValueError):
        return (), ""
    return (*contained_sink_command_prefix(python, package_root), "guard"), request_root


def _stable_guard_cli_command(home_dir: Path) -> str:
    # AppImages prepend a transient mount to PATH. The official user install is
    # durable and must own hooks after the desktop process exits. Managed Core
    # under the Desktop app-data directory is also durable and must outrank a
    # PATH pipx hol-guard that would start a second, older daemon. Past those,
    # the extension runs the CLI of the runtime installing it, never whichever
    # hol-guard happens to come first on PATH, which can be another install.
    durable_desktop = durable_desktop_current_hol_guard(home_dir)
    candidates = (
        os.environ.get(_DESKTOP_RUNTIME_OWNER_ENV),
        str(durable_desktop) if durable_desktop is not None else None,
        str(home_dir / ".local" / "bin" / "hol-guard"),
        *_installing_runtime_cli_candidates(),
    )
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser().absolute()
        try:
            resolved = path.resolve(strict=False)
        except RuntimeError:
            continue
        normalized = str(path).replace("\\", "/").lower()
        if "/tmp/.mount_" in normalized or "/private/tmp/.mount_" in normalized:
            continue
        desktop_shim = desktop_core_shim_for_executable(resolved)
        if desktop_shim is not None:
            if desktop_shim.is_file() and os.access(desktop_shim, os.X_OK):
                return str(desktop_shim)
            # A versioned Desktop executable is not durable enough to own a
            # generated extension. Continue to the official install instead.
            continue
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return "hol-guard"


def _installing_runtime_cli_candidates() -> tuple[str, ...]:
    """Return the ``hol-guard`` entry points that belong to this interpreter."""
    if getattr(sys, "frozen", False):
        return (sys.executable,)
    scripts = [sysconfig.get_path("scripts")]
    user_site = site.getusersitepackages() if site.ENABLE_USER_SITE else None
    if user_site and Path(__file__).resolve().is_relative_to(Path(user_site).resolve()):
        # A user install's own entry point outranks an unrelated one beside
        # the interpreter.
        scripts.insert(0, sysconfig.get_path("scripts", sysconfig.get_preferred_scheme("user")))
    name = "hol-guard.exe" if os.name == "nt" else "hol-guard"
    return tuple(str(Path(directory) / name) for directory in scripts if directory)


def _windows_cli_bootstrap(package_root: Path, *, guard_home: Path, harness: str) -> str:
    return (
        "import json,os,sys;"
        f"sys.path.insert(0,{str(package_root)!r});"
        "from codex_plugin_scanner.guard.codex_hook_windows_job import assign_current_process_to_windows_hook_job;"
        "_windows_job=assign_current_process_to_windows_hook_job() if os.name=='nt' else None;"
        "sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;"
        "sys.stderr.flush() if _windows_job is not None else None;from pathlib import Path;"
        "from codex_plugin_scanner.guard.hook_execution_environment import stamp_hook_input_text;"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import run_bounded_cli_hook;"
        "argv=json.loads(sys.argv[1]);config={'python_executable':sys.executable,"
        f"'package_root':{str(package_root)!r},'guard_home':{str(guard_home)!r},"
        f"'cli_args':argv,'harness':{harness!r},'timeout_seconds':0.75}};"
        "raise SystemExit(run_bounded_cli_hook(config,input_text=stamp_hook_input_text(sys.stdin.read(1000001))))"
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
