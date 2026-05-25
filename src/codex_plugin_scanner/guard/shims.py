"""Local launcher shims for Guard-managed harness execution."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .launcher import merge_guard_launcher_env

if TYPE_CHECKING:
    from .adapters.base import HarnessContext

_PACKAGE_SHIM_COMMANDS = {
    "bun": "bun",
    "bundle": "bundle",
    "cargo": "cargo",
    "composer": "composer",
    "go": "go",
    "gradle": "gradle",
    "mvn": "mvn",
    "npm": "npm",
    "pip": "pip",
    "pipenv": "pipenv",
    "pipx": "pipx",
    "pnpm": "pnpm",
    "poetry": "poetry",
    "uv": "uv",
    "uvx": "uvx",
    "yarn": "yarn",
}
_PACKAGE_SHIM_MANIFEST = "manifest.json"


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
    legacy_launcher_names: tuple[str, ...] = (),
    display_name: str | None = None,
) -> dict[str, object]:
    """Remove a previously installed Guard launcher shim."""

    shim_dir = context.guard_home / "bin"
    shim_name = launcher_name or harness
    harness_label = display_name or harness
    shim_paths = [
        shim_dir / f"guard-{name}{suffix}" for name in (shim_name, *legacy_launcher_names) for suffix in ("", ".cmd")
    ]
    removed_paths: list[str] = []
    for path in shim_paths:
        if path.exists():
            path.unlink()
            removed_paths.append(str(path))
    posix_path = shim_dir / f"guard-{shim_name}"
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


def install_package_shims(
    context: HarnessContext,
    *,
    managers: tuple[str, ...] | None = None,
) -> dict[str, object]:
    shim_root = context.guard_home / "package-shims"
    shim_dir = shim_root / "bin"
    shim_dir.mkdir(parents=True, exist_ok=True)
    normalized_managers = _normalize_package_shim_managers(managers)
    installed: list[str] = []
    for manager in normalized_managers:
        command = _PACKAGE_SHIM_COMMANDS[manager]
        posix_path = shim_dir / command
        windows_path = shim_dir / f"{command}.cmd"
        posix_path.write_text(_build_package_manager_python_shim(context, command), encoding="utf-8")
        posix_path.chmod(posix_path.stat().st_mode | 0o755)
        windows_path.write_text(_build_windows_script(posix_path), encoding="utf-8")
        installed.append(manager)
    manifest_payload = {
        "installed_managers": installed,
        "shim_dir": str(shim_dir),
    }
    _package_shim_manifest_path(context).write_text(json.dumps(manifest_payload, sort_keys=True), encoding="utf-8")
    return {
        "installed_managers": installed,
        "installed_count": len(installed),
        "shim_dir": str(shim_dir),
        "manifest_path": str(_package_shim_manifest_path(context)),
        "path_export_hint": f'export PATH="{shim_dir}:$PATH"',
        "status_command": "hol-guard package-shims status --json",
        "uninstall_command": "hol-guard package-shims uninstall --json",
    }


def package_shim_status(context: HarnessContext) -> dict[str, object]:
    manifest = _load_package_shim_manifest(context)
    installed_managers = [
        manager
        for manager in manifest.get("installed_managers", [])
        if isinstance(manager, str) and manager in _PACKAGE_SHIM_COMMANDS
    ]
    shim_dir = context.guard_home / "package-shims" / "bin"
    active_managers = [manager for manager in installed_managers if (shim_dir / _PACKAGE_SHIM_COMMANDS[manager]).exists()]
    missing_managers = [manager for manager in installed_managers if manager not in active_managers]
    return {
        "installed_managers": installed_managers,
        "active_managers": active_managers,
        "missing_managers": missing_managers,
        "shim_dir": str(shim_dir),
        "manifest_path": str(_package_shim_manifest_path(context)),
    }


def uninstall_package_shims(
    context: HarnessContext,
    *,
    managers: tuple[str, ...] | None = None,
) -> dict[str, object]:
    manifest = _load_package_shim_manifest(context)
    manifest_managers = tuple(
        manager
        for manager in manifest.get("installed_managers", [])
        if isinstance(manager, str) and manager in _PACKAGE_SHIM_COMMANDS
    )
    requested_managers = _normalize_package_shim_managers(managers) if managers else manifest_managers
    shim_dir = context.guard_home / "package-shims" / "bin"
    removed_paths: list[str] = []
    for manager in requested_managers:
        command = _PACKAGE_SHIM_COMMANDS[manager]
        for suffix in ("", ".cmd"):
            candidate = shim_dir / f"{command}{suffix}"
            if candidate.exists():
                candidate.unlink()
                removed_paths.append(str(candidate))
    remaining = [manager for manager in manifest_managers if manager not in requested_managers]
    manifest_path = _package_shim_manifest_path(context)
    if remaining:
        manifest_path.write_text(
            json.dumps({"installed_managers": remaining, "shim_dir": str(shim_dir)}, sort_keys=True),
            encoding="utf-8",
        )
    elif manifest_path.exists():
        manifest_path.unlink()
    return {
        "removed_managers": list(requested_managers),
        "removed_paths": removed_paths,
        "remaining_managers": remaining,
        "manifest_path": str(manifest_path),
        "shim_dir": str(shim_dir),
    }


def _build_package_manager_python_shim(context: HarnessContext, command: str) -> str:
    workspace_args: list[str] = []
    if context.workspace_dir is not None:
        workspace_args = ["--workspace", str(context.workspace_dir)]
    command_args = [
        sys.executable,
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "protect",
        "--guard-home",
        str(context.guard_home),
        *_home_override_args(context),
        *workspace_args,
        "--",
        command,
    ]
    return "\n".join(
        (
            f"#!{sys.executable}",
            "from __future__ import annotations",
            "import subprocess",
            "import sys",
            f"base_command = {command_args!r}",
            "raise SystemExit(subprocess.call([*base_command, *sys.argv[1:]]))",
            "",
        )
    )


def _normalize_package_shim_managers(managers: tuple[str, ...] | None) -> tuple[str, ...]:
    if managers is None or len(managers) == 0:
        return tuple(sorted(_PACKAGE_SHIM_COMMANDS.keys()))
    normalized = []
    for manager in managers:
        key = manager.strip().lower()
        if key in _PACKAGE_SHIM_COMMANDS and key not in normalized:
            normalized.append(key)
    return tuple(normalized)


def _package_shim_manifest_path(context: HarnessContext) -> Path:
    return context.guard_home / "package-shims" / _PACKAGE_SHIM_MANIFEST


def _load_package_shim_manifest(context: HarnessContext) -> dict[str, object]:
    manifest_path = _package_shim_manifest_path(context)
    if not manifest_path.exists():
        return {}
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


__all__ = [
    "install_guard_shim",
    "remove_guard_shim",
    "install_package_shims",
    "package_shim_status",
    "uninstall_package_shims",
]
