"""Local launcher shims for Guard-managed harness execution."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .launcher import merge_guard_launcher_env
from .package_shim_status import enrich_package_shim_status_payload
from .shim_probe import (
    SHIM_PROBE_ENV_VALUE,
    SHIM_PROBE_ENV_VAR,
    package_shim_probe_args,
    parse_protect_json_stdout,
    protect_evaluator_evidence,
)
from .stable_digest import stable_digest_hex

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
    "npx": "npx",
    "pip": "pip",
    "pip3": "pip3",
    "pipenv": "pipenv",
    "pipx": "pipx",
    "pnpm": "pnpm",
    "poetry": "poetry",
    "uv": "uv",
    "uvx": "uvx",
    "yarn": "yarn",
}
_PACKAGE_SHIM_MANIFEST = "manifest.json"
_TRUSTED_CLI_LAUNCHER = (
    "import importlib.util, os, sys; "
    "trusted_root = os.path.realpath(sys.argv.pop(1)); "
    "module_name = sys.argv.pop(1); "
    "package_name = module_name.split('.', 1)[0]; "
    "package_root = os.path.join(trusted_root, package_name); "
    "module_path = os.path.join(package_root, *module_name.split('.')[1:]) + '.py'; "
    "cwd = os.path.realpath(os.getcwd()); "
    "normalize = lambda entry: cwd if entry in ('', '.', os.curdir) else os.path.realpath(entry); "
    "blocked_entries = {cwd, trusted_root}; "
    "sys.path = [trusted_root, *[entry for entry in sys.path if normalize(entry) not in blocked_entries]]; "
    "package_spec = importlib.util.spec_from_file_location("
    "package_name, "
    "os.path.join(package_root, '__init__.py'), "
    "submodule_search_locations=[package_root],"
    "); "
    "package_module = importlib.util.module_from_spec(package_spec); "
    "sys.modules[package_name] = package_module; "
    "package_spec.loader.exec_module(package_module); "
    "module_spec = importlib.util.spec_from_file_location(module_name, module_path); "
    "module = importlib.util.module_from_spec(module_spec); "
    "module.__package__ = package_name; "
    "sys.modules[module_name] = module; "
    "module_spec.loader.exec_module(module); "
    "sys.argv[0] = module_path; "
    "raise SystemExit(module.main(sys.argv[1:]))"
)


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
        *_trusted_python_flags(),
        "-c",
        _TRUSTED_CLI_LAUNCHER,
        str(_trusted_import_root()),
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
    if not context.home_dir:
        return []
    if context.home_dir.resolve() == Path.home().resolve():
        return []
    return ["--home", str(context.home_dir)]


def build_shim_content_hash(content: bytes) -> str:
    """Return hex SHA-256 of shim content bytes."""
    return hashlib.sha256(content).hexdigest()


def _normalized_package_shim_content(content: bytes) -> str:
    """Return generated-shim content with install-specific paths masked."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    normalized_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("#!"):
            normalized_lines.append("#!<python>")
            continue
        if line.startswith("base_command = "):
            normalized_lines.append(f"base_command = {_normalized_base_command_repr(line)}")
            continue
        if line.startswith("guard_cwd = "):
            normalized_lines.append("guard_cwd = '<path>'")
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


def get_real_binary_info(
    binary_path: str,
    *,
    redact_path_prefix: str | None = None,
) -> dict[str, object]:
    """Return hash, mtime, and redacted display path for the real binary at *binary_path*."""
    p = Path(binary_path)
    if not p.exists() or not p.is_file():
        return {"found": False, "content_hash": None, "mtime": None, "path_display": None}
    content = p.read_bytes()
    content_hash = build_shim_content_hash(content)
    mtime = p.stat().st_mtime
    path_str = str(p)
    if redact_path_prefix and path_str.startswith(redact_path_prefix):
        path_display = "…" + path_str[len(redact_path_prefix) :]
    else:
        path_display = path_str
    return {
        "found": True,
        "content_hash": content_hash,
        "mtime": mtime,
        "path_display": path_display,
    }


def _has_package_shim_layout(candidate: Path) -> bool:
    parent = candidate.parent
    grandparent = parent.parent
    return parent.name == "bin" and grandparent.name == "package-shims"


def _is_trusted_package_shim_binary(candidate: Path, trusted_shim_dir: Path) -> bool:
    try:
        candidate.resolve().relative_to(trusted_shim_dir.resolve())
    except ValueError:
        return False
    return candidate.is_file()


def _is_foreign_package_shim_binary(candidate: Path, trusted_shim_dir: Path) -> bool:
    return _has_package_shim_layout(candidate) and not _is_trusted_package_shim_binary(
        candidate,
        trusted_shim_dir,
    )


def get_path_order_status(
    context: HarnessContext,
    *,
    manager: str,
    path_env: str | None = None,
) -> dict[str, object]:
    """Return PATH order status: whether shim precedes the real manager binary."""
    command = _PACKAGE_SHIM_COMMANDS.get(manager)
    if not command:
        return {"shim_precedes_real": False, "real_binary_found": False, "path_broken": True, "shim_dir": None}
    shim_dir = (context.guard_home / "package-shims" / "bin").expanduser().resolve()
    shim_path = shim_dir / command
    path_dirs = (path_env or os.environ.get("PATH", "")).split(os.pathsep)
    shim_dir_index: int | None = None
    real_dir_index: int | None = None
    foreign_shim_index: int | None = None
    foreign_shim_path: str | None = None
    real_binary_path: str | None = None
    for idx, dir_entry in enumerate(path_dirs):
        d = Path(dir_entry).expanduser().resolve()
        if d == shim_dir and shim_dir_index is None:
            shim_dir_index = idx
            continue
        candidate = d / command
        if not candidate.exists() or not candidate.is_file() or candidate == shim_path:
            continue
        if _is_foreign_package_shim_binary(candidate, shim_dir):
            if foreign_shim_index is None:
                foreign_shim_index = idx
                foreign_shim_path = str(candidate)
            continue
        if _is_trusted_package_shim_binary(candidate, shim_dir):
            continue
        if real_dir_index is None:
            real_dir_index = idx
            real_binary_path = str(candidate)
    foreign_shim_precedes_trusted = (
        foreign_shim_index is not None and shim_dir_index is not None and foreign_shim_index < shim_dir_index
    )
    if shim_dir_index is None:
        return {
            "shim_precedes_real": False,
            "real_binary_found": real_dir_index is not None,
            "real_binary_path": real_binary_path,
            "real_binary_path_index": real_dir_index,
            "shim_in_path": False,
            "shim_path_index": None,
            "path_broken": True,
            "foreign_shim_bypass": foreign_shim_index is not None,
            "foreign_shim_path": foreign_shim_path,
            "foreign_shim_path_index": foreign_shim_index,
            "shim_dir": str(shim_dir),
        }
    if foreign_shim_precedes_trusted:
        return {
            "shim_precedes_real": False,
            "real_binary_found": real_dir_index is not None,
            "real_binary_path": real_binary_path,
            "real_binary_path_index": real_dir_index,
            "shim_in_path": True,
            "shim_path_index": shim_dir_index,
            "path_broken": True,
            "foreign_shim_bypass": True,
            "foreign_shim_path": foreign_shim_path,
            "foreign_shim_path_index": foreign_shim_index,
            "shim_dir": str(shim_dir),
        }
    if real_dir_index is None:
        return {
            "shim_precedes_real": True,
            "real_binary_found": False,
            "real_binary_path": None,
            "real_binary_path_index": None,
            "shim_in_path": True,
            "shim_path_index": shim_dir_index,
            "path_broken": False,
            "foreign_shim_bypass": False,
            "foreign_shim_path": foreign_shim_path,
            "foreign_shim_path_index": foreign_shim_index,
            "shim_dir": str(shim_dir),
        }
    precedes = shim_dir_index < real_dir_index
    return {
        "shim_precedes_real": precedes,
        "real_binary_found": True,
        "real_binary_path": real_binary_path,
        "real_binary_path_index": real_dir_index,
        "shim_in_path": True,
        "shim_path_index": shim_dir_index,
        "path_broken": not precedes,
        "foreign_shim_bypass": False,
        "foreign_shim_path": foreign_shim_path,
        "foreign_shim_path_index": foreign_shim_index,
        "shim_dir": str(shim_dir),
    }


def _package_shim_profile_status(context: HarnessContext) -> dict[str, object]:
    shim_dir = context.guard_home / "package-shims" / "bin"
    home_dir = context.home_dir if isinstance(context.home_dir, Path) else None
    if home_dir is None:
        return {
            "shell_profile_configured": False,
            "shell_profile_path": None,
        }
    profile_path, _export_line = _package_shim_profile_target(home_dir, shim_dir)
    try:
        existing = profile_path.read_text(encoding="utf-8") if profile_path.exists() else ""
    except OSError:
        existing = ""
    configured = _profile_already_references_path(existing, shim_dir)
    return {
        "shell_profile_configured": configured,
        "shell_profile_path": str(profile_path),
    }


def _package_shim_activation_path_status(
    *,
    installed_managers: list[str],
    path_contains_shim_dir: bool,
    shell_profile_configured: bool,
) -> str:
    if installed_managers and path_contains_shim_dir:
        return "in_path"
    if installed_managers and shell_profile_configured:
        return "restart_required"
    return "missing_from_path"


def install_package_shims(
    context: HarnessContext,
    *,
    managers: tuple[str, ...] | None = None,
) -> dict[str, object]:
    shim_root = context.guard_home / "package-shims"
    shim_dir = shim_root / "bin"
    shim_dir.mkdir(parents=True, exist_ok=True)
    normalized_managers = _normalize_package_shim_managers(managers)
    existing_manifest = _load_package_shim_manifest(context)
    existing_managers = tuple(
        manager
        for manager in existing_manifest.get("installed_managers", [])
        if isinstance(manager, str) and manager in _PACKAGE_SHIM_COMMANDS
    )
    tracked_managers = tuple(dict.fromkeys([*existing_managers, *normalized_managers]))
    existing_hashes: dict[str, str] = existing_manifest.get("content_hashes", {})
    existing_last_tests = existing_manifest.get("last_test_at", {})
    last_test_at = dict(existing_last_tests) if isinstance(existing_last_tests, dict) else {}
    installed: list[str] = []
    content_hashes: dict[str, str] = dict(existing_hashes)
    for manager in normalized_managers:
        command = _PACKAGE_SHIM_COMMANDS[manager]
        posix_path = shim_dir / command
        windows_path = shim_dir / f"{command}.cmd"
        content = _build_package_manager_python_shim(context, command)
        posix_path.write_text(content, encoding="utf-8")
        posix_path.chmod(posix_path.stat().st_mode | 0o755)
        windows_path.write_text(_build_windows_script(posix_path), encoding="utf-8")
        content_hashes[manager] = build_shim_content_hash(posix_path.read_bytes())
        installed.append(manager)
    manifest_payload = {
        "content_hashes": content_hashes,
        "installed_managers": list(tracked_managers),
        "last_test_at": last_test_at,
        "shim_dir": str(shim_dir),
    }
    _write_package_shim_manifest(context, manifest_payload)
    program_name = _command_program_name()
    shell_hints = _path_export_hints(shim_dir)
    path_repair_required = [
        manager
        for manager in tracked_managers
        if not bool(get_path_order_status(context, manager=manager).get("shim_precedes_real"))
    ]
    return {
        "installed_managers": list(tracked_managers),
        "installed_count": len(tracked_managers),
        "installed_now": installed,
        "installed_now_count": len(installed),
        "shim_dir": str(shim_dir),
        "manifest_path": str(_package_shim_manifest_path(context)),
        "path_export_hint": _path_export_hint(shim_dir),
        "path_repair_required": path_repair_required,
        "restart_shell_required": bool(path_repair_required),
        "shell_hints": shell_hints,
        "status_command": f"{program_name} package-shims status --json",
        "uninstall_command": f"{program_name} package-shims uninstall --json",
    }


def activate_package_shims(
    context: HarnessContext,
    *,
    managers: tuple[str, ...] | None = None,
    repair: bool = False,
) -> dict[str, object]:
    result = (
        repair_package_shims(context, managers=managers)
        if repair
        else install_package_shims(context, managers=managers)
    )
    profile = ensure_package_shim_path_in_shell_profile(context)
    status = package_shim_status(context)
    return {
        **result,
        "activation_state": status["path_status"],
        "package_shims": status,
        "profile": profile,
        "restart_shell_required": bool(status["restart_shell_required"]),
    }


def package_shim_status(context: HarnessContext) -> dict[str, object]:
    manifest = _load_package_shim_manifest(context)
    installed_managers = [
        manager
        for manager in manifest.get("installed_managers", [])
        if isinstance(manager, str) and manager in _PACKAGE_SHIM_COMMANDS
    ]
    last_test_at = manifest.get("last_test_at", {})
    normalized_last_tests = last_test_at if isinstance(last_test_at, dict) else {}
    detected_managers, undetected_managers = _detect_system_package_managers(context)
    detected_set = set(detected_managers)
    shim_dir = context.guard_home / "package-shims" / "bin"
    stored_hashes: dict[str, str] = manifest.get("content_hashes", {})
    active_managers: list[str] = []
    protected_managers: list[str] = []
    missing_managers: list[str] = []
    bypasses: list[dict[str, str]] = []
    manager_details: list[dict[str, object]] = []
    path_entries = [entry for entry in os.environ.get("PATH", "").split(os.pathsep) if entry]
    path_contains_shim_dir = any(Path(entry).expanduser() == shim_dir.expanduser() for entry in path_entries)
    for manager in installed_managers:
        command = _PACKAGE_SHIM_COMMANDS[manager]
        shim_path = shim_dir / command
        exists = shim_path.exists()
        path_status = get_path_order_status(context, manager=manager)
        if exists:
            active_managers.append(manager)
            current_content = shim_path.read_bytes()
            current_hash = build_shim_content_hash(current_content)
            stored_hash = stored_hashes.get(manager)
            expected_content = _build_package_manager_python_shim(context, command).encode("utf-8")
            expected_hash = build_shim_content_hash(expected_content)
            if current_hash == expected_hash or _normalized_package_shim_content(
                current_content
            ) == _normalized_package_shim_content(expected_content):
                integrity = "ok"
            elif stored_hash == current_hash:
                integrity = "stale"
            elif stored_hash is None:
                integrity = "unknown"
            else:
                integrity = "tampered"
        else:
            missing_managers.append(manager)
            integrity = "missing"
        manager_details.append(
            {
                "integrity": integrity,
                "last_test_at": normalized_last_tests.get(manager),
                "manager": manager,
                "path_active": bool(path_status.get("shim_precedes_real")),
                "path_index": path_status.get("shim_path_index"),
                "path_status": path_status,
                "real_binary_found": bool(path_status.get("real_binary_found")),
                "real_binary_path": path_status.get("real_binary_path"),
                "real_binary_path_index": path_status.get("real_binary_path_index"),
                "shim_path": str(shim_path),
                "system_binary_detected": manager in detected_set,
            }
        )
        if exists and bool(path_status.get("shim_precedes_real")):
            protected_managers.append(manager)
        elif exists:
            bypasses.append(
                {
                    "manager": manager,
                    "reason": "path_inactive",
                }
            )
    profile_status = _package_shim_profile_status(context)
    activation_path_status = _package_shim_activation_path_status(
        installed_managers=installed_managers,
        path_contains_shim_dir=path_contains_shim_dir,
        shell_profile_configured=bool(profile_status["shell_profile_configured"]),
    )
    return enrich_package_shim_status_payload(
        {
            "active_managers": active_managers,
            "detected_managers": detected_managers,
            "installed_managers": installed_managers,
            "last_test_at": normalized_last_tests,
            "protected_managers": protected_managers,
            "path_active": bool(installed_managers) and len(protected_managers) == len(installed_managers),
            "path_contains_shim_dir": path_contains_shim_dir,
            "path_status": activation_path_status,
            "bypasses": bypasses,
            "manager_details": manager_details,
            "manifest_path": str(_package_shim_manifest_path(context)),
            "missing_managers": missing_managers,
            "restart_shell_required": activation_path_status == "restart_required",
            "shell_profile_configured": bool(profile_status["shell_profile_configured"]),
            "shell_profile_path": profile_status["shell_profile_path"],
            "shell_hints": _path_export_hints(shim_dir),
            "shim_dir": str(shim_dir),
            "supported_managers": list(package_shim_supported_managers()),
            "undetected_managers": undetected_managers,
        },
        manifest,
    )


def package_shim_cloud_coverage(
    context: HarnessContext,
    *,
    generated_at: str | None = None,
) -> dict[str, object]:
    status = package_shim_status(context)
    return {
        "generatedAt": generated_at or datetime.now(timezone.utc).isoformat(),
        "configuredManagers": list(status["installed_managers"]),
        "protectedManagers": list(status["protected_managers"]),
        "missingManagers": list(status["missing_managers"]),
        "pathActive": bool(status["path_active"]),
        "bypasses": list(status["bypasses"]),
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
        manifest_hashes = manifest.get("content_hashes")
        content_hashes = {
            manager: hash_value
            for manager, hash_value in (manifest_hashes.items() if isinstance(manifest_hashes, dict) else ())
            if manager in remaining and isinstance(hash_value, str)
        }
        manifest_last_tests = manifest.get("last_test_at", {})
        last_test_at = {
            manager: timestamp
            for manager, timestamp in (manifest_last_tests.items() if isinstance(manifest_last_tests, dict) else ())
            if manager in remaining and isinstance(timestamp, str)
        }
        _write_package_shim_manifest(
            context,
            {
                "content_hashes": content_hashes,
                "installed_managers": remaining,
                "last_test_at": last_test_at,
                "shim_dir": str(shim_dir),
            },
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


def package_shim_supported_managers() -> tuple[str, ...]:
    return tuple(sorted(_PACKAGE_SHIM_COMMANDS.keys()))


def repair_package_shims(
    context: HarnessContext,
    *,
    managers: tuple[str, ...] | None = None,
) -> dict[str, object]:
    """Detect missing or tampered shims and reinstall them. Returns repair summary."""
    status = package_shim_status(context)
    selected_managers = set(_normalize_package_shim_managers(managers)) if managers else None
    managers_to_repair: list[str] = []
    path_repair_required: list[str] = []
    for detail in status.get("manager_details", []):
        if not isinstance(detail, dict):
            continue
        manager = detail.get("manager")
        if not isinstance(manager, str):
            continue
        if selected_managers is not None and manager not in selected_managers:
            continue
        if detail.get("integrity") in ("missing", "stale", "tampered"):
            managers_to_repair.append(manager)
        elif not bool(detail.get("path_active")):
            path_repair_required.append(manager)
    if not managers_to_repair:
        return {
            "repaired": [],
            "repaired_count": 0,
            "already_ok": status.get("installed_managers", []),
            "path_repair_required": path_repair_required,
            "shell_hints": status.get("shell_hints", {}),
            "nothing_to_repair": True,
        }
    result = install_package_shims(context, managers=tuple(managers_to_repair))
    return {
        "repaired": managers_to_repair,
        "repaired_count": len(managers_to_repair),
        "path_repair_required": path_repair_required,
        "shell_hints": status.get("shell_hints", {}),
        "install_result": result,
    }


def ensure_guard_shim_path_in_shell_profile(context: HarnessContext) -> dict[str, object]:
    """Prepend the harness launcher shim dir in the user's normal shell profile."""

    shim_dir = context.guard_home / "bin"
    if os.name == "nt":
        return {
            "changed": False,
            "profile_path": None,
            "shim_dir": str(shim_dir),
            "restart_shell_required": False,
            "manual_path_required": True,
        }
    profile_path, export_line = _guard_shim_profile_target(context.home_dir, shim_dir)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    existing = profile_path.read_text(encoding="utf-8") if profile_path.exists() else ""
    if _profile_already_references_path(existing, shim_dir):
        return {
            "changed": False,
            "profile_path": str(profile_path),
            "shim_dir": str(shim_dir),
            "restart_shell_required": True,
        }
    prefix = "" if existing == "" or existing.endswith("\n") else "\n"
    profile_path.write_text(f"{existing}{prefix}{export_line}\n", encoding="utf-8")
    return {
        "changed": True,
        "profile_path": str(profile_path),
        "shim_dir": str(shim_dir),
        "restart_shell_required": True,
    }


def ensure_package_shim_path_in_shell_profile(context: HarnessContext) -> dict[str, object]:
    """Prepend the package shim dir in the user's normal shell profile."""

    shim_dir = context.guard_home / "package-shims" / "bin"
    profile_path, export_line = _package_shim_profile_target(context.home_dir, shim_dir)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    existing = profile_path.read_text(encoding="utf-8") if profile_path.exists() else ""
    if _profile_already_references_path(existing, shim_dir):
        return {
            "changed": False,
            "profile_path": str(profile_path),
            "shim_dir": str(shim_dir),
            "restart_shell_required": True,
        }
    prefix = "" if existing == "" or existing.endswith("\n") else "\n"
    profile_path.write_text(f"{existing}{prefix}{export_line}\n", encoding="utf-8")
    return {
        "changed": True,
        "profile_path": str(profile_path),
        "shim_dir": str(shim_dir),
        "restart_shell_required": True,
    }


def _guard_shim_profile_target(home_dir: Path, shim_dir: Path) -> tuple[Path, str]:
    shell = Path(os.environ.get("SHELL", "")).name
    marker = "# HOL Guard harness launchers"
    if shell == "fish":
        return (
            home_dir / ".config" / "fish" / "config.fish",
            f"{marker}\nfish_add_path --prepend {shim_dir}",
        )
    if shell == "bash":
        return (
            home_dir / ".bashrc",
            f'{marker}\nexport PATH="{shim_dir}:$PATH"',
        )
    return (
        home_dir / ".zshrc",
        f'{marker}\nexport PATH="{shim_dir}:$PATH"',
    )


def _package_shim_profile_target(home_dir: Path, shim_dir: Path) -> tuple[Path, str]:
    shell = Path(os.environ.get("SHELL", "")).name
    marker = "# HOL Guard package manager shims"
    if shell == "fish":
        return (
            home_dir / ".config" / "fish" / "config.fish",
            f"{marker}\nfish_add_path --prepend {shim_dir}",
        )
    if shell == "bash":
        return (
            home_dir / ".bashrc",
            f'{marker}\nexport PATH="{shim_dir}:$PATH"',
        )
    return (
        home_dir / ".zshrc",
        f'{marker}\nexport PATH="{shim_dir}:$PATH"',
    )


def _profile_already_references_path(content: str, shim_dir: Path) -> bool:
    shim_text = str(shim_dir)
    return any(
        (shim_text in line and "PATH" in line) or (shim_text in line and "fish_add_path" in line)
        for line in content.splitlines()
    )


def _build_package_manager_python_shim(context: HarnessContext, command: str) -> str:
    workspace_args: list[str] = []
    if context.workspace_dir is not None:
        workspace_args = ["--workspace", str(context.workspace_dir)]
    shim_dir = context.guard_home / "package-shims" / "bin"
    command_args = [
        sys.executable,
        *_trusted_python_flags(),
        "-c",
        _TRUSTED_CLI_LAUNCHER,
        str(_trusted_import_root()),
        "codex_plugin_scanner.cli",
        "guard",
        "protect",
        "--package-shim-ui",
        "--dry-run",
        "--guard-home",
        str(context.guard_home),
        *_home_override_args(context),
        *workspace_args,
    ]
    return "\n".join(
        (
            f"#!{sys.executable}",
            "from __future__ import annotations",
            "import os",
            "import shutil",
            "import subprocess",
            "import sys",
            f"base_command = {command_args!r}",
            f"command_name = {command!r}",
            f"guard_cwd = {str(_trusted_import_root())!r}",
            f"guard_has_explicit_workspace = {context.workspace_dir is not None!r}",
            f"shim_dir = {str(shim_dir.resolve())!r}",
            "guard_env = dict(os.environ)",
            "guard_env.pop('PYTHONPATH', None)",
            "guard_command = [*base_command, command_name]",
            f"if os.environ.get({SHIM_PROBE_ENV_VAR!r}) == {SHIM_PROBE_ENV_VALUE!r}:",
            "    guard_command = [*base_command, '--json', command_name]",
            "guard_kwargs = {'capture_output': True, 'text': True, 'env': guard_env}",
            "if guard_has_explicit_workspace:",
            "    guard_kwargs['cwd'] = guard_cwd",
            "guard_process = subprocess.run([*guard_command, *sys.argv[1:]], **guard_kwargs)",
            "if guard_process.stdout:",
            "    sys.stdout.write(guard_process.stdout)",
            "if guard_process.stderr:",
            "    sys.stderr.write(guard_process.stderr)",
            "if guard_process.returncode != 0:",
            "    raise SystemExit(guard_process.returncode)",
            f"if os.environ.get({SHIM_PROBE_ENV_VAR!r}) == {SHIM_PROBE_ENV_VALUE!r}:",
            "    raise SystemExit(0)",
            "path_entries = [entry for entry in os.environ.get('PATH', '').split(os.pathsep) if entry]",
            "shim_dir_abs = os.path.abspath(shim_dir)",
            "filtered_entries = [entry for entry in path_entries if os.path.abspath(entry) != shim_dir_abs]",
            "filtered_path = os.pathsep.join(filtered_entries)",
            "resolved_command = shutil.which(command_name, path=filtered_path)",
            "if resolved_command is None:",
            "    sys.stderr.write(f'Unable to locate real {command_name} binary on PATH\\n')",
            "    raise SystemExit(127)",
            "manager_env = dict(os.environ)",
            "manager_env['PATH'] = filtered_path",
            "raise SystemExit(subprocess.call([resolved_command, *sys.argv[1:]], env=manager_env))",
            "",
        )
    )


def _trusted_python_flags() -> list[str]:
    flags = ["-I"]
    if tuple(sys.version_info[:2]) >= (3, 11):
        flags.append("-P")
    return flags


def _normalize_package_shim_managers(managers: tuple[str, ...] | None) -> tuple[str, ...]:
    if managers is None or len(managers) == 0:
        return tuple(sorted(_PACKAGE_SHIM_COMMANDS.keys()))
    normalized = []
    for manager in managers:
        key = manager.strip().lower()
        if key in _PACKAGE_SHIM_COMMANDS and key not in normalized:
            normalized.append(key)
    return tuple(normalized)


def _trusted_import_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _package_shim_manifest_path(context: HarnessContext) -> Path:
    return context.guard_home / "package-shims" / _PACKAGE_SHIM_MANIFEST


def _filtered_manager_path(context: HarnessContext) -> str:
    shim_dir = context.guard_home / "package-shims" / "bin"
    shim_dir_abs = os.path.abspath(os.path.expanduser(str(shim_dir)))
    path_entries = [entry for entry in os.environ.get("PATH", "").split(os.pathsep) if entry]
    filtered_entries = [entry for entry in path_entries if os.path.abspath(os.path.expanduser(entry)) != shim_dir_abs]
    return os.pathsep.join(filtered_entries)


def _detect_system_package_managers(context: HarnessContext) -> tuple[list[str], list[str]]:
    """Return supported managers with and without a real binary on PATH."""

    filtered_path = _filtered_manager_path(context)
    if filtered_path == "":
        return [], list(package_shim_supported_managers())
    detected: list[str] = []
    undetected: list[str] = []
    for manager in package_shim_supported_managers():
        command = _PACKAGE_SHIM_COMMANDS[manager]
        resolved = shutil.which(command, path=filtered_path)
        if resolved is not None:
            detected.append(manager)
        else:
            undetected.append(manager)
    return detected, undetected


def _load_package_shim_manifest(context: HarnessContext) -> dict[str, object]:
    manifest_path = _package_shim_manifest_path(context)
    if not manifest_path.exists():
        return {}
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_package_shim_manifest(context: HarnessContext, payload: dict[str, object]) -> None:
    _package_shim_manifest_path(context).write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _record_package_shim_test_results(
    context: HarnessContext,
    manager_results: list[dict[str, object]],
    *,
    tested_at: str | None = None,
) -> None:
    manifest = _load_package_shim_manifest(context)
    last_test_at = manifest.get("last_test_at")
    normalized_last_tests = dict(last_test_at) if isinstance(last_test_at, dict) else {}
    timestamp = tested_at or datetime.now(timezone.utc).isoformat()
    for result in manager_results:
        manager = result.get("manager")
        if isinstance(manager, str):
            normalized_last_tests[manager] = timestamp
    manifest["last_test_at"] = normalized_last_tests
    _write_package_shim_manifest(context, manifest)


def _command_program_name() -> str:
    if not sys.argv:
        return "hol-guard"
    candidate = Path(sys.argv[0]).name.strip()
    return candidate or "hol-guard"


def _path_export_hint(shim_dir: Path) -> str:
    if os.name == "nt":
        return f"set PATH={shim_dir};%PATH%"
    return f'export PATH="{shim_dir}:$PATH"'


def _path_export_hints(shim_dir: Path) -> dict[str, str]:
    posix_hint = f'export PATH="{shim_dir}:$PATH"'
    return {
        "bash": posix_hint,
        "zsh": posix_hint,
        "fish": f"fish_add_path --prepend {shim_dir}",
        "powershell": f'$env:Path = "{shim_dir};$env:Path"',
    }


def probe_package_shim_intercepts(
    context: HarnessContext,
    *,
    managers: tuple[str, ...] | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    """Execute installed package-manager shims to prove intercept wiring is live."""

    status = package_shim_status(context)
    installed = {str(manager) for manager in status.get("installed_managers", []) if isinstance(manager, str)}
    protected = {str(manager) for manager in status.get("protected_managers", []) if isinstance(manager, str)}
    tested_managers = list(managers or tuple(sorted(installed)))
    path_repair_required = [manager for manager in tested_managers if manager in installed and manager not in protected]
    manager_results: list[dict[str, object]] = []
    manager_details = status.get("manager_details", [])
    detail_by_manager = {
        str(item.get("manager")): item
        for item in manager_details
        if isinstance(item, dict) and isinstance(item.get("manager"), str)
    }
    target_workspace = workspace_dir or context.workspace_dir or context.home_dir
    shim_dir = context.guard_home / "package-shims" / "bin"
    for manager in tested_managers:
        if manager not in installed:
            continue
        manager_detail = detail_by_manager.get(manager)
        if manager_detail is not None and manager_detail.get("integrity") == "tampered":
            manager_results.append(
                {
                    "evaluator_invoked": False,
                    "intercept_ran": False,
                    "manager": manager,
                    "skipped_reason": "shim_tampered",
                },
            )
            continue
        if manager not in protected:
            manager_results.append(
                {
                    "evaluator_invoked": False,
                    "intercept_ran": False,
                    "manager": manager,
                    "skipped_reason": "path_inactive",
                },
            )
            continue
        command = _PACKAGE_SHIM_COMMANDS.get(manager)
        if command is None:
            manager_results.append(
                {
                    "evaluator_invoked": False,
                    "intercept_ran": False,
                    "manager": manager,
                    "skipped_reason": "unsupported_manager",
                },
            )
            continue
        shim_path = shim_dir / command
        if not shim_path.exists():
            manager_results.append(
                {
                    "evaluator_invoked": False,
                    "intercept_ran": False,
                    "manager": manager,
                    "skipped_reason": "shim_missing",
                },
            )
            continue
        probe_args = package_shim_probe_args(manager)
        probe_env = dict(os.environ)
        probe_env[SHIM_PROBE_ENV_VAR] = SHIM_PROBE_ENV_VALUE
        try:
            # codeql[py/path-injection] target_workspace is home_dir or a validated daemon workspace_dir.
            result = subprocess.run(
                [str(shim_path), *probe_args],
                capture_output=True,
                check=False,
                cwd=target_workspace,
                env=probe_env,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError):
            manager_results.append(
                {
                    "evaluator_invoked": False,
                    "intercept_ran": False,
                    "manager": manager,
                    "skipped_reason": "probe_failed",
                },
            )
            continue
        protect_payload = parse_protect_json_stdout(result.stdout)
        evaluator_evidence = protect_evaluator_evidence(protect_payload)
        command_hash = stable_digest_hex(
            json.dumps([manager, *probe_args]).encode("utf-8"),
        )
        manager_results.append(
            {
                "command_hash": command_hash,
                "evaluator_invoked": evaluator_evidence["evaluator_invoked"],
                "evaluator_source": evaluator_evidence["evaluator_source"],
                "evidence_ids": evaluator_evidence["evidence_ids"],
                "intercept_ran": bool(evaluator_evidence["evaluator_invoked"]),
                "manager": manager,
                "protect_decision": evaluator_evidence["protect_decision"],
                "probe_args": list(probe_args),
                "shim_exit_code": result.returncode,
            },
        )
    intercept_proved = any(bool(result.get("evaluator_invoked")) for result in manager_results)
    if manager_results:
        _record_package_shim_test_results(context, manager_results)
    return {
        "blocked_execution": bool(tested_managers) and all(manager in protected for manager in tested_managers),
        "intercept_proved": intercept_proved,
        "manager_results": manager_results,
        "missing_managers": [manager for manager in tested_managers if manager not in installed],
        "package_shims": status,
        "path_repair_required": path_repair_required,
        "tested_managers": tested_managers,
    }


__all__ = [
    "activate_package_shims",
    "ensure_guard_shim_path_in_shell_profile",
    "ensure_package_shim_path_in_shell_profile",
    "install_guard_shim",
    "install_package_shims",
    "package_shim_cloud_coverage",
    "package_shim_status",
    "package_shim_supported_managers",
    "probe_package_shim_intercepts",
    "remove_guard_shim",
    "uninstall_package_shims",
]
