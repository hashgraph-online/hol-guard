"""Local launcher shims for Guard-managed harness execution."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .durable_harness_launcher import build_harness_shim, build_windows_script
from .launcher import merge_guard_launcher_env
from .package_shim_frozen import (
    FROZEN_PACKAGE_SHIM_SENTINEL,
    classify_installed_package_shim_integrity,
    frozen_package_shim_python_path,
    installed_package_shim_attestation_bytes,
    normalized_package_shim_content,
    package_shim_interpreter,
    resolve_frozen_package_shim_path,
    run_frozen_package_shim,
    write_package_manager_shim_files,
)
from .package_shim_status import enrich_package_shim_status_payload
from .shim_probe import (
    SHIM_PROBE_ENV_VALUE,
    SHIM_PROBE_ENV_VAR,
    package_shim_probe_args,
    parse_protect_json_stdout,
    protect_evaluator_evidence,
)
from .sqlite_tuning import SQLITE_CONNECT_TIMEOUT_SECONDS
from .stable_digest import stable_digest_hex


class HarnessContextLike(Protocol):
    @property
    def home_dir(self) -> Path: ...

    @property
    def workspace_dir(self) -> Path | None: ...

    @property
    def guard_home(self) -> Path: ...


HarnessContext = HarnessContextLike

_PACKAGE_SHIM_COMMANDS = {
    "brew": "brew",
    "bun": "bun",
    "bunx": "bunx",
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
_LOCAL_TEST_RUNNER_COMMANDS = frozenset({"jest", "mocha", "vitest"})
_GUARD_PROFILE_MARKER = "# HOL Guard harness launchers"
_PACKAGE_PROFILE_MARKER = "# HOL Guard package manager shims"
_PACKAGE_SHIM_PROBE_TIMEOUT_SECONDS = int(SQLITE_CONNECT_TIMEOUT_SECONDS) + 5
# Path fragments that indicate a shim dir lives in an ephemeral location (a test
# temp dir, the system temp root, etc.). Such paths must never be written into a
# long-lived shell profile: they vanish and leave broken PATH entries behind.
# Kept POSIX-only because the profile writers short-circuit on Windows
# (os.name == "nt") before the transient check can run.
_TRANSIENT_PATH_FRAGMENTS = (
    "/var/folders/",
    "/private/var/folders/",
    "/tmp/",
    "/private/tmp/",
    "/temp/",
    "pytest-of-",
)
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
    context: HarnessContextLike,
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
    context: HarnessContextLike,
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


def _build_python_shim(harness: str, context: HarnessContextLike, workspace_args: list[str]) -> str:
    return build_harness_shim(
        sys.executable,
        harness,
        context,
        workspace_args,
        trusted_python_flags=_trusted_python_flags(),
        trusted_launcher=_TRUSTED_CLI_LAUNCHER,
        trusted_import_root=_trusted_import_root(),
        launcher_env=merge_guard_launcher_env(),
        home_override_args=_home_override_args(context),
        is_transient_path=_is_transient_path,
    )


def _build_windows_script(posix_path: Path) -> str:
    return build_windows_script(package_shim_interpreter(), posix_path)


def _write_package_manager_shim_files(context: HarnessContext, command: str, shim_dir: Path) -> Path:
    return write_package_manager_shim_files(
        shim_dir=shim_dir,
        command=command,
        python_source=_build_package_manager_python_shim(context, command),
        windows_script=_build_windows_script,
    )


def _home_override_args(context: HarnessContextLike) -> list[str]:
    if not context.home_dir:
        return []
    if not bool(getattr(context, "home_override_explicit", False)) and (
        context.home_dir.resolve() == Path.home().resolve()
    ):
        return []
    return ["--home", str(context.home_dir)]


def build_shim_content_hash(content: bytes) -> str:
    """Return hex SHA-256 of shim content bytes."""
    return hashlib.sha256(content).hexdigest()


def _normalized_package_shim_content(content: bytes) -> str:
    return normalized_package_shim_content(content)


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
    effective_path = path_env if path_env is not None else os.environ.get("PATH", "")
    path_dirs = effective_path.split(os.pathsep)
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
            "shell_profile_paths": [],
            "shell_profile_missing_paths": [],
        }
    targets = _package_shim_profile_targets(home_dir, shim_dir)
    configured_paths: list[str] = []
    missing_paths: list[str] = []
    for profile_path, _export_line in targets:
        try:
            existing = profile_path.read_text(encoding="utf-8") if profile_path.exists() else ""
        except OSError:
            existing = ""
        if _profile_already_references_path(existing, shim_dir):
            configured_paths.append(str(profile_path))
        else:
            missing_paths.append(str(profile_path))
    primary_path = str(targets[0][0]) if targets else None
    return {
        "shell_profile_configured": bool(targets) and not missing_paths,
        "shell_profile_path": primary_path,
        "shell_profile_paths": configured_paths,
        "shell_profile_missing_paths": missing_paths,
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
    path_env: str | None = None,
) -> dict[str, object]:
    shim_root = context.guard_home / "package-shims"
    shim_dir = shim_root / "bin"
    shim_dir.mkdir(parents=True, exist_ok=True)
    normalized_managers = _normalize_package_shim_managers(managers)
    existing_manifest = _load_package_shim_manifest(context)
    existing_managers = tuple(
        manager
        for manager in _string_items(existing_manifest.get("installed_managers"))
        if manager in _PACKAGE_SHIM_COMMANDS
    )
    tracked_managers = tuple(dict.fromkeys([*existing_managers, *normalized_managers]))
    existing_hashes = _string_map(existing_manifest.get("content_hashes"))
    last_test_at = dict(_string_map(existing_manifest.get("last_test_at")))
    installed: list[str] = []
    content_hashes: dict[str, str] = dict(existing_hashes)
    for manager in normalized_managers:
        command = _PACKAGE_SHIM_COMMANDS[manager]
        posix_path = _write_package_manager_shim_files(context, command, shim_dir)
        content_hashes[manager] = build_shim_content_hash(
            installed_package_shim_attestation_bytes(shim_dir, command, posix_path.read_bytes())
        )
        installed.append(manager)
    manifest_payload: dict[str, object] = {
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
        if not bool(get_path_order_status(context, manager=manager, path_env=path_env).get("shim_precedes_real"))
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


def package_shim_status(context: HarnessContext, *, path_env: str | None = None) -> dict[str, object]:
    manifest, manifest_state = _load_package_shim_manifest_with_state(context)
    installed_managers = [
        manager for manager in _string_items(manifest.get("installed_managers")) if manager in _PACKAGE_SHIM_COMMANDS
    ]
    last_test_at = manifest.get("last_test_at", {})
    normalized_last_tests = last_test_at if isinstance(last_test_at, dict) else {}
    detected_managers, undetected_managers = _detect_system_package_managers(context, path_env=path_env)
    detected_set = set(detected_managers)
    shim_dir = context.guard_home / "package-shims" / "bin"
    stored_hashes = _string_map(manifest.get("content_hashes"))
    active_managers: list[str] = []
    protected_managers: list[str] = []
    missing_managers: list[str] = []
    bypasses: list[dict[str, str]] = []
    manager_details: list[dict[str, object]] = []
    effective_path = path_env if path_env is not None else os.environ.get("PATH", "")
    path_entries = [entry for entry in effective_path.split(os.pathsep) if entry]
    resolved_shim_dir = shim_dir.expanduser().resolve()
    path_contains_shim_dir = any(Path(entry).expanduser().resolve() == resolved_shim_dir for entry in path_entries)
    for manager in installed_managers:
        command = _PACKAGE_SHIM_COMMANDS[manager]
        shim_path = shim_dir / command
        exists = shim_path.exists()
        path_status = get_path_order_status(context, manager=manager, path_env=path_env)
        if exists:
            active_managers.append(manager)
            python_source = _build_package_manager_python_shim(context, command)
            integrity = classify_installed_package_shim_integrity(
                python_source=python_source,
                shim_dir=shim_dir,
                command=command,
                installed_wrapper=shim_path.read_bytes(),
                stored_hash=stored_hashes.get(manager),
                hash_content=build_shim_content_hash,
            )
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
            bypass_reason = "foreign_shim_bypass" if bool(path_status.get("foreign_shim_bypass")) else "path_inactive"
            bypasses.append(
                {
                    "manager": manager,
                    "reason": bypass_reason,
                }
            )
    profile_status = _package_shim_profile_status(context)
    path_active = bool(installed_managers) and len(protected_managers) == len(installed_managers)
    activation_path_status = _package_shim_activation_path_status(
        installed_managers=installed_managers,
        path_contains_shim_dir=path_contains_shim_dir,
        shell_profile_configured=bool(profile_status["shell_profile_configured"]),
    )
    process_path_status = "missing"
    if path_contains_shim_dir:
        process_path_status = "active"
    elif activation_path_status == "restart_required":
        process_path_status = "profile_staged"
    return enrich_package_shim_status_payload(
        {
            "active_managers": active_managers,
            "detected_managers": detected_managers,
            "installed_managers": installed_managers,
            "last_test_at": normalized_last_tests,
            "protected_managers": protected_managers,
            "path_active": path_active,
            "path_contains_shim_dir": path_contains_shim_dir,
            "path_status": activation_path_status,
            "bypasses": bypasses,
            "manager_details": manager_details,
            "manifest_state": manifest_state,
            "manifest_path": str(_package_shim_manifest_path(context)),
            "missing_managers": missing_managers,
            "restart_shell_required": activation_path_status == "restart_required",
            "process_path_status": process_path_status,
            "process_restart_required": activation_path_status == "restart_required",
            "shell_profile_configured": bool(profile_status["shell_profile_configured"]),
            "shell_profile_path": profile_status["shell_profile_path"],
            "shell_profile_paths": profile_status["shell_profile_paths"],
            "shell_profile_missing_paths": profile_status["shell_profile_missing_paths"],
            "shell_hints": _path_export_hints(shim_dir),
            "shim_dir": str(shim_dir),
            "supported_managers": list(package_shim_supported_managers()),
            "undetected_managers": undetected_managers,
        },
        manifest,
    )


def package_shim_dashboard_status(context: HarnessContext) -> dict[str, object]:
    """Project persistent shell activation instead of the daemon's inherited PATH.

    The resident daemon does not source interactive shell profiles. Treating its
    process PATH as the user's shell PATH leaves the dashboard permanently stuck
    on "restart required" even after a new login. The dashboard may regard the
    setup as active when every installed shim is intact and all managed profiles
    still contain the Guard PATH block. Raw CLI status continues to report the
    calling process PATH unchanged.
    """

    status = package_shim_status(context)
    if status.get("path_status") != "restart_required" or not status.get("shell_profile_configured"):
        return status
    installed_managers = _string_items(status.get("installed_managers"))
    if not installed_managers or status.get("missing_managers"):
        return status
    details = _dict_items(status.get("manager_details"))
    detail_by_manager = {
        str(detail.get("manager")): detail for detail in details if isinstance(detail.get("manager"), str)
    }
    if any(detail_by_manager.get(manager, {}).get("integrity") != "ok" for manager in installed_managers):
        return status

    projected_details: list[dict[str, object]] = []
    for detail in details:
        manager = detail.get("manager")
        if manager not in installed_managers:
            projected_details.append(detail)
            continue
        path_detail = detail.get("path_status")
        projected_path_detail = (
            {
                **path_detail,
                "path_broken": False,
                "shim_in_path": True,
                "shim_precedes_real": True,
                "shim_path_index": None,
                "real_binary_path_index": None,
                "foreign_shim_bypass": False,
                "foreign_shim_path_index": None,
            }
            if isinstance(path_detail, dict)
            else path_detail
        )
        projected_details.append(
            {
                **detail,
                "path_active": True,
                "path_status": projected_path_detail,
            }
        )
    return {
        **status,
        "bypasses": [],
        "manager_details": projected_details,
        "path_active": True,
        "path_broken_managers": [],
        "pathBrokenManagers": [],
        "path_contains_shim_dir": True,
        "path_status": "in_path",
        "protected_managers": list(installed_managers),
        "protectedManagers": list(installed_managers),
        "restart_shell_required": False,
    }


def package_shim_cloud_coverage(
    context: HarnessContext,
    *,
    generated_at: str | None = None,
) -> dict[str, object]:
    status = package_shim_status(context)
    return {
        "generatedAt": generated_at or datetime.now(timezone.utc).isoformat(),
        "configuredManagers": list(_string_items(status.get("installed_managers"))),
        "protectedManagers": list(_string_items(status.get("protected_managers"))),
        "missingManagers": list(_string_items(status.get("missing_managers"))),
        "pathActive": bool(status["path_active"]),
        "bypasses": list(_dict_items(status.get("bypasses"))),
    }


def uninstall_package_shims(
    context: HarnessContext,
    *,
    managers: tuple[str, ...] | None = None,
) -> dict[str, object]:
    manifest = _load_package_shim_manifest(context)
    manifest_managers = tuple(
        manager for manager in _string_items(manifest.get("installed_managers")) if manager in _PACKAGE_SHIM_COMMANDS
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
        sidecar = frozen_package_shim_python_path(shim_dir, command)
        if sidecar.exists():
            sidecar.unlink()
            removed_paths.append(str(sidecar))
    remaining = [manager for manager in manifest_managers if manager not in requested_managers]
    manifest_path = _package_shim_manifest_path(context)
    if remaining:
        manifest_hashes = _string_map(manifest.get("content_hashes"))
        content_hashes = {
            manager: hash_value for manager, hash_value in manifest_hashes.items() if manager in remaining
        }
        manifest_last_tests = _string_map(manifest.get("last_test_at"))
        last_test_at = {
            manager: timestamp for manager, timestamp in manifest_last_tests.items() if manager in remaining
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
    path_env: str | None = None,
) -> dict[str, object]:
    """Detect missing or tampered shims and reinstall them. Returns repair summary."""
    status = package_shim_status(context, path_env=path_env)
    selected_managers = set(_normalize_package_shim_managers(managers)) if managers else None
    managers_to_repair: list[str] = []
    path_repair_required: list[str] = []
    for detail in _dict_items(status.get("manager_details")):
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
    result = install_package_shims(context, managers=tuple(managers_to_repair), path_env=path_env)
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
    if _is_transient_path(shim_dir):
        return {
            "changed": False,
            "profile_path": None,
            "shim_dir": str(shim_dir),
            "restart_shell_required": False,
            "manual_path_required": True,
        }
    profile_path, export_line = _guard_shim_profile_target(context.home_dir, shim_dir)
    result = _upsert_managed_profile_block(profile_path, export_line, _GUARD_PROFILE_MARKER)
    return {
        "changed": result["changed"],
        "profile_path": str(profile_path),
        "shim_dir": str(shim_dir),
        "restart_shell_required": True,
    }


def ensure_package_shim_path_in_shell_profile(context: HarnessContext) -> dict[str, object]:
    """Prepend the package shim dir in the user's normal shell profile."""

    shim_dir = context.guard_home / "package-shims" / "bin"
    if os.name == "nt":
        return {
            "changed": False,
            "profile_path": None,
            "shim_dir": str(shim_dir),
            "restart_shell_required": False,
            "manual_path_required": True,
        }
    if _is_transient_path(shim_dir):
        return {
            "changed": False,
            "profile_path": None,
            "shim_dir": str(shim_dir),
            "restart_shell_required": False,
            "manual_path_required": True,
        }
    targets = _package_shim_profile_targets(context.home_dir, shim_dir)
    changed_paths: list[str] = []
    for profile_path, export_line in targets:
        result = _upsert_managed_profile_block(profile_path, export_line, _PACKAGE_PROFILE_MARKER)
        if bool(result["changed"]):
            changed_paths.append(str(profile_path))
    return {
        "changed": bool(changed_paths),
        "changed_paths": changed_paths,
        "profile_path": str(targets[0][0]),
        "profile_paths": [str(profile_path) for profile_path, _export_line in targets],
        "shim_dir": str(shim_dir),
        "restart_shell_required": True,
    }


def remove_guard_profile_blocks(context: HarnessContext) -> dict[str, object]:
    """Remove Guard-managed PATH blocks from common interactive shell profiles."""

    from .shell_profile_cleanup import remove_guard_profile_blocks as remove_profile_blocks

    return remove_profile_blocks(
        context,
        strip_managed_marker_blocks=_strip_managed_marker_blocks,
        guard_profile_marker=_GUARD_PROFILE_MARKER,
        package_profile_marker=_PACKAGE_PROFILE_MARKER,
    )


def _upsert_managed_profile_block(
    profile_path: Path,
    export_line: str,
    marker: str,
) -> dict[str, object]:
    """Idempotently write a single Guard-managed block to a shell profile.

    Replaces any existing block tagged with *marker* instead of appending a new
    one each time, so the profile never accumulates stale Guard PATH entries
    (for example, one per pytest temp shim dir). Keeps all other profile
    content untouched. A managed block is exactly two lines: the marker comment
    followed by the export/fish_add_path line.
    """

    profile_path.parent.mkdir(parents=True, exist_ok=True)
    existing = profile_path.read_text(encoding="utf-8") if profile_path.exists() else ""
    export_line = export_line.rstrip("\n")
    marker_line = export_line.split("\n", 1)[0]
    if marker_line.strip() != marker.strip():
        # Defensive: caller always passes a block whose first line is the marker.
        export_line = f"{marker}\n{export_line}"
    desired = f"{export_line}\n"
    if existing == desired:
        return {"changed": False}
    cleaned = _strip_managed_marker_blocks(existing, marker)
    if cleaned == "":
        new_content = desired
    else:
        prefix = "" if cleaned.endswith("\n") else "\n"
        new_content = f"{cleaned}{prefix}{desired}"
    if new_content == existing:
        return {"changed": False}
    profile_path.write_text(new_content, encoding="utf-8")
    return {"changed": True}


def _strip_managed_marker_blocks(content: str, marker: str) -> str:
    """Remove every Guard-managed block tagged with *marker* from *content*.

    A block is the marker line plus the single line that follows it. To avoid
    leaving a gap where a block sat, a single blank line immediately preceding
    or following a removed block is also dropped. Blank-line runs elsewhere in
    the file (user content) are left untouched.
    """

    if not content:
        return ""
    marker_stripped = marker.strip()
    lines = content.splitlines()
    # First pass: locate index ranges [i, i+1] of each marker block.
    drop_indices: set[int] = set()
    for index, line in enumerate(lines):
        if line.strip() == marker_stripped and index + 1 < len(lines):
            drop_indices.add(index)
            drop_indices.add(index + 1)
    if not drop_indices:
        return content if content.endswith("\n") else content + "\n"
    # Second pass: keep lines, swallowing one blank line adjacent to a dropped
    # block so the removal does not leave a stale blank gap.
    keep: list[str] = []
    for index, line in enumerate(lines):
        if index in drop_indices:
            continue
        is_blank = line.strip() == ""
        if is_blank:
            prev_kept_blank_gap = keep and keep[-1].strip() == ""
            # Drop this blank only if both neighbors were removed (i.e. the blank
            # was sandwiched between two removed block lines or sits at the edge
            # of a removal zone).
            prev_dropped = (index - 1) in drop_indices
            next_dropped = (index + 1) in drop_indices
            edge_of_removal = prev_dropped or next_dropped
            if edge_of_removal and not prev_kept_blank_gap:
                continue
        keep.append(line)
    cleaned = "\n".join(keep)
    if cleaned and not cleaned.endswith("\n"):
        cleaned += "\n"
    return cleaned


def _guard_shim_profile_target(home_dir: Path, shim_dir: Path) -> tuple[Path, str]:
    shell = Path(os.environ.get("SHELL", "")).name
    marker = _GUARD_PROFILE_MARKER
    if shell == "fish":
        return (
            home_dir / ".config" / "fish" / "config.fish",
            f"{marker}\n{_fish_path_prepend(shim_dir)}",
        )
    if shell == "bash":
        return (
            home_dir / ".bashrc",
            f"{marker}\n{_posix_path_export(shim_dir)}",
        )
    return (
        home_dir / ".zshrc",
        f"{marker}\n{_posix_path_export(shim_dir)}",
    )


def _package_shim_profile_target(home_dir: Path, shim_dir: Path) -> tuple[Path, str]:
    shell = Path(os.environ.get("SHELL", "")).name
    marker = _PACKAGE_PROFILE_MARKER
    if shell == "fish":
        return (
            home_dir / ".config" / "fish" / "config.fish",
            f"{marker}\n{_fish_path_prepend(shim_dir)}",
        )
    if shell == "bash":
        return (
            home_dir / ".bashrc",
            f"{marker}\n{_posix_path_export(shim_dir)}",
        )
    return (
        home_dir / ".zshrc",
        f"{marker}\n{_posix_path_export(shim_dir)}",
    )


def _package_shim_profile_targets(home_dir: Path, shim_dir: Path) -> tuple[tuple[Path, str], ...]:
    """Return the selected-shell target plus Bash interactive and login targets.

    ``$SHELL`` is the login shell, not necessarily the shell that launches a
    package manager. On Linux a user can have a zsh login shell and run Bash,
    and Bash reads different files for interactive and login sessions. Keep
    the selected shell's normal target, then make the same idempotent export
    available to both Bash startup modes.
    """

    primary = _package_shim_profile_target(home_dir, shim_dir)
    marker = _PACKAGE_PROFILE_MARKER
    bash_export = f"{marker}\n{_posix_path_export(shim_dir)}"
    bash_login_path = _bash_login_profile_path(home_dir)
    candidates = (
        primary,
        (home_dir / ".bashrc", bash_export),
        (bash_login_path, bash_export),
    )
    deduplicated: list[tuple[Path, str]] = []
    seen_paths: set[Path] = set()
    for profile_path, export_line in candidates:
        if profile_path in seen_paths:
            continue
        seen_paths.add(profile_path)
        deduplicated.append((profile_path, export_line))
    return tuple(deduplicated)


def _bash_login_profile_path(home_dir: Path) -> Path:
    """Choose Bash's first existing login profile without changing precedence."""

    for name in (".bash_profile", ".bash_login"):
        candidate = home_dir / name
        if candidate.exists():
            return candidate
    return home_dir / ".profile"


def _posix_path_export(shim_dir: Path) -> str:
    return f"export PATH={shlex.quote(str(shim_dir))}:$PATH"


def _fish_path_prepend(shim_dir: Path) -> str:
    return f"fish_add_path --prepend -- {shlex.quote(str(shim_dir))}"


def _is_transient_path(path: Path) -> bool:
    """Return True when *path* lives in an ephemeral temp/test location.

    Such paths must not be persisted into a user shell profile because they are
    cleaned up, leaving broken PATH entries that shadow the real binaries.
    Besides the known static temp roots, any path under the process's own
    ``TMPDIR``/``TEMP``/``TMP`` is treated as transient so non-standard temp
    roots on Linux or CI cannot bypass the guard.
    """

    text = str(path)
    if any(fragment in text for fragment in _TRANSIENT_PATH_FRAGMENTS):
        return True
    for env_name in ("TMPDIR", "TEMP", "TMP"):
        env_value = os.environ.get(env_name, "").strip()
        if env_value:
            try:
                if path.resolve().is_relative_to(Path(env_value).expanduser().resolve()):
                    return True
            except (OSError, ValueError):
                if text.startswith(env_value):
                    return True
    return False


def _profile_already_references_path(content: str, shim_dir: Path) -> bool:
    shim_text = str(shim_dir)
    expected_lines = {_posix_path_export(shim_dir), _fish_path_prepend(shim_dir)}
    return any(
        line.strip() in expected_lines
        or ((shim_text in line and "PATH" in line) or (shim_text in line and "fish_add_path" in line))
        for line in content.splitlines()
    )


def _package_protect_command_args(context: HarnessContextLike, workspace_args: list[str]) -> list[str]:
    home_dir = context.home_dir
    protect_args = [
        "protect",
        "--package-shim-ui",
        "--guard-home",
        str(context.guard_home),
        *(["--home", str(home_dir)] if home_dir else []),
        *workspace_args,
    ]
    if bool(getattr(sys, "frozen", False)):
        return [package_shim_interpreter(), *protect_args]
    return [
        sys.executable,
        *_trusted_python_flags(),
        "-c",
        _TRUSTED_CLI_LAUNCHER,
        str(_trusted_import_root()),
        "codex_plugin_scanner.cli",
        "guard",
        *protect_args,
    ]


def _build_package_manager_python_shim(context: HarnessContext, command: str) -> str:
    workspace_args: list[str] = []
    if context.workspace_dir is not None:
        workspace_args = ["--workspace", str(context.workspace_dir)]
    shim_dir = context.guard_home / "package-shims" / "bin"
    command_args = _package_protect_command_args(context, workspace_args)
    return "\n".join(
        (
            f"#!{package_shim_interpreter()}",
            "from __future__ import annotations",
            "import os",
            "import shutil",
            "import subprocess",
            "import sys",
            "import time",
            "from pathlib import Path",
            f"{FROZEN_PACKAGE_SHIM_SENTINEL} = True",
            f"base_command = {command_args!r}",
            f"command_name = {command!r}",
            f"guard_cli_cwd = {str(_trusted_import_root())!r}",
            f"guard_workspace = {str(context.workspace_dir) if context.workspace_dir is not None else None!r}",
            f"guard_home = {str(context.guard_home)!r}",
            f"guard_has_explicit_workspace = {context.workspace_dir is not None!r}",
            f"shim_dir = {str(shim_dir.resolve())!r}",
            f"local_test_runners = {tuple(sorted(_LOCAL_TEST_RUNNER_COMMANDS))!r}",
            f"shim_probe = os.environ.get({SHIM_PROBE_ENV_VAR!r}) == {SHIM_PROBE_ENV_VALUE!r}",
            f"store_lock_retry_timeout_seconds = {SQLITE_CONNECT_TIMEOUT_SECONDS!r}",
            "store_lock_retry_delay_seconds = 0.1",
            "def _real_manager_launch():",
            "    path_entries = [entry for entry in os.environ.get('PATH', '').split(os.pathsep) if entry]",
            "    shim_dir_abs = os.path.abspath(shim_dir)",
            "    filtered_entries = [entry for entry in path_entries if os.path.abspath(entry) != shim_dir_abs]",
            "    filtered_path = os.pathsep.join(filtered_entries)",
            "    resolved_command = shutil.which(command_name, path=filtered_path)",
            "    if resolved_command is None:",
            "        sys.stderr.write(f'Unable to locate real {command_name} binary on PATH\\n')",
            "        raise SystemExit(127)",
            "    manager_env = dict(os.environ)",
            "    manager_env['PATH'] = filtered_path",
            "    manager_args = list(sys.argv[1:])",
            "    local_only_flag = {'bunx': '--no-install', 'npx': '--no'}.get(command_name)",
            "    leading_test_runner_flags = (",
            "        {'--bun', '--no-install'} if command_name == 'bunx' else {'--no', '--no-install'}",
            "    )",
            "    runner_index = 0",
            "    while runner_index < len(manager_args) and manager_args[runner_index] in leading_test_runner_flags:",
            "        runner_index += 1",
            "    if (",
            "        local_only_flag is not None",
            "        and runner_index < len(manager_args)",
            "        and manager_args[runner_index] in local_test_runners",
            "        and local_only_flag not in manager_args[:runner_index]",
            "    ):",
            "        manager_args.insert(runner_index, local_only_flag)",
            "    return resolved_command, manager_args, manager_env",
            "def _exec_real_manager():",
            "    resolved_command, manager_args, manager_env = _real_manager_launch()",
            "    if os.name == 'nt':",
            "        try:",
            "            raise SystemExit(subprocess.call([resolved_command, *manager_args], env=manager_env))",
            "        except KeyboardInterrupt:",
            "            raise SystemExit(130)",
            "    os.execvpe(resolved_command, [resolved_command, *manager_args], manager_env)",
            "def _command_guard_requirements():",
            "    if shim_probe:",
            "        return True, False",
            "    cwd = os.path.realpath(os.getcwd())",
            "    normalize = lambda entry: cwd if entry in ('', '.', os.curdir) else os.path.realpath(entry)",
            "    blocked_entries = {cwd, guard_cli_cwd}",
            "    sys.path = [guard_cli_cwd, *[entry for entry in sys.path if normalize(entry) not in blocked_entries]]",
            "    from codex_plugin_scanner.guard.package_shim_gate import (",
            "        package_shim_command_requires_external_archive_binding,",
            "        package_shim_command_requires_guard,",
            "    )",
            "    workspace = Path(guard_workspace) if guard_workspace is not None else Path.cwd()",
            "    arguments = tuple(sys.argv[1:])",
            "    return (",
            "        package_shim_command_requires_guard(command_name, arguments, workspace=workspace),",
            "        package_shim_command_requires_external_archive_binding(",
            "            command_name, arguments, workspace=workspace",
            "        ),",
            "    )",
            "try:",
            "    guard_required, external_archive_binding_required = _command_guard_requirements()",
            "except Exception:",
            "    guard_required = True",
            "    external_archive_binding_required = True",
            "if not guard_required:",
            "    _exec_real_manager()",
            "try:",
            "    from codex_plugin_scanner.guard.contained_package_script_execution import (",
            "        try_execute_contained_package_script,",
            "    )",
            "    contained_result = try_execute_contained_package_script(",
            "        command_name,",
            "        tuple(sys.argv[1:]),",
            "        workspace=Path(guard_workspace) if guard_workspace is not None else Path.cwd(),",
            "        guard_home=Path(guard_home),",
            "        shim_directory=Path(shim_dir),",
            "        environment=dict(os.environ),",
            "    )",
            "except Exception:",
            "    contained_result = None",
            "if contained_result is None:",
            "    try:",
            "        from codex_plugin_scanner.guard.contained_typescript_execution import (",
            "            try_execute_contained_typescript,",
            "        )",
            "        contained_result = try_execute_contained_typescript(",
            "            command_name,",
            "            tuple(sys.argv[1:]),",
            "            workspace=Path(guard_workspace) if guard_workspace is not None else Path.cwd(),",
            "            guard_home=Path(guard_home),",
            "            shim_directory=Path(shim_dir),",
            "            environment=dict(os.environ),",
            "        )",
            "    except Exception:",
            "        contained_result = None",
            "if contained_result is None:",
            "    try:",
            "        from codex_plugin_scanner.guard.contained_node_execution import (",
            "            try_execute_contained_node_command,",
            "        )",
            "        contained_result = try_execute_contained_node_command(",
            "            command_name,",
            "            tuple(sys.argv[1:]),",
            "            workspace=Path(guard_workspace) if guard_workspace is not None else Path.cwd(),",
            "            guard_home=Path(guard_home),",
            "            shim_directory=Path(shim_dir),",
            "            environment=dict(os.environ),",
            "        )",
            "    except Exception:",
            "        contained_result = None",
            "if contained_result is not None:",
            "    if contained_result.stdout:",
            "        sys.stdout.write(contained_result.stdout)",
            "    if contained_result.stderr:",
            "        sys.stderr.write(contained_result.stderr)",
            "    raise SystemExit(contained_result.exit_code)",
            "guard_env = dict(os.environ)",
            "guard_args = list(sys.argv[1:])",
            "guard_env.pop('PYTHONPATH', None)",
            "guard_command = [*base_command, '--dry-run', command_name]",
            "if external_archive_binding_required:",
            "    resolved_command, guard_args, guard_env = _real_manager_launch()",
            "    guard_env.pop('PYTHONPATH', None)",
            "    guard_command = [*base_command, resolved_command]",
            "if shim_probe:",
            "    guard_command = [*base_command, '--json', '--dry-run', command_name]",
            "guard_kwargs = {'capture_output': True, 'text': True, 'env': guard_env}",
            "if guard_has_explicit_workspace:",
            "    guard_kwargs['cwd'] = guard_cli_cwd",
            "def _run_guard_with_store_lock_retry(command, kwargs):",
            "    deadline = time.monotonic() + store_lock_retry_timeout_seconds",
            "    while True:",
            "        result = subprocess.run(command, **kwargs)",
            "        stderr = result.stderr or ''",
            "        if result.returncode == 0 or 'database is locked' not in stderr.lower():",
            "            return result",
            "        remaining_seconds = deadline - time.monotonic()",
            "        if remaining_seconds <= 0:",
            "            return result",
            "        time.sleep(min(store_lock_retry_delay_seconds, remaining_seconds))",
            "try:",
            "    guard_process = _run_guard_with_store_lock_retry(",
            "        [*guard_command, *guard_args], guard_kwargs",
            "    )",
            "except KeyboardInterrupt:",
            "    raise SystemExit(130)",
            "if guard_process.stdout:",
            "    sys.stdout.write(guard_process.stdout)",
            "if guard_process.stderr:",
            "    sys.stderr.write(guard_process.stderr)",
            "if shim_probe:",
            "    raise SystemExit(0)",
            "if external_archive_binding_required:",
            "    raise SystemExit(guard_process.returncode)",
            "if guard_process.returncode != 0:",
            "    raise SystemExit(guard_process.returncode)",
            "_exec_real_manager()",
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


def _filtered_manager_path(context: HarnessContext, *, path_env: str | None = None) -> str:
    shim_dir = context.guard_home / "package-shims" / "bin"
    shim_dir_abs = os.path.abspath(os.path.expanduser(str(shim_dir)))
    effective_path = path_env if path_env is not None else os.environ.get("PATH", "")
    path_entries = [entry for entry in effective_path.split(os.pathsep) if entry]
    filtered_entries = [entry for entry in path_entries if os.path.abspath(os.path.expanduser(entry)) != shim_dir_abs]
    return os.pathsep.join(filtered_entries)


def _detect_system_package_managers(
    context: HarnessContext,
    *,
    path_env: str | None = None,
) -> tuple[list[str], list[str]]:
    """Return supported managers with and without a real binary on PATH."""

    filtered_path = _filtered_manager_path(context, path_env=path_env)
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
    manifest, _state = _load_package_shim_manifest_with_state(context)
    return manifest


def _load_package_shim_manifest_with_state(
    context: HarnessContext,
) -> tuple[dict[str, object], str]:
    manifest_path = _package_shim_manifest_path(context)
    if not manifest_path.exists():
        return {}, "absent"
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}, "unreadable"
    if not isinstance(payload, dict):
        return {}, "invalid"
    installed_managers = payload.get("installed_managers")
    if not isinstance(installed_managers, list) or not installed_managers:
        return {}, "invalid"
    if any(not isinstance(manager, str) or manager not in _PACKAGE_SHIM_COMMANDS for manager in installed_managers):
        return {}, "invalid"
    return payload, "valid"


def _dict_items(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _string_map(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {key: item for key, item in value.items() if isinstance(key, str) and isinstance(item, str)}


def _write_package_shim_manifest(context: HarnessContext, payload: dict[str, object]) -> None:
    _package_shim_manifest_path(context).write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _record_package_shim_test_results(
    context: HarnessContext,
    manager_results: list[dict[str, object]],
    *,
    tested_at: str | None = None,
) -> None:
    manifest = _load_package_shim_manifest(context)
    normalized_last_tests = dict(_string_map(manifest.get("last_test_at")))
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
    return _posix_path_export(shim_dir)


def _path_export_hints(shim_dir: Path) -> dict[str, str]:
    posix_hint = _posix_path_export(shim_dir)
    return {
        "bash": posix_hint,
        "zsh": posix_hint,
        "fish": _fish_path_prepend(shim_dir),
        "powershell": f'$env:Path = "{shim_dir};$env:Path"',
    }


def probe_package_shim_intercepts(
    context: HarnessContext,
    *,
    managers: tuple[str, ...] | None = None,
    workspace_dir: Path | None = None,
    allow_inactive_path: bool = False,
    timeout_seconds: int = _PACKAGE_SHIM_PROBE_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Execute installed package-manager shims to prove intercept wiring is live."""

    status = package_shim_status(context)
    installed = set(_string_items(status.get("installed_managers")))
    protected = set(_string_items(status.get("protected_managers")))
    tested_managers = list(managers or tuple(sorted(installed)))
    path_repair_required = [manager for manager in tested_managers if manager in installed and manager not in protected]
    manager_results: list[dict[str, object]] = []
    detail_by_manager = {
        str(item.get("manager")): item
        for item in _dict_items(status.get("manager_details"))
        if isinstance(item.get("manager"), str)
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
        if manager not in protected and not allow_inactive_path:
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
                timeout=timeout_seconds,
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
                "execution_permitted": evaluator_evidence["execution_permitted"],
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
    "FROZEN_PACKAGE_SHIM_SENTINEL",
    "activate_package_shims",
    "ensure_guard_shim_path_in_shell_profile",
    "ensure_package_shim_path_in_shell_profile",
    "install_guard_shim",
    "install_package_shims",
    "package_shim_cloud_coverage",
    "package_shim_dashboard_status",
    "package_shim_status",
    "package_shim_supported_managers",
    "probe_package_shim_intercepts",
    "remove_guard_profile_blocks",
    "remove_guard_shim",
    "resolve_frozen_package_shim_path",
    "run_frozen_package_shim",
    "uninstall_package_shims",
]
