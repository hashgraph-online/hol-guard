"""Helpers for updating the installed HOL Guard CLI."""

from __future__ import annotations

import http.client
import importlib
import importlib.metadata
import json
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import sysconfig
import urllib.error
import urllib.request
from pathlib import Path

from packaging.version import InvalidVersion, Version

from ..adapters.base import HarnessContext
from ..adapters.codex import CodexHarnessAdapter, codex_native_hook_state
from ..redaction import redact_sensitive_text
from ..store import GuardStore
from .install_commands import apply_managed_install

_ALREADY_CURRENT_HINTS = (
    "already at latest version",
    "already up-to-date",
)
_PYPI_JSON_URL = "https://pypi.org/pypi/hol-guard/json"
_PYPI_TIMEOUT_SECONDS = 3.0


def run_guard_update(
    *,
    dry_run: bool,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    workspace: str | None = None,
    now: str | None = None,
) -> tuple[dict[str, object], int]:
    current_version = _current_version()
    installer = _installer_kind()
    command = _update_command(installer)
    payload: dict[str, object] = {
        "current_version": current_version,
        "installer": installer,
        "command": command,
        "retry_command": _shell_command(command),
        "binary_diagnostics": _binary_diagnostics(command, installer),
        "dry_run": dry_run,
    }
    direct_url = _direct_url_payload()
    if direct_url is not None:
        payload["direct_url"] = direct_url
        is_editable = bool(direct_url.get("dir_info", {}).get("editable"))
        payload["editable_install"] = is_editable
        if is_editable:
            payload["status"] = "skipped"
            payload["changed"] = False
            payload["error"] = (
                "Automatic update is disabled for editable installs. Re-run your local install workflow instead."
            )
            return payload, 0
    if dry_run:
        payload["version_check"] = _version_check_payload(current_version)
        payload["status"] = "planned"
        payload["changed"] = False
        payload["message"] = "Review the planned installer command before updating."
        return payload, 0
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as error:
        payload["status"] = "failed"
        payload["changed"] = False
        payload["error"] = redact_sensitive_text(str(error))
        payload["message"] = "HOL Guard update failed before the installer started."
        return payload, 1
    payload["stdout"] = _normalize_output_text(result.stdout)
    payload["stderr"] = _normalize_output_text(result.stderr)
    payload["return_code"] = result.returncode
    importlib.invalidate_caches()
    payload["resulting_version"] = _current_version_from_subprocess()
    if result.returncode != 0:
        payload["status"] = "failed"
        payload["changed"] = False
        payload["message"] = "HOL Guard update failed."
        return payload, 1
    payload["status"] = _success_status(payload)
    payload["changed"] = payload["status"] == "updated"
    payload["message"] = _success_message(
        status=str(payload["status"]),
        current_version=current_version,
        resulting_version=str(payload.get("resulting_version") or ""),
    )
    notes = _success_notes(payload)
    if notes:
        payload["notes"] = notes
    repaired_installs, repair_notes = _repair_supported_harnesses(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
        dry_run=dry_run,
    )
    if repair_notes:
        payload["notes"] = [*notes, *repair_notes]
    if repaired_installs:
        payload["managed_installs"] = repaired_installs
        if len(repaired_installs) == 1:
            payload["managed_install"] = repaired_installs[0]
    return payload, 0


def _normalize_output_text(value: str) -> str:
    return redact_sensitive_text(value.strip())


def _shell_command(command: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def _binary_diagnostics(command: list[str], installer: str) -> dict[str, object]:
    resolved_binary = shutil.which("hol-guard")
    installer_binary = command[0] if command else ""
    expected_script_dir = _expected_script_dir(installer_binary, installer)
    path_status = "unknown"
    if resolved_binary is None:
        path_status = "not_on_path"
    elif installer == "pipx":
        path_status = "pipx_shim_detected"
    elif installer == "uv":
        path_status = "uv_tool_shim_detected"
    elif expected_script_dir is not None and _script_dir(resolved_binary) == expected_script_dir:
        path_status = "matches_installer"
    else:
        path_status = "path_mismatch"
    return {
        "resolved_hol_guard": resolved_binary,
        "installer_binary": installer_binary,
        "expected_script_dir": str(expected_script_dir) if expected_script_dir is not None else None,
        "path_status": path_status,
    }


def _expected_script_dir(installer_binary: str, installer: str) -> Path | None:
    if installer != "pip" or not installer_binary:
        return None
    scripts_dir = sysconfig.get_path("scripts")
    if scripts_dir:
        return _directory_path(scripts_dir)
    return _script_dir(installer_binary)


def _script_dir(path: str) -> Path:
    return _directory_path(Path(path).expanduser().parent)


def _directory_path(path: str | Path) -> Path:
    directory = Path(path).expanduser()
    if not directory.is_absolute():
        directory = Path.cwd() / directory
    return directory.resolve(strict=False)


def _output_lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def _success_status(payload: dict[str, object]) -> str:
    current_version = str(payload.get("current_version") or "").strip()
    resulting_version = str(payload.get("resulting_version") or "").strip()
    if (
        current_version
        and resulting_version
        and current_version != "unknown"
        and resulting_version != "unknown"
        and current_version != resulting_version
    ):
        return "updated"
    output_text = str(payload.get("stdout") or "").lower()
    if any(hint in output_text for hint in _ALREADY_CURRENT_HINTS):
        return "current"
    if "requirement already satisfied: hol-guard" in output_text or "hol-guard is already installed" in output_text:
        return "current"
    return "updated"


def _success_message(*, status: str, current_version: str, resulting_version: str) -> str:
    if status == "current":
        return "HOL Guard is already current."
    if (
        current_version
        and resulting_version
        and current_version != "unknown"
        and resulting_version != "unknown"
        and current_version != resulting_version
    ):
        return f"Updated HOL Guard from {current_version} to {resulting_version}."
    return "HOL Guard update completed successfully."


def _success_notes(payload: dict[str, object]) -> list[str]:
    if str(payload.get("status") or "") not in {"current", "updated"}:
        return []
    return _output_lines(str(payload.get("stderr") or ""))


def _version_check_payload(current_version: str) -> dict[str, object]:
    latest_version = _latest_version_from_pypi()
    if latest_version is None:
        return {
            "source": "pypi",
            "status": "unavailable",
            "current_version": current_version,
            "latest_version": None,
            "update_available": None,
        }
    update_available = _is_newer_version(latest_version, current_version)
    if update_available is None:
        return {
            "source": "pypi",
            "status": "unavailable",
            "current_version": current_version,
            "latest_version": latest_version,
            "update_available": None,
        }
    return {
        "source": "pypi",
        "status": "stale" if update_available else "current",
        "current_version": current_version,
        "latest_version": latest_version,
        "update_available": update_available,
    }


def _latest_version_from_pypi() -> str | None:
    request = urllib.request.Request(_PYPI_JSON_URL, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=_PYPI_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (
        OSError,
        TimeoutError,
        urllib.error.URLError,
        http.client.IncompleteRead,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        return None
    if not isinstance(payload, dict):
        return None
    info = payload.get("info")
    if not isinstance(info, dict):
        return None
    version = info.get("version")
    return version if isinstance(version, str) and version.strip() else None


def _is_newer_version(latest_version: str, current_version: str) -> bool | None:
    try:
        latest = Version(latest_version)
        current = Version(current_version)
    except InvalidVersion:
        return None
    return latest > current


def _current_version() -> str:
    try:
        return importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _installer_kind() -> str:
    prefix_path = Path(sys.prefix).resolve()
    normalized_prefix = prefix_path.as_posix().lower()
    if "/uv/tools/" in normalized_prefix:
        return "uv"
    if (prefix_path / "pipx_metadata.json").exists():
        return "pipx"
    if "/pipx/venvs/" in normalized_prefix:
        return "pipx"
    return "pip"


def _update_command(installer: str) -> list[str]:
    if installer == "uv":
        return ["uv", "tool", "upgrade", "hol-guard"]
    if installer == "pipx":
        return ["pipx", "upgrade", "hol-guard"]
    return [sys.executable, "-m", "pip", "install", "--upgrade", "hol-guard"]


def _direct_url_payload() -> dict[str, object] | None:
    try:
        distribution = importlib.metadata.distribution("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        return None
    raw_payload = distribution.read_text("direct_url.json")
    if raw_payload is None:
        return None
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _current_version_from_subprocess() -> str:
    try:
        result = subprocess.run(
            [sys.executable, "-c", 'import importlib.metadata; print(importlib.metadata.version("hol-guard"))'],
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError:
        return _current_version()
    if result.returncode != 0:
        return _current_version()
    version = result.stdout.strip()
    return version or _current_version()


def _repair_supported_harnesses(
    *,
    context: HarnessContext | None,
    store: GuardStore | None,
    workspace: str | None,
    now: str | None,
    dry_run: bool,
) -> tuple[list[dict[str, object]], list[str]]:
    if dry_run or context is None or store is None or now is None:
        return [], []
    repaired_codex, codex_warning = _repair_codex_install(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
    )
    repaired_installs = [repaired_codex] if repaired_codex is not None else []
    repair_notes = [codex_warning] if codex_warning is not None else []
    return repaired_installs, repair_notes


def _repair_codex_install(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[dict[str, object] | None, str | None]:
    repair_target = _codex_repair_target(context, store)
    if repair_target is None:
        return None, None
    repair_context, repair_workspace = repair_target
    try:
        hook_state = codex_native_hook_state(repair_context)
    except (OSError, RuntimeError) as error:
        return None, f"Could not inspect Codex protection during update: {error}"
    if bool(hook_state["protection_active"]):
        return None, None
    try:
        payload = apply_managed_install(
            "install",
            "codex",
            False,
            repair_context,
            store,
            repair_workspace,
            now,
        )
    except (OSError, RuntimeError, json.JSONDecodeError, sqlite3.Error) as error:
        return None, f"Could not repair Codex protection during update: {error}"
    managed_install = payload.get("managed_install")
    return (managed_install if isinstance(managed_install, dict) else None), None


def _codex_repair_target(context: HarnessContext, store: GuardStore) -> tuple[HarnessContext, str | None] | None:
    try:
        managed_install = store.get_managed_install("codex")
    except (json.JSONDecodeError, sqlite3.Error):
        return _codex_backup_repair_target(context)
    if managed_install is not None and bool(managed_install.get("active")):
        managed_workspace = managed_install.get("workspace")
        if isinstance(managed_workspace, str) and managed_workspace.strip():
            workspace_path = Path(managed_workspace).expanduser().resolve()
            return (
                HarnessContext(
                    home_dir=context.home_dir,
                    workspace_dir=workspace_path,
                    guard_home=context.guard_home,
                ),
                str(workspace_path),
            )
        return HarnessContext(context.home_dir, None, context.guard_home), None
    return _codex_backup_repair_target(context)


def _codex_backup_repair_target(context: HarnessContext) -> tuple[HarnessContext, str | None] | None:
    for repair_context in _codex_backup_repair_contexts(context):
        if not CodexHarnessAdapter._backup_path(repair_context).is_file():
            continue
        repair_workspace = str(repair_context.workspace_dir) if repair_context.workspace_dir is not None else None
        return repair_context, repair_workspace
    return None


def _codex_backup_repair_contexts(context: HarnessContext) -> tuple[HarnessContext, ...]:
    if context.workspace_dir is not None:
        return (context,)
    contexts: list[HarnessContext] = []
    home_dir = context.home_dir.resolve()
    seen_workspaces: set[Path] = set()
    current_dir = Path.cwd().resolve()
    for candidate_dir in (current_dir, *current_dir.parents):
        if candidate_dir == home_dir or candidate_dir in seen_workspaces:
            continue
        seen_workspaces.add(candidate_dir)
        contexts.append(
            HarnessContext(
                home_dir=context.home_dir,
                workspace_dir=candidate_dir,
                guard_home=context.guard_home,
            )
        )
    contexts.append(context)
    return tuple(contexts)


__all__ = ["run_guard_update"]
