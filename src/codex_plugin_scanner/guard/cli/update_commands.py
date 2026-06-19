"""Helpers for updating the installed HOL Guard CLI."""

from __future__ import annotations

import http.client
import importlib
import importlib.metadata
import json
import os
import platform
import shlex
import shutil
import sqlite3
import subprocess
import sys
import sysconfig
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..adapters.base import HarnessContext
from ..adapters.codex import CodexHarnessAdapter, codex_native_hook_state
from ..adapters.opencode_pretool import (
    global_plugin_path,
    install_pretool_plugin,
    managed_plugin_path,
    pretool_plugin_source,
)
from ..redaction import redact_sensitive_text
from ..store import GuardStore
from .dashboard_sync import sync_dashboard_assets as _sync_dashboard_assets
from .install_commands import apply_managed_install

_ALREADY_CURRENT_HINTS = (
    "already at latest version",
    "already up-to-date",
)
_PYPI_JSON_URL = "https://pypi.org/pypi/hol-guard/json"
_PYPI_TIMEOUT_SECONDS = 3.0
_PACKAGE_SHIM_REFRESH_TIMEOUT_SECONDS = 30.0
_last_pypi_payload: dict[str, object] | None = None
_PACKAGE_SHIM_REFRESH_SCRIPT = """
from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.shims import package_shim_status, repair_package_shims


def _resolve_path(value: object) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return Path(value).expanduser().resolve()


payload = json.loads(sys.stdin.read())
home_dir = _resolve_path(payload.get("home_dir")) or Path.home().resolve()
guard_home = _resolve_path(payload.get("guard_home")) or (home_dir / ".hol-guard")
context = HarnessContext(
    home_dir=home_dir,
    workspace_dir=_resolve_path(payload.get("workspace_dir")),
    guard_home=guard_home,
)
before = package_shim_status(context)
repair = None
if before.get("installed_managers"):
    repair = repair_package_shims(context)
after = package_shim_status(context)
print(json.dumps({"before": before, "repair": repair, "after": after}))
""".strip()


def _read_direct_url_dir_info(direct_url: dict[str, object] | None) -> dict[str, object]:
    if direct_url is None:
        return {}
    dir_info = direct_url.get("dir_info")
    return dir_info if isinstance(dir_info, dict) else {}


def run_guard_update(
    *,
    dry_run: bool,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    workspace: str | None = None,
    now: str | None = None,
    force_pypi_reinstall: bool = False,
) -> tuple[dict[str, object], int]:
    current_version = _current_version()
    installer = _installer_kind()
    direct_url = _direct_url_payload()
    local_source_install = _local_source_install_payload(direct_url)
    vcs_install = _vcs_install_payload(direct_url)
    payload: dict[str, object] = {
        "current_version": current_version,
        "installer": installer,
        "dry_run": dry_run,
    }
    if direct_url is not None:
        payload["direct_url"] = direct_url
        is_editable = bool(_read_direct_url_dir_info(direct_url).get("editable"))
        payload["editable_install"] = is_editable
        if local_source_install is not None:
            payload["source_install"] = local_source_install
        if vcs_install is not None:
            payload["vcs_install"] = vcs_install
        if is_editable:
            payload["status"] = "skipped"
            payload["changed"] = False
            payload["error"] = (
                "Automatic update is disabled for editable installs. Re-run your local install workflow instead."
            )
            return payload, 0
        if (
            local_source_install is not None
            and bool(local_source_install.get("path_exists"))
            and not force_pypi_reinstall
        ):
            payload["status"] = "skipped"
            payload["changed"] = False
            payload["error"] = (
                "Automatic update is disabled for local source installs. Re-run your local install workflow instead."
            )
            return payload, 0
        if local_source_install is not None and not bool(local_source_install.get("path_exists")):
            payload["recovery_source_install"] = True
    version_check = _version_check_payload(current_version)
    if _python_runtime_blocks_update(version_check):
        payload.update(
            {
                "version_check": version_check,
                "status": "blocked",
                "changed": False,
                "python_update_required": True,
                "message": _python_runtime_block_message(version_check),
            }
        )
        return payload, 1
    use_pypi = force_pypi_reinstall or _should_upgrade_from_pypi(
        current_version=current_version,
        version_check=version_check,
        vcs_install=vcs_install,
        local_source_install=local_source_install,
    )
    command = _update_command(installer, use_pypi=use_pypi)
    execution_command = _execution_update_command(command, installer=installer, context=context)
    if force_pypi_reinstall:
        payload["recovery_reinstall"] = True
    payload.update(
        {
            "command": command,
            "retry_command": _shell_command(command),
            "binary_diagnostics": _binary_diagnostics(command, installer),
            "version_check": version_check,
        }
    )
    if use_pypi:
        payload["upgrade_source"] = "pypi"
    if dry_run:
        payload["status"] = "planned"
        payload["changed"] = False
        payload["message"] = _planned_update_message(version_check=version_check, use_pypi=use_pypi)
        return payload, 0
    active_command = execution_command
    active_display_command = command
    attempted_force_retry = False
    nonzero_success_note: str | None = None
    while True:
        try:
            result = subprocess.run(
                active_command,
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
        payload["command"] = active_display_command
        payload["stdout"] = _normalize_output_text(result.stdout)
        payload["stderr"] = _normalize_output_text(result.stderr)
        payload["return_code"] = result.returncode
        importlib.invalidate_caches()
        payload["resulting_version"] = _current_version_from_subprocess()
        initial_version_check = payload.get("version_check")
        resulting_version = str(payload.get("resulting_version") or current_version)
        post_version_check = _version_check_payload(resulting_version)
        payload["post_version_check"] = post_version_check
        payload["version_check"] = _merge_version_checks(
            initial_version_check,
            post_version_check,
            resulting_version,
        )
        if result.returncode != 0:
            if _version_changed(current_version, resulting_version):
                nonzero_success_note = (
                    "Installer exited with code "
                    f"{result.returncode} after version changed. "
                    "Review stderr for any follow-up action."
                )
            conflict_message = _dependency_conflict_message(
                _installer_output_text(payload.get("stdout"), payload.get("stderr")),
            )
            if conflict_message:
                payload["status"] = "blocked"
                payload["changed"] = False
                payload["dependency_conflict"] = True
                payload["message"] = conflict_message
                payload.pop("retry_command", None)
                return payload, 1
            payload["status"] = "failed"
            payload["changed"] = False
            payload["message"] = "HOL Guard update failed."
            if nonzero_success_note is None:
                return payload, 1
        payload["status"] = _success_status(payload)
        payload["changed"] = _version_changed(current_version, resulting_version) or payload["status"] == "updated"
        if not attempted_force_retry and not force_pypi_reinstall and payload.get("status") == "stale":
            target_version = None
            active_version_check = payload.get("version_check")
            if isinstance(active_version_check, dict):
                latest = active_version_check.get("latest_version")
                if isinstance(latest, str) and latest.strip():
                    target_version = latest.strip()
            retry_command = _update_command(installer, use_pypi=True, target_version=target_version)
            if retry_command != active_display_command:
                attempted_force_retry = True
                active_display_command = retry_command
                active_command = _execution_update_command(
                    retry_command,
                    installer=installer,
                    context=context,
                )
                payload["upgrade_source"] = "pypi"
                continue
        break
    conflict_message = _dependency_conflict_message(
        _installer_output_text(payload.get("stdout"), payload.get("stderr")),
    )
    if payload.get("status") == "stale" and conflict_message:
        payload["status"] = "blocked"
        payload["dependency_conflict"] = True
        payload["message"] = conflict_message
        payload.pop("retry_command", None)
    stale_retry_command = "" if payload.get("status") == "blocked" else _stale_retry_command(payload)
    if stale_retry_command:
        payload["retry_command"] = stale_retry_command
    if payload.get("status") != "blocked":
        payload["message"] = _success_message(
            status=str(payload["status"]),
            current_version=current_version,
            resulting_version=resulting_version,
            version_check=payload.get("version_check"),
            retry_command=stale_retry_command,
        )
    notes = _success_notes(payload)
    if nonzero_success_note is not None:
        notes = [*notes, nonzero_success_note]
    if notes:
        payload["notes"] = notes
    if payload.get("changed") is True or payload.get("status") == "current":
        package_shims, package_shim_note = _refresh_package_shims_after_update(
            context=context,
            dry_run=dry_run,
        )
        if package_shims is not None:
            payload["package_shims"] = package_shims
        _append_payload_note(payload, package_shim_note)
    repaired_installs, repair_notes = _repair_supported_harnesses(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
        dry_run=dry_run,
    )
    if repair_notes:
        payload["notes"] = [*_payload_notes(payload), *repair_notes]
    if repaired_installs:
        payload["managed_installs"] = repaired_installs
        if len(repaired_installs) == 1:
            payload["managed_install"] = repaired_installs[0]
    # Sync dashboard assets when the package changed, even if the install still trails PyPI.
    if not dry_run and (payload.get("status") in {"updated", "current"} or payload.get("changed") is True):
        dashboard_sync = _sync_dashboard_assets()
        if dashboard_sync:
            payload["dashboard_sync"] = dashboard_sync
            sync_notes = dashboard_sync.get("notes")
            if isinstance(sync_notes, list) and sync_notes:
                existing = payload.get("notes")
                existing_notes = existing if isinstance(existing, list) else []
                payload["notes"] = [*existing_notes, *sync_notes]
    return payload, 0


def _normalize_output_text(value: str) -> str:
    return redact_sensitive_text(value.strip())


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _payload_notes(payload: dict[str, object]) -> list[str]:
    return _string_list(payload.get("notes"))


def _append_payload_note(payload: dict[str, object], note: str | None) -> None:
    if note is None or not note.strip():
        return
    payload["notes"] = [*_payload_notes(payload), note]


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
    try:
        scripts_dir = sysconfig.get_path("scripts")
    except Exception:
        scripts_dir = None
    if scripts_dir:
        return _directory_path(scripts_dir)
    return _script_dir(installer_binary)


def build_guard_install_surface_payload() -> dict[str, object]:
    installer = _installer_kind()
    return {
        "installer": installer,
        "binary_diagnostics": _binary_diagnostics(_update_command(installer, use_pypi=False), installer),
    }


def _script_dir(path: str) -> Path:
    return _directory_path(Path(path).expanduser().parent)


def _directory_path(path: str | Path) -> Path:
    directory = Path(path).expanduser()
    if not directory.is_absolute():
        directory = Path.cwd() / directory
    return directory.absolute()


def _output_lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def _success_status(payload: dict[str, object]) -> str:
    if _is_stale_install(payload):
        return "stale"
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


def _is_stale_install(payload: dict[str, object]) -> bool:
    version_check = payload.get("version_check")
    return isinstance(version_check, dict) and version_check.get("update_available") is True


def _version_changed(current_version: str, resulting_version: str) -> bool:
    return (
        bool(current_version)
        and bool(resulting_version)
        and current_version != "unknown"
        and resulting_version != "unknown"
        and current_version != resulting_version
    )


def _merge_version_checks(
    initial_version_check: object,
    post_version_check: object,
    resulting_version: str,
) -> dict[str, object]:
    if isinstance(post_version_check, dict) and post_version_check.get("update_available") is not None:
        return post_version_check
    if isinstance(initial_version_check, dict):
        merged = dict(initial_version_check)
        latest_version = merged.get("latest_version")
        if isinstance(latest_version, str) and latest_version.strip() and resulting_version not in {"", "unknown"}:
            try:
                if Version(resulting_version) >= Version(latest_version.strip()):
                    merged["update_available"] = False
                    merged["status"] = "current"
                    merged["current_version"] = resulting_version
            except InvalidVersion:
                pass
        return merged
    if isinstance(post_version_check, dict):
        return post_version_check
    return {
        "source": "pypi",
        "status": "unavailable",
        "current_version": None,
        "latest_version": None,
        "update_available": None,
    }


def _stale_retry_command(payload: dict[str, object]) -> str:
    version_check = payload.get("version_check")
    target_version: str | None = None
    if isinstance(version_check, dict):
        latest_version = version_check.get("latest_version")
        if isinstance(latest_version, str) and latest_version.strip():
            target_version = latest_version.strip()
    if isinstance(version_check, dict) and version_check.get("update_available") is True:
        installer = str(payload.get("installer") or "pip")
        return _shell_command(_update_command(installer, use_pypi=True, target_version=target_version))
    retry_command = payload.get("retry_command")
    if isinstance(retry_command, str) and retry_command.strip():
        return retry_command.strip()
    command = payload.get("command")
    if isinstance(command, list) and command:
        return _shell_command(command)
    return ""


def _success_message(
    *,
    status: str,
    current_version: str,
    resulting_version: str,
    version_check: object = None,
    retry_command: str = "",
) -> str:
    if status == "blocked":
        return "HOL Guard update is blocked by incompatible package dependencies."
    if status == "stale":
        latest_version = None
        if isinstance(version_check, dict):
            latest = version_check.get("latest_version")
            if isinstance(latest, str) and latest.strip():
                latest_version = latest.strip()
        installed_version = resulting_version or current_version
        if latest_version and installed_version not in {"", "unknown"}:
            message = f"HOL Guard {installed_version} is behind PyPI {latest_version} after the update attempt."
        else:
            message = "HOL Guard is behind the latest PyPI release."
        if retry_command:
            return f"{message} Run: {retry_command}"
        return message
    if status == "current":
        return "HOL Guard is already current."
    if status == "updated" and current_version == resulting_version:
        return "HOL Guard source was repaired successfully."
    if (
        current_version
        and resulting_version
        and current_version != "unknown"
        and resulting_version != "unknown"
        and current_version != resulting_version
    ):
        return f"Updated HOL Guard from {current_version} to {resulting_version}."
    return "HOL Guard update completed successfully."


def _planned_update_message(*, version_check: dict[str, object], use_pypi: bool) -> str:
    if use_pypi:
        if version_check.get("update_available") is True:
            latest_version = version_check.get("latest_version")
            if isinstance(latest_version, str) and latest_version.strip():
                return f"Review the planned PyPI install command to update to {latest_version.strip()}."
        return "Review the planned PyPI install command to repair the install source."
    return "Review the planned installer command before updating."


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
    required_python_requirements = _latest_version_python_requirements(latest_version)
    runtime_python = _runtime_python_version()
    if update_available and not _python_requirements_satisfied(required_python_requirements, runtime_python):
        compatible_version = _latest_compatible_release_version(current_version, runtime_python)
        if compatible_version is not None:
            return {
                "source": "pypi",
                "status": "stale",
                "current_version": current_version,
                "latest_version": compatible_version,
                "update_available": True,
                "pypi_latest_version": latest_version,
                "pypi_latest_python_incompatible": True,
                "pypi_latest_required_python": _format_python_requirements(required_python_requirements),
                "runtime_python": runtime_python,
            }
        return {
            "source": "pypi",
            "status": "python_incompatible",
            "current_version": current_version,
            "latest_version": latest_version,
            "update_available": True,
            "required_python": _format_python_requirements(required_python_requirements),
            "runtime_python": runtime_python,
        }
    return {
        "source": "pypi",
        "status": "stale" if update_available else "current",
        "current_version": current_version,
        "latest_version": latest_version,
        "update_available": update_available,
    }


def _latest_version_from_pypi() -> str | None:
    global _last_pypi_payload
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
    _last_pypi_payload = payload
    info = payload.get("info")
    if not isinstance(info, dict):
        return None
    version = info.get("version")
    return version if isinstance(version, str) and version.strip() else None


def _latest_compatible_release_version(current_version: str, runtime_python: str) -> str | None:
    payload = _last_pypi_payload
    if not isinstance(payload, dict):
        return None
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return None
    candidates: list[tuple[Version, str]] = []
    for version_text, files in releases.items():
        if not isinstance(version_text, str) or not version_text.strip():
            continue
        try:
            parsed_version = Version(version_text)
        except InvalidVersion:
            continue
        if _is_newer_version(version_text, current_version) is not True:
            continue
        if not _release_has_non_yanked_file(files):
            continue
        requirements = _latest_version_python_requirements(version_text)
        if _python_requirements_satisfied(requirements, runtime_python):
            candidates.append((parsed_version, version_text.strip()))
    if not candidates:
        return None
    stable_candidates = [candidate for candidate in candidates if not candidate[0].is_prerelease]
    return max(stable_candidates or candidates, key=lambda candidate: candidate[0])[1]


def _release_has_non_yanked_file(files: object) -> bool:
    if not isinstance(files, list):
        return False
    return any(isinstance(file_payload, dict) and not file_payload.get("yanked") for file_payload in files)


def _runtime_python_version() -> str:
    return platform.python_version()


def _latest_version_python_requirements(latest_version: str) -> tuple[str, ...] | None:
    payload = _last_pypi_payload
    if not isinstance(payload, dict):
        return None
    releases = payload.get("releases")
    if isinstance(releases, dict):
        files = releases.get(latest_version)
        if isinstance(files, list):
            requirements: list[str] = []
            for file_payload in files:
                if not isinstance(file_payload, dict) or file_payload.get("yanked"):
                    continue
                requires_python = file_payload.get("requires_python")
                if not isinstance(requires_python, str) or not requires_python.strip():
                    continue
                requirement = requires_python.strip()
                if requirement not in requirements:
                    requirements.append(requirement)
            if requirements:
                return tuple(requirements)
    info = payload.get("info")
    if isinstance(info, dict) and info.get("version") == latest_version:
        requires_python = info.get("requires_python")
        if isinstance(requires_python, str) and requires_python.strip():
            return (requires_python.strip(),)
    return None


def _python_requirements_satisfied(requirements: tuple[str, ...] | None, runtime_python: str) -> bool:
    if not requirements:
        return True
    for requires_python in requirements:
        try:
            if SpecifierSet(requires_python).contains(runtime_python, prereleases=True):
                return True
        except InvalidSpecifier:
            return True
    return False


def _format_python_requirements(requirements: tuple[str, ...] | None) -> str | None:
    if not requirements:
        return None
    return " or ".join(requirements)


def _python_runtime_blocks_update(version_check: object) -> bool:
    return isinstance(version_check, dict) and version_check.get("status") == "python_incompatible"


def _python_runtime_block_message(version_check: object) -> str:
    if not isinstance(version_check, dict):
        return "HOL Guard update requires a different Python runtime."
    latest_version = version_check.get("latest_version")
    required_python = version_check.get("required_python")
    runtime_python = version_check.get("runtime_python")
    latest_label = (
        latest_version if isinstance(latest_version, str) and latest_version.strip() else "the latest release"
    )
    requirement_label = (
        required_python
        if isinstance(required_python, str) and required_python.strip()
        else "the supported Python range"
    )
    runtime_label = runtime_python if isinstance(runtime_python, str) and runtime_python.strip() else "this Python"
    return (
        f"HOL Guard {latest_label} requires Python {requirement_label}; this install is running Python "
        f"{runtime_label}. Reinstall HOL Guard with Python {requirement_label} (for example, Python 3.13 when "
        "the latest release requires <3.14), then rerun hol-guard update."
    )


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


def _should_upgrade_from_pypi(
    *,
    current_version: str,
    version_check: dict[str, object],
    vcs_install: dict[str, object] | None,
    local_source_install: dict[str, object] | None,
) -> bool:
    if local_source_install is not None and not bool(local_source_install.get("path_exists")):
        latest_version = version_check.get("latest_version")
        if isinstance(latest_version, str) and latest_version.strip():
            newer_than_pypi = _is_newer_version(current_version, latest_version.strip())
            if newer_than_pypi is True:
                return False
        return True
    if version_check.get("update_available") is not True:
        return False
    return vcs_install is not None


def _hol_guard_package_spec(target_version: str | None = None) -> str:
    if isinstance(target_version, str) and target_version.strip() and target_version.strip() not in {"unknown"}:
        return f"hol-guard=={target_version.strip()}"
    return "hol-guard"


def _installer_output_text(stdout: object, stderr: object) -> str:
    return "\n".join(part.strip() for part in (str(stdout or "").strip(), str(stderr or "").strip()) if part.strip())


def _dependency_conflict_message(installer_output: str) -> str | None:
    lowered = installer_output.lower()
    if "resolutionimpossible" not in lowered and "conflicting dependencies" not in lowered:
        return None
    if "rich" in lowered and "cisco-ai-skill-scanner" in lowered:
        return (
            "PyPI cannot install the latest HOL Guard release because hol-guard and "
            "cisco-ai-skill-scanner require incompatible rich versions. Wait for a fixed "
            "HOL Guard release, then run hol-guard update again."
        )
    return (
        "PyPI cannot install the latest HOL Guard release because of conflicting package "
        "dependencies. Check installer output for details."
    )


def _update_command(installer: str, *, use_pypi: bool = False, target_version: str | None = None) -> list[str]:
    package = _hol_guard_package_spec(target_version)
    if use_pypi:
        if installer == "uv":
            return ["uv", "tool", "install", "--force", package]
        if installer == "pipx":
            return ["pipx", "install", "--force", package]
        return [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall", package]
    if installer == "uv":
        return ["uv", "tool", "upgrade", "hol-guard"]
    if installer == "pipx":
        return ["pipx", "upgrade", "hol-guard"]
    return [sys.executable, "-m", "pip", "install", "--upgrade", "hol-guard"]


def _execution_update_command(
    command: list[str],
    *,
    installer: str,
    context: HarnessContext | None,
) -> list[str]:
    if (
        installer == "pipx"
        and context is not None
        and _package_shim_manifest_has_installed_managers(context)
        and (real_binary := _resolve_unshimmed_binary(command[0], context))
    ):
        return [real_binary, *command[1:]]
    return command


def _vcs_install_payload(direct_url: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(direct_url, dict):
        return None
    vcs_info = direct_url.get("vcs_info")
    if not isinstance(vcs_info, dict):
        return None
    vcs = vcs_info.get("vcs")
    if not isinstance(vcs, str) or not vcs.strip():
        return None
    payload: dict[str, object] = {"kind": "vcs", "vcs": vcs.strip()}
    raw_url = direct_url.get("url")
    if isinstance(raw_url, str) and raw_url.strip():
        payload["url"] = raw_url.strip()
    requested_revision = vcs_info.get("requested_revision")
    if isinstance(requested_revision, str) and requested_revision.strip():
        payload["requested_revision"] = requested_revision.strip()
    commit_id = vcs_info.get("commit_id")
    if isinstance(commit_id, str) and commit_id.strip():
        payload["commit_id"] = commit_id.strip()
    return payload


def _local_source_install_payload(direct_url: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(direct_url, dict):
        return None
    if isinstance(direct_url.get("vcs_info"), dict):
        return None
    if isinstance(direct_url.get("archive_info"), dict):
        return None
    raw_url = direct_url.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None
    parsed = urlparse(raw_url)
    if parsed.scheme != "file":
        return None
    raw_path = urllib.request.url2pathname(parsed.path)
    if not raw_path:
        return None
    source_path = Path(raw_path).expanduser()
    if not source_path.is_absolute():
        source_path = Path.cwd() / source_path
    return {
        "kind": "local_path",
        "url": raw_url,
        "path": str(source_path.resolve(strict=False)),
        "path_exists": source_path.exists(),
    }


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


def _resolve_unshimmed_binary(command_name: str, context: HarnessContext) -> str | None:
    filtered_path = _path_without_guard_package_shims(context)
    if not filtered_path:
        return None
    return shutil.which(command_name, path=filtered_path)


def _path_without_guard_package_shims(context: HarnessContext) -> str:
    shim_dir = (context.guard_home / "package-shims" / "bin").expanduser().resolve()
    filtered_entries = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        try:
            if Path(entry).expanduser().resolve() == shim_dir:
                continue
        except OSError:
            pass
        filtered_entries.append(entry)
    return os.pathsep.join(filtered_entries)


def _refresh_package_shims_after_update(
    *,
    context: HarnessContext | None,
    dry_run: bool,
) -> tuple[dict[str, object] | None, str | None]:
    if dry_run or context is None or not _package_shim_manifest_has_installed_managers(context):
        return None, None
    refresh_context = {
        "home_dir": str(context.home_dir),
        "workspace_dir": str(context.workspace_dir) if context.workspace_dir is not None else None,
        "guard_home": str(context.guard_home),
    }
    try:
        result = subprocess.run(
            [sys.executable, "-c", _PACKAGE_SHIM_REFRESH_SCRIPT],
            input=json.dumps(refresh_context),
            capture_output=True,
            check=False,
            text=True,
            timeout=_PACKAGE_SHIM_REFRESH_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, f"Could not refresh package firewall shims during update: {redact_sensitive_text(str(error))}"
    stdout = _normalize_output_text(result.stdout)
    stderr = _normalize_output_text(result.stderr)
    if result.returncode != 0:
        details = stderr or stdout or f"exit code {result.returncode}"
        return None, f"Could not refresh package firewall shims during update: {details}"
    try:
        refresh_payload = json.loads(stdout) if stdout else {}
    except json.JSONDecodeError as error:
        return None, f"Could not parse package firewall refresh output during update: {error}"
    if not isinstance(refresh_payload, dict):
        return None, "Could not parse package firewall refresh output during update: invalid payload"
    after_status = refresh_payload.get("after")
    if not isinstance(after_status, dict):
        return None, "Could not parse package firewall refresh output during update: missing status"
    installed_managers = _string_list(after_status.get("installed_managers"))
    if not installed_managers:
        return None, None
    return refresh_payload, _package_shim_refresh_note(refresh_payload)


def _package_shim_manifest_has_installed_managers(context: HarnessContext) -> bool:
    manifest_path = context.guard_home / "package-shims" / "manifest.json"
    try:
        raw_manifest = manifest_path.read_text(encoding="utf-8")
    except OSError:
        return False
    try:
        manifest = json.loads(raw_manifest)
    except json.JSONDecodeError:
        return False
    if not isinstance(manifest, dict):
        return False
    return bool(_string_list(manifest.get("installed_managers")))


def _package_shim_refresh_note(refresh_payload: dict[str, object]) -> str | None:
    after_status = refresh_payload.get("after")
    if not isinstance(after_status, dict):
        return None
    manager_details = after_status.get("manager_details")
    detail_items = manager_details if isinstance(manager_details, list) else []
    unhealthy_managers = [
        str(detail.get("manager"))
        for detail in detail_items
        if isinstance(detail, dict) and detail.get("integrity") in {"missing", "stale", "tampered"}
    ]
    path_repair_required = _string_list(after_status.get("path_repair_required"))
    if unhealthy_managers:
        return f"Package firewall shims still need repair after update for {', '.join(unhealthy_managers)}."
    repair_result = refresh_payload.get("repair")
    repaired = _string_list(repair_result.get("repaired")) if isinstance(repair_result, dict) else []
    if repaired:
        note = f"Refreshed package firewall shims during update for {', '.join(repaired)}."
        if path_repair_required:
            note += f" Restart your shell to reactivate {', '.join(path_repair_required)}."
        return note
    if path_repair_required:
        return (
            "Package firewall shims are current, but PATH repair is still required for "
            f"{', '.join(path_repair_required)}."
        )
    return None


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
    opencode_note = _refresh_opencode_pretool_plugin(context=context, store=store)
    if opencode_note is not None:
        repair_notes.append(opencode_note)
    return repaired_installs, repair_notes


def _refresh_opencode_pretool_plugin(
    *,
    context: HarnessContext,
    store: GuardStore,
) -> str | None:
    try:
        managed_install = store.get_managed_install("opencode")
    except (json.JSONDecodeError, sqlite3.Error):
        return None
    if managed_install is None or not bool(managed_install.get("active")):
        return None
    repair_context, _ = _repair_context_from_managed_install(context, managed_install)
    global_path = global_plugin_path(repair_context)
    managed_path = managed_plugin_path(repair_context)
    try:
        expected_source = pretool_plugin_source(repair_context)
    except (OSError, RuntimeError) as error:
        return f"Could not inspect OpenCode pretool plugin during update: {error}"
    try:
        global_source = global_path.read_text(encoding="utf-8") if global_path.is_file() else ""
        managed_source = managed_path.read_text(encoding="utf-8") if managed_path.is_file() else ""
    except OSError as error:
        return f"Could not inspect OpenCode pretool plugin during update: {error}"
    if global_source == expected_source and managed_source == expected_source:
        return None
    try:
        install_pretool_plugin(repair_context)
    except (OSError, RuntimeError) as error:
        return f"Could not refresh OpenCode pretool plugin during update: {error}"
    return "Refreshed the OpenCode pretool plugin during update. Restart OpenCode to load it."


def _repair_context_from_managed_install(
    context: HarnessContext,
    managed_install: dict[str, object],
) -> tuple[HarnessContext, str | None]:
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
        return _repair_context_from_managed_install(context, managed_install)
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


def build_guard_update_status_payload() -> dict[str, object]:
    current_version = _current_version()
    install_surface = build_guard_install_surface_payload()
    installer = str(install_surface.get("installer") or "")
    binary_diagnostics = install_surface.get("binary_diagnostics")
    if not isinstance(binary_diagnostics, dict):
        binary_diagnostics = {}
    direct_url = _direct_url_payload()
    local_source_install = _local_source_install_payload(direct_url)
    version_check = _version_check_payload(current_version)
    auto_updatable = True
    blocked_reason: str | None = None
    recovery_reinstall_available = False

    if _python_runtime_blocks_update(version_check):
        auto_updatable = False
        blocked_reason = _python_runtime_block_message(version_check)
    elif isinstance(direct_url, dict):
        if bool(_read_direct_url_dir_info(direct_url).get("editable")):
            auto_updatable = False
            blocked_reason = (
                "This install was set up from local source code. Re-run your usual local install command instead."
            )
        elif local_source_install is not None and bool(local_source_install.get("path_exists")):
            auto_updatable = False
            blocked_reason = (
                "This install was set up from a local folder. Re-run your usual local install command instead."
            )
            # Recovery can convert this install back to a normal PyPI package.
            recovery_reinstall_available = True

    update_available = auto_updatable and version_check.get("update_available") is True
    latest_version = version_check.get("latest_version")
    recovery_reinstall_command = (
        _shell_command(_update_command(installer, use_pypi=True)) if recovery_reinstall_available else None
    )
    return {
        "current_version": current_version,
        "latest_version": latest_version if isinstance(latest_version, str) else None,
        "installer": installer,
        "binary_diagnostics": binary_diagnostics,
        "version_check": version_check,
        "auto_updatable": auto_updatable,
        "update_available": update_available,
        "blocked_reason": blocked_reason,
        "python_update_required": _python_runtime_blocks_update(version_check),
        "recovery_reinstall_available": recovery_reinstall_available,
        "recovery_reinstall_command": recovery_reinstall_command,
    }


__all__ = ["build_guard_install_surface_payload", "build_guard_update_status_payload", "run_guard_update"]
