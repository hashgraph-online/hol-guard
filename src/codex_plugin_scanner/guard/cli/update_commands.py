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
import time
import urllib.error
import urllib.request
from contextvars import ContextVar
from pathlib import Path
from urllib.parse import ParseResult, urlparse

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..adapters.base import HarnessContext
from ..adapters.codex import CodexHarnessAdapter, codex_native_hook_state
from ..adapters.cursor_hooks import cursor_native_hook_state
from ..adapters.opencode_pretool import (
    global_plugin_path,
    install_pretool_plugin,
    managed_plugin_path,
    pretool_plugin_source,
)
from ..codex_hook_integrity import CodexHookIntegrityError, load_authenticated_hook_manifest
from ..config import resolve_guard_home
from ..mdm.contracts import ManagedNetworkPolicy, ManagedPolicy
from ..mdm.network import ManagedNetworkError, managed_urlopen
from ..mdm.policy import load_managed_policy
from ..redaction import redact_sensitive_text
from ..store import GuardStore
from .install_commands import apply_managed_install
from .update_artifact import (
    TrustedWheelArtifact,
    UpdateArtifactError,
    record_local_wheel_receipt,
    recover_local_wheel_original,
    stage_trusted_wheel,
)
from .update_subprocess import (
    InstalledDistribution,
    TrustedUpdateContext,
    UpdateSubprocessError,
    build_trusted_update_context,
)

_ALREADY_CURRENT_HINTS = (
    "already at latest version",
    "already up-to-date",
)
_PYPI_JSON_URL = "https://pypi.org/pypi/hol-guard/json"
_PYPI_TIMEOUT_SECONDS = 3.0
_PYPI_RESPONSE_LIMIT_BYTES = 8 * 1024 * 1024
_PYPI_READ_CHUNK_BYTES = 64 * 1024
_PACKAGE_SHIM_REFRESH_TIMEOUT_SECONDS = 30.0
_last_pypi_payload: dict[str, object] | None = None
_version_network_policy: ContextVar[ManagedNetworkPolicy | None] = ContextVar(
    "guard_update_version_network_policy",
    default=None,
)
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
diagnostic_path = payload.get("diagnostic_path")
if not isinstance(diagnostic_path, str):
    diagnostic_path = ""
before = package_shim_status(context, path_env=diagnostic_path)
repair = None
if before.get("installed_managers"):
    repair = repair_package_shims(context, path_env=diagnostic_path)
after = package_shim_status(context, path_env=diagnostic_path)
print(json.dumps({"before": before, "repair": repair, "after": after}))
""".strip()
_DAEMON_REFRESH_TIMEOUT_SECONDS = 75.0
_DAEMON_REFRESH_CLEANUP_TIMEOUT_SECONDS = 15.0
_DAEMON_REFRESH_SCRIPT = """
from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.daemon.manager import (
    clear_guard_daemon_state,
    ensure_guard_daemon_after_update,
    guard_daemon_retirement_is_complete,
    repair_approval_center_locator,
    retire_all_guard_daemons_for_home,
)

payload = json.loads(sys.stdin.read())
guard_home = Path(payload["guard_home"]).expanduser().resolve()
home_dir_value = payload.get("home_dir")
home_dir = (
    Path(home_dir_value).expanduser().resolve()
    if isinstance(home_dir_value, str) and home_dir_value.strip()
    else Path.home().resolve()
)
state_path = guard_home / "daemon-state.json"
if not state_path.is_file():
    print(json.dumps({"status": "not_running"}))
    raise SystemExit(0)
try:
    state = json.loads(state_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    state = {}
preferred_port = state.get("port") if isinstance(state.get("port"), int) else None
retired = retire_all_guard_daemons_for_home(guard_home)
if not guard_daemon_retirement_is_complete(guard_home):
    print(json.dumps({"status": "retirement_failed", "retired": retired}))
    raise SystemExit(1)
clear_guard_daemon_state(guard_home)
repair_approval_center_locator(guard_home)
refresh_parameters = inspect.signature(ensure_guard_daemon_after_update).parameters
refresh_kwargs = {"preferred_port": preferred_port}
if "home_dir" in refresh_parameters:
    refresh_kwargs["home_dir"] = home_dir
if "allow_windows_job_breakaway" in refresh_parameters:
    refresh_kwargs["allow_windows_job_breakaway"] = True
daemon_url = ensure_guard_daemon_after_update(guard_home, **refresh_kwargs)
print(json.dumps({"status": "restarted", "retired": retired, "daemon_url": daemon_url}))
""".strip()
_DAEMON_REFRESH_CLEANUP_SCRIPT = """
from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.daemon.manager import (
    _guard_daemon_pid_is_running,
    clear_guard_daemon_state,
    guard_daemon_retirement_is_complete,
    load_authenticated_guard_daemon_pending_launch,
    retire_all_guard_daemons_for_home,
)
from codex_plugin_scanner.guard.daemon.discovery import load_authenticated_daemon_state
from codex_plugin_scanner.guard.windows_paths import windows_process_creation_time

payload = json.loads(sys.stdin.read())
guard_home = Path(payload["guard_home"]).expanduser().resolve()
retired = retire_all_guard_daemons_for_home(guard_home)
remaining = []
state = load_authenticated_daemon_state(guard_home)
if isinstance(state, dict):
    state_pid = state.get("pid")
    if isinstance(state_pid, int) and state_pid > 0 and _guard_daemon_pid_is_running(state_pid):
        remaining.append(state_pid)
pending = load_authenticated_guard_daemon_pending_launch(guard_home)
if isinstance(pending, dict):
    pending_pid = pending.get("pid")
    pending_creation_time = pending.get("process_creation_time")
    if (
        isinstance(pending_pid, int)
        and pending_pid > 0
        and isinstance(pending_creation_time, int)
        and windows_process_creation_time(pending_pid) == pending_creation_time
        and _guard_daemon_pid_is_running(pending_pid)
        and pending_pid not in remaining
    ):
        remaining.append(pending_pid)
if remaining or not guard_daemon_retirement_is_complete(guard_home):
    print(json.dumps({"status": "cleanup_failed", "retired": retired, "remaining": remaining}))
    raise SystemExit(1)
clear_guard_daemon_state(guard_home)
print(json.dumps({"status": "cleaned", "retired": retired, "remaining": []}))
""".strip()
_HARNESS_REPAIR_TIMEOUT_SECONDS = 60.0
_HARNESS_REPAIR_SCRIPT = """
from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.update_commands import _repair_supported_harnesses_in_process
from codex_plugin_scanner.guard.store import GuardStore


payload = json.loads(sys.stdin.read())
home_dir = Path(payload["home_dir"]).resolve()
guard_home = Path(payload["guard_home"]).resolve()
workspace_value = payload.get("workspace_dir")
workspace_dir = Path(workspace_value).resolve() if isinstance(workspace_value, str) else None
context = HarnessContext(
    home_dir=home_dir,
    workspace_dir=workspace_dir,
    guard_home=guard_home,
    home_override_explicit=bool(payload.get("home_override_explicit")),
)
store = GuardStore(guard_home)
managed_installs, notes = _repair_supported_harnesses_in_process(
    context=context,
    store=store,
    workspace=workspace_value,
    now=str(payload["now"]),
    dry_run=False,
)
print(json.dumps({"managed_installs": managed_installs, "notes": notes}, sort_keys=True))
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
    wheel: str | None = None,
    guard_home: Path | None = None,
    include_alpha: bool = False,
) -> tuple[dict[str, object], int]:
    installer = _installer_kind()
    payload: dict[str, object] = {
        "installer": installer,
        "dry_run": dry_run,
    }
    managed_policy_state = load_managed_policy()
    managed_update_blocked = managed_policy_state.status != "absent" and (
        managed_policy_state.policy is None or managed_policy_state.policy.update.owner == "mdm"
    )
    if managed_update_blocked:
        payload.update(
            {
                "status": "skipped",
                "changed": False,
                "reason_code": "mdm_update_owned",
                "message": "HOL Guard updates are managed by the organization.",
            }
        )
        return payload, 0
    managed_policy = managed_policy_state.policy
    network_policy = managed_policy.network if managed_policy is not None else ManagedNetworkPolicy()
    configured_index_url = managed_policy.update.index_url if managed_policy is not None else None
    if not network_policy.allow_public_registries and configured_index_url is None:
        payload.update(
            {
                "status": "blocked",
                "changed": False,
                "reason_code": "update_source_unconfigured",
                "message": "HOL Guard update requires an organization-configured package source.",
            }
        )
        return payload, 1
    requested_wheel_path, requested_wheel_error = _resolve_requested_wheel_path(wheel)
    if requested_wheel_error is not None:
        payload["status"] = "failed"
        payload["changed"] = False
        payload["reason_code"] = "update_artifact_invalid"
        payload["error"] = requested_wheel_error
        payload["message"] = "HOL Guard update failed before the installer started."
        return payload, 1
    if requested_wheel_path is not None:
        payload["requested_wheel"] = str(requested_wheel_path)
    if guard_home is not None:
        resolved_guard_home = guard_home.expanduser().resolve()
    elif context is not None:
        resolved_guard_home = context.guard_home.expanduser().resolve()
    else:
        resolved_guard_home = resolve_guard_home()
    daemon_refresh_required = context is not None and (resolved_guard_home / "daemon-state.json").is_file()
    if context is not None:
        trusted_workspace = context.workspace_dir
    elif workspace:
        trusted_workspace = Path(workspace).expanduser()
    else:
        trusted_workspace = Path.cwd()
    try:
        update_context = build_trusted_update_context(
            guard_home=resolved_guard_home,
            workspace_dir=trusted_workspace,
            installer_kind=installer,
            source_url=configured_index_url,
            source_kind="managed_index" if configured_index_url is not None else "pypi",
            proxy_mode=network_policy.proxy_mode,
            proxy_url=network_policy.proxy_url,
            ca_bundle_path=network_policy.ca_bundle_path,
        )
    except UpdateSubprocessError as error:
        return _trusted_update_failure(payload, error)
    payload["trusted_update"] = _trusted_update_public_payload(update_context)
    try:
        installed_distribution = update_context.query_distribution()
    except UpdateSubprocessError as error:
        return _trusted_update_failure(payload, error)
    current_version = installed_distribution.version
    direct_url = installed_distribution.direct_url
    local_source_install = _local_source_install_payload(direct_url)
    local_archive_install = _recover_local_archive_install(
        _local_archive_install_payload(direct_url),
        direct_url=direct_url,
        guard_home=resolved_guard_home,
        installed_version=current_version,
    )
    vcs_install = _vcs_install_payload(direct_url)
    payload["current_version"] = current_version
    if direct_url is not None:
        payload["direct_url"] = _public_direct_url_payload(direct_url)
        is_editable = bool(_read_direct_url_dir_info(direct_url).get("editable"))
        payload["editable_install"] = is_editable
        if local_source_install is not None:
            payload["source_install"] = local_source_install
        if local_archive_install is not None:
            payload["archive_install"] = local_archive_install
        if vcs_install is not None:
            payload["vcs_install"] = vcs_install
        if is_editable and requested_wheel_path is None:
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
            and requested_wheel_path is None
        ):
            payload["status"] = "skipped"
            payload["changed"] = False
            payload["error"] = (
                "Automatic update is disabled for local source installs. Re-run your local install workflow instead."
            )
            return payload, 0
        if (
            local_archive_install is not None
            and str(local_archive_install.get("archive_type") or "") == "wheel"
            and not force_pypi_reinstall
            and requested_wheel_path is None
        ):
            payload["status"] = "skipped"
            payload["changed"] = False
            if bool(local_archive_install.get("path_exists")):
                payload["error"] = (
                    "Automatic update is disabled for local wheel installs. "
                    f"Re-run `{_local_archive_update_hint(local_archive_install)}` "
                    "or your local install workflow instead."
                )
            else:
                payload["error"] = (
                    "Automatic update is disabled for local wheel installs when the original wheel file is gone. "
                    "Pass a new wheel with `hol-guard update --wheel <wheel-or-directory>` "
                    "or re-run your local install workflow instead."
                )
            return payload, 0
        if local_source_install is not None and not bool(local_source_install.get("path_exists")):
            payload["recovery_source_install"] = True
    version_check = _version_check_payload(
        current_version,
        source_kind=update_context.source.public_name,
        network_policy=network_policy,
        include_alpha=include_alpha,
    )
    if requested_wheel_path is None and _python_runtime_blocks_update(version_check):
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
    target_version = None
    if version_check.get("update_available") is True:
        latest_version = version_check.get("latest_version")
        if isinstance(latest_version, str) and latest_version.strip():
            target_version = latest_version.strip()
            use_pypi = True
    trusted_wheel: TrustedWheelArtifact | None = None
    if requested_wheel_path is not None:
        try:
            trusted_wheel = stage_trusted_wheel(
                requested_wheel_path,
                neutral_cwd=update_context.neutral_cwd,
            )
        except UpdateArtifactError as error:
            return _trusted_update_failure(payload, UpdateSubprocessError(error.reason_code))
    command = _update_command(
        installer,
        use_pypi=use_pypi,
        target_version=target_version,
        wheel_path=requested_wheel_path,
    )
    execution_display_command = _update_command(
        installer,
        use_pypi=use_pypi,
        target_version=target_version,
        wheel_path=trusted_wheel.staged_path if trusted_wheel is not None else None,
    )
    try:
        execution_command = update_context.build_installer_command(execution_display_command)
    except UpdateSubprocessError as error:
        return _trusted_update_failure(payload, error, trusted_wheel=trusted_wheel)
    if force_pypi_reinstall:
        payload["recovery_reinstall"] = True
    payload.update(
        {
            "command": command,
            "retry_command": _safe_update_retry_command(requested_wheel_path, include_alpha=include_alpha),
            "binary_diagnostics": _binary_diagnostics(command, installer),
            "version_check": version_check,
        }
    )
    if requested_wheel_path is not None:
        payload["upgrade_source"] = "local_wheel"
        if trusted_wheel is not None:
            payload["wheel_sha256"] = trusted_wheel.sha256
            payload["wheel_version"] = trusted_wheel.version
    else:
        payload["upgrade_source"] = update_context.source.public_name
        if include_alpha:
            payload["release_channel"] = "alpha"
    if dry_run:
        payload["status"] = "planned"
        payload["changed"] = False
        payload["message"] = _planned_update_message(
            version_check=version_check,
            use_pypi=use_pypi,
            wheel_path=requested_wheel_path,
        )
        if trusted_wheel is not None:
            trusted_wheel.cleanup()
        return payload, 0
    active_command = execution_command
    active_display_command = command
    attempted_force_retry = False
    installer_execution_started = False
    while True:
        try:
            if trusted_wheel is not None:
                trusted_wheel.revalidate()
            installer_execution_started = True
            result = update_context.run(active_command)
        except UpdateArtifactError as error:
            return _trusted_update_failure(
                payload,
                UpdateSubprocessError(error.reason_code),
                trusted_wheel=trusted_wheel,
                retain_trusted_wheel=installer_execution_started,
            )
        except UpdateSubprocessError as error:
            return _trusted_update_failure(
                payload,
                error,
                trusted_wheel=trusted_wheel,
                retain_trusted_wheel=installer_execution_started,
            )
        payload["command"] = active_display_command
        payload["stdout"] = _normalize_output_text(result.stdout)
        payload["stderr"] = _normalize_output_text(result.stderr)
        payload["return_code"] = result.returncode
        if result.output_limited:
            return _trusted_update_failure(
                payload,
                UpdateSubprocessError("update_installer_output_limit"),
                trusted_wheel=trusted_wheel,
                retain_trusted_wheel=installer_execution_started,
            )
        importlib.invalidate_caches()
        try:
            payload["resulting_version"] = _current_version_from_subprocess(update_context)
        except UpdateSubprocessError as error:
            return _trusted_update_failure(
                payload,
                error,
                trusted_wheel=trusted_wheel,
                retain_trusted_wheel=installer_execution_started,
            )
        initial_version_check = payload.get("version_check")
        resulting_version = str(payload.get("resulting_version") or current_version)
        if trusted_wheel is not None:
            try:
                if Version(resulting_version) != Version(trusted_wheel.version):
                    return _trusted_update_failure(
                        payload,
                        UpdateSubprocessError("update_version_mismatch"),
                        trusted_wheel=trusted_wheel,
                        retain_trusted_wheel=installer_execution_started,
                    )
            except InvalidVersion:
                return _trusted_update_failure(
                    payload,
                    UpdateSubprocessError("update_version_output_invalid"),
                    trusted_wheel=trusted_wheel,
                    retain_trusted_wheel=installer_execution_started,
                )
        if result.returncode != 0:
            conflict_message = _dependency_conflict_message(
                _installer_output_text(payload.get("stdout"), payload.get("stderr")),
            )
            if conflict_message:
                payload["status"] = "blocked"
                payload["changed"] = False
                payload["dependency_conflict"] = True
                payload["message"] = conflict_message
                payload.pop("retry_command", None)
                if trusted_wheel is not None:
                    _retain_local_wheel_staging(payload)
                return payload, 1
            payload["status"] = "failed"
            payload["changed"] = False
            payload["reason_code"] = "update_installer_failed"
            payload["message"] = "HOL Guard update failed."
            if trusted_wheel is not None:
                _retain_local_wheel_staging(payload)
            return payload, 1
        if trusted_wheel is not None:
            _record_verified_local_wheel_receipt(
                payload,
                update_context=update_context,
                trusted_wheel=trusted_wheel,
                guard_home=resolved_guard_home,
                installed_version=resulting_version,
            )
        post_version_check = _version_check_payload(
            resulting_version,
            source_kind=update_context.source.public_name,
            network_policy=network_policy,
            include_alpha=include_alpha,
        )
        payload["post_version_check"] = post_version_check
        payload["version_check"] = _merge_version_checks(
            initial_version_check,
            post_version_check,
            resulting_version,
        )
        payload["status"] = _success_status(payload)
        payload["changed"] = _version_changed(current_version, resulting_version) or payload["status"] == "updated"
        if (
            not attempted_force_retry
            and not force_pypi_reinstall
            and requested_wheel_path is None
            and payload.get("status") == "stale"
        ):
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
                try:
                    active_command = update_context.build_installer_command(retry_command)
                except UpdateSubprocessError as error:
                    return _trusted_update_failure(payload, error, trusted_wheel=trusted_wheel)
                payload["upgrade_source"] = update_context.source.public_name
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
    if notes:
        payload["notes"] = [*_payload_notes(payload), *notes]
    if payload.get("changed") is True or payload.get("status") == "current":
        package_shims, package_shim_note = _refresh_package_shims_after_update(
            context=context,
            dry_run=dry_run,
            update_context=update_context,
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
        update_context=update_context,
    )
    if repair_notes:
        payload["notes"] = [*_payload_notes(payload), *repair_notes]
    if repaired_installs:
        payload["managed_installs"] = repaired_installs
        if len(repaired_installs) == 1:
            payload["managed_install"] = repaired_installs[0]
    if context is not None:
        daemon_refresh, daemon_refresh_note = refresh_guard_daemon_after_update(
            context,
            update_context=update_context,
        )
        if daemon_refresh is not None:
            payload["daemon_refresh"] = daemon_refresh
        _append_payload_note(payload, daemon_refresh_note)
        if daemon_refresh_required and not (
            isinstance(daemon_refresh, dict) and daemon_refresh.get("status") == "restarted"
        ):
            payload.update(
                {
                    "status": "failed",
                    "reason_code": "update_daemon_refresh_failed",
                    "message": "HOL Guard was updated, but its daemon could not be restarted safely.",
                }
            )
            return payload, 1
    return payload, 0


def _record_verified_local_wheel_receipt(
    payload: dict[str, object],
    *,
    update_context: TrustedUpdateContext,
    trusted_wheel: TrustedWheelArtifact,
    guard_home: Path,
    installed_version: str,
) -> None:
    """Delete staging only after installed PEP 610 metadata binds the exact wheel."""

    try:
        trusted_wheel.revalidate()
        installed_distribution = update_context.query_distribution()
    except (UpdateArtifactError, UpdateSubprocessError):
        _retain_local_wheel_staging(
            payload,
            "Retained the private staged wheel because the installed local-wheel provenance could not be verified.",
        )
        return
    archive_install = _local_archive_install_payload(installed_distribution.direct_url)
    archive_sha256 = _direct_url_archive_sha256(installed_distribution.direct_url)
    staged_path_value = archive_install.get("path") if isinstance(archive_install, dict) else None
    try:
        versions_match = (
            Version(installed_distribution.version) == Version(installed_version) == Version(trusted_wheel.version)
        )
    except InvalidVersion:
        versions_match = False
    if (
        not versions_match
        or not isinstance(staged_path_value, str)
        or Path(staged_path_value) != trusted_wheel.staged_path
        or archive_sha256 != trusted_wheel.sha256
    ):
        _retain_local_wheel_staging(
            payload,
            "Retained the private staged wheel because installed PEP 610 metadata did not bind the exact artifact.",
        )
        return
    try:
        record_local_wheel_receipt(
            trusted_wheel,
            guard_home=guard_home,
            installed_version=installed_version,
        )
    except UpdateArtifactError:
        _retain_local_wheel_staging(
            payload,
            "Retained the private staged wheel because its local-source receipt could not be persisted.",
        )
        return
    payload["local_wheel_receipt"] = "recorded"
    trusted_wheel.cleanup()


def _retain_local_wheel_staging(payload: dict[str, object], note: str | None = None) -> None:
    payload["local_wheel_receipt"] = "staging_retained"
    _append_payload_note(
        payload,
        note or "Retained the private staged wheel because installer completion could not be verified conclusively.",
    )


def _normalize_output_text(value: str) -> str:
    return redact_sensitive_text(value.strip())


def _trusted_update_failure(
    payload: dict[str, object],
    error: UpdateSubprocessError,
    *,
    trusted_wheel: TrustedWheelArtifact | None = None,
    retain_trusted_wheel: bool = False,
) -> tuple[dict[str, object], int]:
    if trusted_wheel is not None:
        if retain_trusted_wheel:
            _retain_local_wheel_staging(payload)
        else:
            trusted_wheel.cleanup()
    payload.update(
        {
            "status": "failed",
            "changed": False,
            "reason_code": error.reason_code,
            "error": error.reason_code,
            "message": "HOL Guard update could not complete in its trusted maintenance environment.",
        }
    )
    return payload, 1


def _trusted_update_public_payload(context: TrustedUpdateContext) -> dict[str, object]:
    return {
        "python": str(context.python.canonical_path),
        "python_sha256": context.python.sha256,
        "installer": str(context.installer.canonical_path) if context.installer is not None else "python-module-pip",
        "installer_sha256": context.installer.sha256 if context.installer is not None else context.python.sha256,
        "installer_interpreters": [
            {"path": str(identity.canonical_path), "sha256": identity.sha256}
            for identity in context.installer_interpreters
        ],
        "source": context.source.public_name,
        "source_fingerprint": context.source.fingerprint,
        "cwd": str(context.neutral_cwd),
        "environment_mode": "minimal",
    }


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
    if str(payload.get("upgrade_source") or "") == "local_wheel":
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
        if (
            current_version
            and resulting_version
            and current_version != "unknown"
            and resulting_version != "unknown"
            and current_version == resulting_version
        ):
            return "current"
        output_text = str(payload.get("stdout") or "").lower()
        if any(hint in output_text for hint in _ALREADY_CURRENT_HINTS):
            return "current"
        if "requirement already satisfied: hol-guard" in output_text or "hol-guard is already installed" in output_text:
            return "current"
        return "updated"
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
    if str(payload.get("upgrade_source") or "") == "local_wheel":
        return ""
    version_check = payload.get("version_check")
    if isinstance(version_check, dict) and version_check.get("update_available") is True:
        command = ["hol-guard", "update"]
        if payload.get("release_channel") == "alpha":
            command.append("--alpha")
        return _shell_command(command)
    retry_command = payload.get("retry_command")
    if isinstance(retry_command, str) and retry_command.strip():
        return retry_command.strip()
    command = payload.get("command")
    if isinstance(command, list) and command:
        return _shell_command(command)
    return ""


def _safe_update_retry_command(wheel_path: Path | None, *, include_alpha: bool = False) -> str:
    command = ["hol-guard", "update"]
    if include_alpha:
        command.append("--alpha")
    if wheel_path is not None:
        command.extend(["--wheel", str(wheel_path)])
    return _shell_command(command)


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


def _planned_update_message(
    *,
    version_check: dict[str, object],
    use_pypi: bool,
    wheel_path: Path | None = None,
) -> str:
    if wheel_path is not None:
        return "Review the planned local wheel install command before updating."
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


def _version_check_payload(
    current_version: str,
    *,
    source_kind: str = "pypi",
    network_policy: ManagedNetworkPolicy | None = None,
    include_alpha: bool = False,
) -> dict[str, object]:
    if source_kind != "pypi":
        return {
            "source": source_kind,
            "status": "source_managed",
            "current_version": current_version,
            "latest_version": None,
            "update_available": None,
        }
    policy_token = _version_network_policy.set(network_policy)
    try:
        latest_version = (
            _latest_alpha_version_from_pypi(current_version) if include_alpha else _latest_version_from_pypi()
        )
    finally:
        _version_network_policy.reset(policy_token)
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
        **({"release_channel": "alpha"} if include_alpha else {}),
        "status": "stale" if update_available else "current",
        "current_version": current_version,
        "latest_version": latest_version,
        "update_available": update_available,
    }


def _latest_version_from_pypi() -> str | None:
    global _last_pypi_payload
    request = urllib.request.Request(_PYPI_JSON_URL, headers={"Accept": "application/json"})
    deadline = time.monotonic() + _PYPI_TIMEOUT_SECONDS
    try:
        with managed_urlopen(
            request,
            timeout=_PYPI_TIMEOUT_SECONDS,
            policy=_version_network_policy.get(),
        ) as response:
            raw_payload = _read_bounded_pypi_response(response, deadline=deadline)
            if len(raw_payload) > _PYPI_RESPONSE_LIMIT_BYTES:
                return None
            payload = json.loads(raw_payload.decode("utf-8"))
    except (
        ManagedNetworkError,
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


def _latest_alpha_version_from_pypi(current_version: str) -> str | None:
    _ = _latest_version_from_pypi()
    payload = _last_pypi_payload
    if not isinstance(payload, dict):
        return None
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return None
    try:
        current_major = Version(current_version).major
    except InvalidVersion:
        return None
    candidates: list[tuple[Version, str]] = []
    for version_text, files in releases.items():
        if not isinstance(version_text, str) or not version_text.strip():
            continue
        try:
            parsed_version = Version(version_text)
        except InvalidVersion:
            continue
        if parsed_version.major != current_major or parsed_version.pre is None or parsed_version.pre[0] != "a":
            continue
        if _release_has_non_yanked_file(files):
            candidates.append((parsed_version, version_text.strip()))
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: candidate[0])[1]


def _read_bounded_pypi_response(response: object, *, deadline: float) -> bytes:
    read = getattr(response, "read1", None)
    if not callable(read):
        read = getattr(response, "read", None)
        if not callable(read):
            raise OSError("PyPI response is not readable")
        if time.monotonic() >= deadline:
            raise TimeoutError("PyPI response deadline exceeded")
        payload = read(_PYPI_RESPONSE_LIMIT_BYTES + 1)
        if time.monotonic() >= deadline:
            raise TimeoutError("PyPI response deadline exceeded")
        if not isinstance(payload, bytes):
            raise OSError("PyPI response returned non-byte content")
        return payload
    payload = bytearray()
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("PyPI response deadline exceeded")
        remaining_capacity = _PYPI_RESPONSE_LIMIT_BYTES + 1 - len(payload)
        if remaining_capacity <= 0:
            return bytes(payload)
        chunk = read(min(_PYPI_READ_CHUNK_BYTES, remaining_capacity))
        if not isinstance(chunk, bytes):
            raise OSError("PyPI response returned non-byte content")
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) > _PYPI_RESPONSE_LIMIT_BYTES:
            return bytes(payload)


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


def _target_version_is_prerelease(target_version: str | None) -> bool:
    if not isinstance(target_version, str) or not target_version.strip():
        return False
    try:
        return Version(target_version.strip()).is_prerelease
    except InvalidVersion:
        return False


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


def _update_command(
    installer: str,
    *,
    use_pypi: bool = False,
    target_version: str | None = None,
    wheel_path: Path | None = None,
) -> list[str]:
    if wheel_path is not None:
        wheel = str(wheel_path)
        if installer == "uv":
            return ["uv", "tool", "install", "--force", wheel]
        if installer == "pipx":
            return ["pipx", "install", "--force", wheel]
        return [sys.executable, "-m", "pip", "install", "--force-reinstall", wheel]
    package = _hol_guard_package_spec(target_version)
    allow_prerelease = _target_version_is_prerelease(target_version)
    if use_pypi:
        if installer == "uv":
            command = ["uv", "tool", "install", "--force"]
            if allow_prerelease:
                command.append("--prerelease=allow")
            command.append(package)
            return command
        if installer == "pipx":
            command = ["pipx", "install", "--force", package]
            if allow_prerelease:
                command.extend(["--pip-args", "--pre"])
            return command
        command = [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall"]
        if allow_prerelease:
            command.append("--pre")
        command.append(package)
        return command
    if installer == "uv":
        return ["uv", "tool", "upgrade", "hol-guard"]
    if installer == "pipx":
        return ["pipx", "upgrade", "hol-guard"]
    return [sys.executable, "-m", "pip", "install", "--upgrade", "hol-guard"]


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
        payload["url"] = _credential_safe_url(raw_url.strip())
    requested_revision = vcs_info.get("requested_revision")
    if isinstance(requested_revision, str) and requested_revision.strip():
        payload["requested_revision"] = requested_revision.strip()
    commit_id = vcs_info.get("commit_id")
    if isinstance(commit_id, str) and commit_id.strip():
        payload["commit_id"] = commit_id.strip()
    return payload


def _local_archive_install_payload(direct_url: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(direct_url, dict):
        return None
    if isinstance(direct_url.get("vcs_info"), dict):
        return None
    if not isinstance(direct_url.get("archive_info"), dict):
        return None
    raw_url = direct_url.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None
    parsed = urlparse(raw_url)
    if parsed.scheme != "file":
        return None
    raw_path = _file_url_to_path(parsed)
    if not raw_path:
        return None
    archive_path = Path(raw_path)
    if not archive_path.is_absolute():
        return {
            "kind": "local_archive",
            "archive_type": "wheel" if archive_path.suffix.lower() == ".whl" else "archive",
            "url": _credential_safe_url(raw_url),
            "path": str(archive_path),
            "path_exists": False,
            "path_resolution_error": "relative_file_url",
        }
    resolved_archive_path, path_resolution_error = _safe_resolve_path(archive_path)
    archive_path_value = resolved_archive_path or archive_path
    archive_type = "wheel" if archive_path.suffix.lower() == ".whl" else "archive"
    payload: dict[str, object] = {
        "kind": "local_archive",
        "archive_type": archive_type,
        "url": _credential_safe_url(raw_url),
        "path": str(archive_path_value),
        "path_exists": _safe_path_exists(archive_path_value),
    }
    if path_resolution_error is not None:
        payload["path_resolution_error"] = path_resolution_error
    return payload


def _recover_local_archive_install(
    local_archive_install: dict[str, object] | None,
    *,
    direct_url: dict[str, object] | None,
    guard_home: Path,
    installed_version: str,
) -> dict[str, object] | None:
    if (
        local_archive_install is None
        or local_archive_install.get("archive_type") != "wheel"
        or local_archive_install.get("path_exists") is True
    ):
        return local_archive_install
    staged_path_value = local_archive_install.get("path")
    archive_sha256 = _direct_url_archive_sha256(direct_url)
    if not isinstance(staged_path_value, str) or not archive_sha256:
        return local_archive_install
    staged_path = Path(staged_path_value)
    if not staged_path.is_absolute():
        return local_archive_install
    original_path = recover_local_wheel_original(
        guard_home=guard_home,
        staged_path=staged_path,
        installed_version=installed_version,
        wheel_sha256=archive_sha256,
    )
    if original_path is None:
        return local_archive_install
    return {
        **local_archive_install,
        "path": str(original_path),
        "path_exists": True,
        "original_source_receipt": "verified",
    }


def _direct_url_archive_sha256(direct_url: dict[str, object] | None) -> str | None:
    if not isinstance(direct_url, dict):
        return None
    archive_info = direct_url.get("archive_info")
    if not isinstance(archive_info, dict):
        return None
    hashes = archive_info.get("hashes")
    candidate = hashes.get("sha256") if isinstance(hashes, dict) else None
    if not isinstance(candidate, str):
        hash_value = archive_info.get("hash")
        if not isinstance(hash_value, str):
            return None
        lowered = hash_value.lower()
        for prefix in ("sha256=", "sha256:"):
            if lowered.startswith(prefix):
                candidate = hash_value[len(prefix) :]
                break
    if not isinstance(candidate, str):
        return None
    normalized = candidate.strip().lower()
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        return None
    return normalized


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
    raw_path = _file_url_to_path(parsed)
    if not raw_path:
        return None
    source_path = Path(raw_path)
    if not source_path.is_absolute():
        return {
            "kind": "local_path",
            "url": _credential_safe_url(raw_url),
            "path": str(source_path),
            "path_exists": False,
            "path_resolution_error": "relative_file_url",
        }
    resolved_source_path, path_resolution_error = _safe_resolve_path(source_path)
    source_path_value = resolved_source_path or source_path
    payload: dict[str, object] = {
        "kind": "local_path",
        "url": _credential_safe_url(raw_url),
        "path": str(source_path_value),
        "path_exists": _safe_path_exists(source_path_value),
    }
    if path_resolution_error is not None:
        payload["path_resolution_error"] = path_resolution_error
    return payload


def _resolve_requested_wheel_path(wheel: str | None) -> tuple[Path | None, str | None]:
    if not isinstance(wheel, str) or not wheel.strip():
        return None, None
    candidate = Path(wheel).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        if candidate.is_symlink():
            return None, "HOL Guard wheel path must not be a symbolic link."
    except OSError:
        return None, "Could not inspect HOL Guard wheel path."
    resolved_candidate, path_resolution_error = _safe_resolve_path(candidate)
    if path_resolution_error is not None or resolved_candidate is None:
        return None, f"Could not resolve HOL Guard wheel path {candidate}: {path_resolution_error or 'unknown error'}"
    candidate = resolved_candidate
    if not candidate.exists():
        if candidate.suffix.lower() == ".whl":
            return None, f"HOL Guard wheel not found: {candidate}"
        return None, f"Directory of wheels not found: {candidate}"
    if candidate.is_dir():

        def _safe_mtime(path: Path) -> int:
            try:
                return path.stat().st_mtime_ns
            except OSError:
                return 0

        try:
            directory_entries = list(candidate.iterdir())
        except OSError as error:
            return None, (f"Could not read HOL Guard wheel directory {candidate}: {redact_sensitive_text(str(error))}")

        wheels: list[Path] = []
        for path in directory_entries:
            if not path.is_file():
                continue
            if _parsed_hol_guard_wheel_version(path) is None:
                continue
            wheels.append(path)
        wheels.sort(
            key=lambda path: (
                _parsed_hol_guard_wheel_version(path) or Version("0"),
                _safe_mtime(path),
                path.name.lower(),
            ),
            reverse=True,
        )
        if not wheels:
            return None, f"No HOL Guard wheels found in {candidate}."
        return wheels[0], None
    if candidate.suffix.lower() != ".whl":
        return None, f"Expected a HOL Guard wheel file or a directory of wheels, got {candidate}."
    if not candidate.is_file():
        return None, f"Expected a HOL Guard wheel file, got {candidate}."
    if _parsed_hol_guard_wheel_version(candidate) is None:
        return None, f"Expected a HOL Guard wheel file, got {candidate}."
    return candidate, None


def _local_archive_update_hint(local_archive_install: dict[str, object]) -> str:
    archive_path = local_archive_install.get("path")
    if isinstance(archive_path, str) and archive_path.strip():
        return _shell_command(["hol-guard", "update", "--wheel", archive_path.strip()])
    return "hol-guard update --wheel <wheel-or-directory>"


def _file_url_to_path(parsed: ParseResult) -> str:
    path = urllib.request.url2pathname(parsed.path)
    netloc = parsed.netloc.strip()
    if netloc and netloc.lower() != "localhost":
        if os.name == "nt":
            return urllib.request.url2pathname(f"//{netloc}{path}")
        return f"//{netloc}{path}"
    return path


def _safe_resolve_path(path: Path) -> tuple[Path | None, str | None]:
    try:
        return path.resolve(strict=False), None
    except (OSError, RuntimeError) as error:
        return None, redact_sensitive_text(str(error))


def _safe_path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except (OSError, RuntimeError):
        return False


def _parsed_hol_guard_wheel_version(path: Path) -> Version | None:
    filename = path.name
    suffix = path.suffix
    if suffix.lower() != ".whl":
        return None
    parts = filename[: -len(suffix)].split("-")
    if len(parts) < 5 or parts[0].lower() != "hol_guard":
        return None
    try:
        return Version(parts[1])
    except InvalidVersion:
        return None


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


def _public_direct_url_payload(payload: dict[str, object]) -> dict[str, object]:
    public: dict[str, object] = {}
    for key, value in payload.items():
        if key == "url" and isinstance(value, str):
            public[key] = _credential_safe_url(value)
        elif isinstance(value, dict):
            public[key] = _public_direct_url_payload(value)
        elif isinstance(value, list):
            public[key] = [_public_direct_url_payload(item) if isinstance(item, dict) else item for item in value]
        else:
            public[key] = value
    return public


def _credential_safe_url(value: str) -> str:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return "[redacted-url]"
    # Older CPython releases rewrite file:relative into the absolute-looking file:///relative form.
    if parsed.scheme == "file" and not parsed.netloc and parsed.path and not parsed.path.startswith("/"):
        relative_path = parsed.path
        if parsed.params:
            relative_path = f"{relative_path};{parsed.params}"
        return f"file:{relative_path}"
    netloc = parsed.netloc
    if parsed.username is not None or parsed.password is not None:
        hostname = parsed.hostname
        if hostname is None:
            return "[redacted-url]"
        rendered_host = f"[{hostname}]" if ":" in hostname else hostname
        netloc = f"{rendered_host}:{port}" if port is not None else rendered_host
    return parsed._replace(netloc=netloc, query="", fragment="").geturl()


def _current_version_from_subprocess(update_context: TrustedUpdateContext) -> str:
    """Return one validated version from the context's intended distribution."""

    return update_context.query_distribution().version


def _standalone_update_context(context: HarnessContext) -> TrustedUpdateContext:
    state = load_managed_policy()
    if state.status != "absent" and state.policy is None:
        raise UpdateSubprocessError("update_source_invalid")
    policy = state.policy
    network = policy.network if policy is not None else ManagedNetworkPolicy()
    index_url = policy.update.index_url if policy is not None else None
    if not network.allow_public_registries and index_url is None:
        raise UpdateSubprocessError("update_source_unconfigured")
    return build_trusted_update_context(
        guard_home=context.guard_home,
        workspace_dir=context.workspace_dir,
        installer_kind=_installer_kind(),
        source_url=index_url,
        source_kind="managed_index" if index_url is not None else "pypi",
        proxy_mode=network.proxy_mode,
        proxy_url=network.proxy_url,
        ca_bundle_path=network.ca_bundle_path,
    )


def _refresh_package_shims_after_update(
    *,
    context: HarnessContext | None,
    dry_run: bool,
    update_context: TrustedUpdateContext | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    if dry_run or context is None or not _package_shim_manifest_has_installed_managers(context):
        return None, None
    refresh_context = {
        "home_dir": str(context.home_dir),
        "workspace_dir": str(context.workspace_dir) if context.workspace_dir is not None else None,
        "guard_home": str(context.guard_home),
        # This value is diagnostic input only; it is never installed as the child PATH.
        "diagnostic_path": os.environ.get("PATH", ""),
    }
    try:
        active_context = update_context or _standalone_update_context(context)
        result = active_context.run(
            active_context.python_command(_PACKAGE_SHIM_REFRESH_SCRIPT),
            input_text=json.dumps(refresh_context),
            timeout_seconds=_PACKAGE_SHIM_REFRESH_TIMEOUT_SECONDS,
        )
    except UpdateSubprocessError as error:
        return None, f"Could not refresh package firewall shims during update: {error.reason_code}"
    stdout = _normalize_output_text(result.stdout)
    stderr = _normalize_output_text(result.stderr)
    if result.output_limited:
        return None, "Could not refresh package firewall shims during update: update_installer_output_limit"
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


def refresh_guard_daemon_after_update(
    context: HarnessContext,
    *,
    update_context: TrustedUpdateContext | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Restart a resident daemon in a fresh interpreter after a CLI package update."""

    if not (context.guard_home / "daemon-state.json").is_file():
        return None, None
    active_context: TrustedUpdateContext | None = None
    try:
        active_context = update_context or _standalone_update_context(context)
        result = active_context.run(
            active_context.python_command(_DAEMON_REFRESH_SCRIPT),
            input_text=json.dumps(
                {
                    "guard_home": str(context.guard_home),
                    "home_dir": str(context.home_dir),
                }
            ),
            timeout_seconds=_DAEMON_REFRESH_TIMEOUT_SECONDS,
            allow_windows_job_breakaway=True,
        )
    except UpdateSubprocessError as error:
        cleanup_verified = True
        if active_context is not None:
            cleanup_verified = _cleanup_failed_guard_daemon_refresh(active_context, context)
        return None, _daemon_refresh_failure_note(
            f"Could not restart the Guard daemon after update: {error.reason_code}",
            cleanup_verified=cleanup_verified,
        )
    stdout = _normalize_output_text(result.stdout)
    stderr = _normalize_output_text(result.stderr)
    if result.output_limited:
        cleanup_verified = _cleanup_failed_guard_daemon_refresh(active_context, context)
        return None, _daemon_refresh_failure_note(
            "Could not restart the Guard daemon after update: update_installer_output_limit",
            cleanup_verified=cleanup_verified,
        )
    if result.returncode != 0:
        cleanup_verified = _cleanup_failed_guard_daemon_refresh(active_context, context)
        details = stderr or stdout or f"exit code {result.returncode}"
        return None, _daemon_refresh_failure_note(
            f"Could not restart the Guard daemon after update: {details}",
            cleanup_verified=cleanup_verified,
        )
    try:
        payload = json.loads(stdout) if stdout else {}
    except json.JSONDecodeError as error:
        cleanup_verified = _cleanup_failed_guard_daemon_refresh(active_context, context)
        return None, _daemon_refresh_failure_note(
            f"Could not parse the Guard daemon restart result after update: {error}",
            cleanup_verified=cleanup_verified,
        )
    if not isinstance(payload, dict):
        cleanup_verified = _cleanup_failed_guard_daemon_refresh(active_context, context)
        return None, _daemon_refresh_failure_note(
            "Could not parse the Guard daemon restart result after update: invalid payload",
            cleanup_verified=cleanup_verified,
        )
    status = payload.get("status")
    if status != "restarted":
        cleanup_verified = _cleanup_failed_guard_daemon_refresh(active_context, context)
        return payload, _daemon_refresh_failure_note(
            "Could not restart the Guard daemon after update: restart was not confirmed",
            cleanup_verified=cleanup_verified,
        )
    return payload, "Restarted the Guard daemon to load the updated package."


def _cleanup_failed_guard_daemon_refresh(
    update_context: TrustedUpdateContext,
    context: HarnessContext,
) -> bool:
    """Best-effort retirement for a daemon that may have escaped a Windows Job."""

    try:
        result = update_context.run(
            update_context.python_command(_DAEMON_REFRESH_CLEANUP_SCRIPT),
            input_text=json.dumps({"guard_home": str(context.guard_home)}),
            timeout_seconds=_DAEMON_REFRESH_CLEANUP_TIMEOUT_SECONDS,
        )
    except UpdateSubprocessError:
        return False
    if result.returncode != 0 or result.output_limited or result.stderr or not result.stdout:
        return False
    lines = result.stdout.strip().splitlines()
    if len(lines) != 1:
        return False
    try:
        payload = json.loads(lines[0])
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict) or set(payload) != {"remaining", "retired", "status"}:
        return False
    remaining = payload.get("remaining")
    retired = payload.get("retired")
    return (
        payload.get("status") == "cleaned"
        and isinstance(remaining, list)
        and not remaining
        and isinstance(retired, list)
        and all(type(pid) is int and pid > 0 for pid in retired)
    )


def _daemon_refresh_failure_note(message: str, *, cleanup_verified: bool) -> str:
    if cleanup_verified:
        return message
    return f"{message}. Guard daemon cleanup could not be verified."


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
    update_context: TrustedUpdateContext,
) -> tuple[list[dict[str, object]], list[str]]:
    """Repair managed harnesses in the updater's already-bound interpreter."""

    if dry_run or context is None or store is None or now is None:
        return [], []
    repair_payload = {
        "home_dir": str(context.home_dir),
        "workspace_dir": str(context.workspace_dir) if context.workspace_dir is not None else workspace,
        "guard_home": str(context.guard_home),
        "home_override_explicit": context.home_override_explicit,
        "now": now,
    }
    try:
        result = update_context.run(
            update_context.python_command(_HARNESS_REPAIR_SCRIPT),
            input_text=json.dumps(repair_payload),
            timeout_seconds=_HARNESS_REPAIR_TIMEOUT_SECONDS,
        )
    except UpdateSubprocessError as error:
        return [], [f"Could not repair supported harnesses during update: {error.reason_code}"]
    if result.output_limited:
        return [], ["Could not repair supported harnesses during update: update_installer_output_limit"]
    if result.returncode != 0:
        return [], ["Could not repair supported harnesses during update: update_repair_failed"]
    try:
        repair_result = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [], ["Could not repair supported harnesses during update: update_repair_output_invalid"]
    if not isinstance(repair_result, dict) or set(repair_result) != {"managed_installs", "notes"}:
        return [], ["Could not repair supported harnesses during update: update_repair_output_invalid"]
    raw_installs = repair_result.get("managed_installs")
    raw_notes = repair_result.get("notes")
    if not isinstance(raw_installs, list) or not isinstance(raw_notes, list):
        return [], ["Could not repair supported harnesses during update: update_repair_output_invalid"]
    if not all(isinstance(item, dict) for item in raw_installs) or not all(isinstance(item, str) for item in raw_notes):
        return [], ["Could not repair supported harnesses during update: update_repair_output_invalid"]
    return [dict(item) for item in raw_installs], [str(item) for item in raw_notes]


def _repair_supported_harnesses_in_process(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
    dry_run: bool,
) -> tuple[list[dict[str, object]], list[str]]:
    """Perform repair after the trusted subprocess boundary has been crossed."""

    if dry_run:
        return [], []
    repaired_codex, codex_warning = _repair_codex_install(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
    )
    repaired_installs = [repaired_codex] if repaired_codex is not None else []
    repair_notes = [codex_warning] if codex_warning is not None else []
    repaired_cursor, cursor_warning = _repair_cursor_install(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
    )
    if repaired_cursor is not None:
        repaired_installs.append(repaired_cursor)
    if cursor_warning is not None:
        repair_notes.append(cursor_warning)
    repaired_pi, pi_warning = _repair_pi_install(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
    )
    if repaired_pi is not None:
        repaired_installs.append(repaired_pi)
    if pi_warning is not None:
        repair_notes.append(pi_warning)
    opencode_note = _refresh_opencode_pretool_plugin(context=context, store=store)
    if opencode_note is not None:
        repair_notes.append(opencode_note)
    return repaired_installs, repair_notes


def _repair_pi_install(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[dict[str, object] | None, str | None]:
    """Rewrite the managed Pi extension after package updates.

    The extension embeds timeout and daemon-compat constants. Refreshing it after
    update keeps the fast daemon path available and avoids cold CLI timeouts.
    """

    try:
        managed_install = store.get_managed_install("pi")
    except (json.JSONDecodeError, sqlite3.Error):
        return None, None
    if managed_install is None or not bool(managed_install.get("active")):
        return None, None
    try:
        repair_context, repair_workspace = _repair_context_from_managed_install(context, managed_install)
        payload = apply_managed_install(
            "install",
            "pi",
            False,
            repair_context,
            store,
            repair_workspace or workspace,
            now,
        )
    except (OSError, RuntimeError, json.JSONDecodeError, sqlite3.Error) as error:
        return None, f"Could not refresh Pi protection during update: {error}"
    repaired = payload.get("managed_install")
    if not isinstance(repaired, dict):
        return None, "Could not refresh Pi protection during update: managed install was not recorded"
    return repaired, None


def _repair_cursor_install(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[dict[str, object] | None, str | None]:
    try:
        managed_install = store.get_managed_install("cursor")
    except (json.JSONDecodeError, sqlite3.Error):
        return None, None
    if managed_install is None or not bool(managed_install.get("active")):
        return None, None
    manifest = managed_install.get("manifest")
    if not isinstance(manifest, dict):
        return None, "Could not inspect Cursor protection during update: managed manifest is invalid"
    surface_value = manifest.get("surface")
    surface = surface_value if surface_value in {"editor", "all"} else None
    if surface is None:
        return None, None
    try:
        repair_context, repair_workspace = _repair_context_from_managed_install(context, managed_install)
        hook_state = cursor_native_hook_state(repair_context)
    except (OSError, RuntimeError, json.JSONDecodeError, sqlite3.Error) as error:
        return None, f"Could not inspect Cursor protection during update: {error}"
    if hook_state["protection_active"] is True:
        return None, None
    try:
        payload = apply_managed_install(
            "install",
            "cursor",
            False,
            repair_context,
            store,
            repair_workspace or workspace,
            now,
            surface=surface,
        )
    except (OSError, RuntimeError, json.JSONDecodeError, sqlite3.Error) as error:
        return None, f"Could not repair Cursor protection during update: {error}"
    repaired = payload.get("managed_install")
    if not isinstance(repaired, dict):
        return None, "Could not repair Cursor protection during update: managed install was not recorded"
    return repaired, None


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
        manifest = managed_install.get("manifest")
        explicit_value = manifest.get("hook_workspace_explicit") if isinstance(manifest, dict) else None
        workspace_override_explicit = (
            explicit_value
            if isinstance(explicit_value, bool)
            else _legacy_codex_workspace_was_explicit(context, managed_install, workspace_path)
        )
        return (
            HarnessContext(
                home_dir=context.home_dir,
                workspace_dir=workspace_path,
                guard_home=context.guard_home,
                home_override_explicit=context.home_override_explicit,
                workspace_override_explicit=workspace_override_explicit,
            ),
            str(workspace_path),
        )
    return (
        HarnessContext(
            home_dir=context.home_dir,
            workspace_dir=None,
            guard_home=context.guard_home,
            home_override_explicit=context.home_override_explicit,
        ),
        None,
    )


def _legacy_codex_workspace_was_explicit(
    context: HarnessContext,
    managed_install: dict[str, object],
    workspace_path: Path,
) -> bool:
    if managed_install.get("harness") != "codex":
        return True
    try:
        authenticated = load_authenticated_hook_manifest(
            context.guard_home,
            CodexHarnessAdapter._hook_config_path(context),
        )
    except (CodexHookIntegrityError, OSError):
        return False
    manifest_context = authenticated.get("context")
    bound_workspace = manifest_context.get("workspace_dir") if isinstance(manifest_context, dict) else None
    return isinstance(bound_workspace, str) and Path(bound_workspace).resolve() == workspace_path


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
    if (
        bool(hook_state["protection_active"])
        and hook_state.get("integrity_status") == "valid"
        and bool(hook_state["shell_protection_active"])
    ):
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
    try:
        repaired_state = codex_native_hook_state(repair_context)
    except (OSError, RuntimeError) as error:
        return None, f"Could not verify repaired Codex protection during update: {error}"
    if not bool(repaired_state.get("protection_active")) or repaired_state.get("integrity_status") != "valid":
        reason = str(repaired_state.get("integrity_reason") or "codex_hook_integrity_readback_failed")
        return None, f"Could not verify repaired Codex protection during update: {reason}"
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
    return (context,)


def build_guard_update_status_payload() -> dict[str, object]:
    install_surface = build_guard_install_surface_payload()
    installer = str(install_surface.get("installer") or "")
    binary_diagnostics = install_surface.get("binary_diagnostics")
    if not isinstance(binary_diagnostics, dict):
        binary_diagnostics = {}
    managed_state = load_managed_policy()
    managed_policy = managed_state.policy
    source_kind = (
        "managed_index" if managed_policy is not None and managed_policy.update.index_url is not None else "pypi"
    )
    auto_updatable = True
    blocked_reason: str | None = None
    trusted_failure_reason: str | None = None
    recovery_reinstall_available = False
    installed_distribution: InstalledDistribution | None = None

    if managed_state.status != "absent" and managed_policy is None:
        auto_updatable = False
        blocked_reason = "The managed update policy is unavailable or invalid."
    elif managed_policy is not None and managed_policy.update.owner == "mdm":
        auto_updatable = False
        blocked_reason = "HOL Guard updates are managed by the organization."
    elif (
        managed_policy is not None
        and not managed_policy.network.allow_public_registries
        and managed_policy.update.index_url is None
    ):
        auto_updatable = False
        blocked_reason = "An organization-configured package source is required."
    else:
        try:
            installed_distribution = _status_installed_distribution(
                installer=installer,
                managed_policy=managed_policy,
            )
        except UpdateSubprocessError as error:
            auto_updatable = False
            trusted_failure_reason = error.reason_code
            blocked_reason = "The trusted update environment could not be verified."

    current_version = installed_distribution.version if installed_distribution is not None else "unknown"
    direct_url = installed_distribution.direct_url if installed_distribution is not None else None
    local_source_install = _local_source_install_payload(direct_url)
    local_archive_install = _recover_local_archive_install(
        _local_archive_install_payload(direct_url),
        direct_url=direct_url,
        guard_home=resolve_guard_home(),
        installed_version=current_version,
    )
    version_check = (
        _version_check_payload(
            current_version,
            source_kind=source_kind,
            network_policy=(managed_policy.network if managed_policy is not None else ManagedNetworkPolicy()),
        )
        if installed_distribution is not None
        else {
            "source": source_kind,
            "status": "unavailable",
            "current_version": None,
            "latest_version": None,
            "update_available": None,
        }
    )

    if auto_updatable and _python_runtime_blocks_update(version_check):
        auto_updatable = False
        blocked_reason = _python_runtime_block_message(version_check)
    elif auto_updatable and isinstance(direct_url, dict):
        if bool(_read_direct_url_dir_info(direct_url).get("editable")):
            auto_updatable = False
            blocked_reason = (
                "This install was set up from local source code. Re-run your usual local install command instead."
            )
        elif local_archive_install is not None and str(local_archive_install.get("archive_type") or "") == "wheel":
            auto_updatable = False
            if bool(local_archive_install.get("path_exists")):
                blocked_reason = (
                    "This install was set up from a local wheel. "
                    "Re-run `hol-guard update --wheel <wheel-or-directory>` "
                    "or your usual local install command instead."
                )
            else:
                blocked_reason = (
                    "This install was set up from a local wheel whose source file is no longer available. "
                    "Pass a new wheel with `hol-guard update --wheel <wheel-or-directory>` "
                    "or re-run your usual local install command instead."
                )
            recovery_reinstall_available = True
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
        _shell_command(["hol-guard", "update", "--force-pypi-reinstall"]) if recovery_reinstall_available else None
    )
    payload: dict[str, object] = {
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
    if trusted_failure_reason is not None:
        payload["reason_code"] = trusted_failure_reason
    return payload


def _status_installed_distribution(
    *,
    installer: str,
    managed_policy: ManagedPolicy | None,
) -> InstalledDistribution:
    network = managed_policy.network if managed_policy is not None else ManagedNetworkPolicy()
    index_url = managed_policy.update.index_url if managed_policy is not None else None
    context = build_trusted_update_context(
        guard_home=resolve_guard_home(),
        workspace_dir=None,
        installer_kind=installer,
        source_url=index_url,
        source_kind="managed_index" if index_url is not None else "pypi",
        proxy_mode=network.proxy_mode,
        proxy_url=network.proxy_url,
        ca_bundle_path=network.ca_bundle_path,
    )
    return context.query_distribution()


__all__ = ["build_guard_install_surface_payload", "build_guard_update_status_payload", "run_guard_update"]
