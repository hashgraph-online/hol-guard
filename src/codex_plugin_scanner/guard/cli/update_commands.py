"""Helpers for updating the installed HOL Guard CLI."""

from __future__ import annotations

import http.client  # noqa: F401
import importlib as importlib
import importlib.metadata  # noqa: F401
import json as json
import os as os
import platform as platform
import re as re
import shlex as shlex
import shutil as shutil
import sqlite3 as sqlite3
import subprocess as subprocess
import sys as sys
import sysconfig as sysconfig
import time as time
import urllib.error
import urllib.request  # noqa: F401
from collections.abc import Mapping as Mapping
from contextvars import ContextVar as ContextVar
from pathlib import Path as Path
from urllib.parse import ParseResult as ParseResult
from urllib.parse import urlparse as urlparse

from packaging.specifiers import InvalidSpecifier as InvalidSpecifier
from packaging.specifiers import SpecifierSet as SpecifierSet
from packaging.version import InvalidVersion as InvalidVersion
from packaging.version import Version as Version

from ... import version as package_version  # noqa: F401
from ..adapters.base import HarnessContext as HarnessContext
from ..adapters.codex import CodexHarnessAdapter as CodexHarnessAdapter
from ..adapters.codex import codex_native_hook_state as codex_native_hook_state
from ..adapters.cursor_hooks import cursor_native_hook_state as cursor_native_hook_state
from ..adapters.opencode_pretool import global_plugin_path as global_plugin_path
from ..adapters.opencode_pretool import install_pretool_plugin as install_pretool_plugin
from ..adapters.opencode_pretool import managed_plugin_path as managed_plugin_path
from ..adapters.opencode_pretool import pretool_plugin_source as pretool_plugin_source
from ..adapters.pi import OmpHarnessAdapter as OmpHarnessAdapter
from ..adapters.pi import PiHarnessAdapter as PiHarnessAdapter
from ..adapters.pi_extension_source import managed_extension_source as managed_extension_source
from ..adapters.pi_support import json_payload as json_payload
from ..config import load_guard_config as load_guard_config
from ..config import resolve_guard_home as resolve_guard_home
from ..daemon.runtime_peer import daemon_refresh_outcome_succeeded as _daemon_refresh_outcome_succeeded  # noqa: F401
from ..daemon.runtime_peer import retained_desktop_owner_note as retained_desktop_owner_note
from ..daemon.runtime_peer import retained_desktop_owner_payload as retained_desktop_owner_payload
from ..daemon.runtime_peer import retained_newer_runtime_payload as _verified_newer_guard_daemon  # noqa: F401
from ..daemon.update_refresh_program import DAEMON_REFRESH_SCRIPT as DAEMON_REFRESH_SCRIPT
from ..mdm.contracts import ManagedNetworkPolicy as ManagedNetworkPolicy
from ..mdm.contracts import ManagedPolicy as ManagedPolicy
from ..mdm.network import ManagedNetworkError as ManagedNetworkError
from ..mdm.network import managed_urlopen as managed_urlopen
from ..mdm.policy import load_managed_policy as load_managed_policy
from ..redaction import redact_sensitive_text as redact_sensitive_text
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_authority import AuthorityHealth as AuthorityHealth
from ..store import GuardStore as GuardStore
from .install_commands import apply_managed_install as apply_managed_install
from .managed_install_context import managed_install_context as _repair_context_from_managed_install  # noqa: F401
from .update_artifact import TrustedWheelArtifact as TrustedWheelArtifact
from .update_artifact import UpdateArtifactError as UpdateArtifactError
from .update_artifact import record_local_wheel_receipt as record_local_wheel_receipt
from .update_artifact import recover_local_wheel_original as recover_local_wheel_original
from .update_artifact import stage_trusted_wheel as stage_trusted_wheel
from .update_desktop_apply import desktop_update_status_state as desktop_update_status_state
from .update_desktop_apply import finalize_desktop_update_status as finalize_desktop_update_status
from .update_desktop_apply import run_desktop_managed_update as run_desktop_managed_update
from .update_desktop_core import is_desktop_managed_runtime as is_desktop_managed_runtime
from .update_grok_repair import append_grok_repair as append_grok_repair
from .update_install_verify import verify_installed_distribution as verify_installed_distribution
from .update_release_candidates import newest_pypi_version as newest_pypi_version
from .update_subprocess import InstalledDistribution as InstalledDistribution
from .update_subprocess import TrustedUpdateContext as TrustedUpdateContext
from .update_subprocess import UpdateSubprocessError as UpdateSubprocessError
from .update_subprocess import build_trusted_update_context as build_trusted_update_context

_TRUSTED_UPDATE_FAILURE_MESSAGES = {
    "update_install_inconsistent": (
        "HOL Guard updated its version metadata but not all of its installed files. "
        "Retry the update to finish the installation."
    ),
}

_ALREADY_CURRENT_HINTS = (
    "already at latest version",
    "already up-to-date",
    "nothing to upgrade",
    "is pinned to",
)
_PIPX_LAUNCHER_FAILURE_HINTS = (
    "ModuleNotFoundError: No module named 'pipx'",
    'ModuleNotFoundError: No module named "pipx"',
    "venv for 'hol-guard' was not found",
    'venv for "hol-guard" was not found',
)
_PYPI_PROPAGATION_FAILURE_HINTS = (
    "No matching distribution found for hol-guard==",
    "Could not find a version that satisfies the requirement hol-guard==",
)
_PYPI_PROPAGATION_EXCLUSION_HINTS = (
    "authentication",
    "certificate verify failed",
    "connection error",
    "connection refused",
    "connection reset",
    "could not fetch url",
    "credential",
    "forbidden",
    "invalid index",
    "name or service not known",
    "ssl",
    "temporary failure in name resolution",
    "timed out",
    "timeout",
    "tls",
    "unauthorized",
)
_PYPI_AUTH_STATUS_RE = re.compile(
    r"(?:\b(?:http(?:\s+error)?|status(?:\s+code)?|error:)\s*(?:401|403)\b|"
    r"\b(?:401|403)\s+(?:unauthorized|forbidden)\b)",
    re.IGNORECASE,
)
_PYPI_PROPAGATION_RETRY_DELAY_SECONDS = 2.0
_PYPI_PROPAGATION_RETRY_LIMIT = 1
_PYPI_JSON_URL = "https://pypi.org/pypi/hol-guard/json"
_GITHUB_ALPHA_REFS_URL = "https://api.github.com/repos/hashgraph-online/hol-guard/git/matching-refs/tags/alpha/v"
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
_DAEMON_REFRESH_SCRIPT = DAEMON_REFRESH_SCRIPT
_DAEMON_REFRESH_BOOTSTRAP_SCRIPT = """
from codex_plugin_scanner.guard.daemon.update_refresh_program import DAEMON_REFRESH_SCRIPT

exec(DAEMON_REFRESH_SCRIPT, {})
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


# Helpers resolve these live facade bindings only when their functions are called.
from .update_driver import _authority_blocks_downgrade as _authority_blocks_downgrade  # noqa: E402
from .update_driver import _read_direct_url_dir_info as _read_direct_url_dir_info  # noqa: E402
from .update_driver import run_guard_update as run_guard_update  # noqa: E402
from .update_execution import _execute_update as _execute_update  # noqa: E402
from .update_harness_repair import _codex_backup_repair_contexts as _codex_backup_repair_contexts  # noqa: E402
from .update_harness_repair import _codex_backup_repair_target as _codex_backup_repair_target  # noqa: E402
from .update_harness_repair import _codex_repair_target as _codex_repair_target  # noqa: E402
from .update_harness_repair import _pi_family_extension_is_current as _pi_family_extension_is_current  # noqa: E402
from .update_harness_repair import _refresh_opencode_pretool_plugin as _refresh_opencode_pretool_plugin  # noqa: E402
from .update_harness_repair import _repair_codex_install as _repair_codex_install  # noqa: E402
from .update_harness_repair import _repair_cursor_install as _repair_cursor_install  # noqa: E402
from .update_harness_repair import _repair_pi_family_install as _repair_pi_family_install  # noqa: E402
from .update_harness_repair import _repair_supported_harnesses as _repair_supported_harnesses  # noqa: E402
from .update_harness_repair import (  # noqa: E402
    _repair_supported_harnesses_in_process as _repair_supported_harnesses_in_process,
)
from .update_install_sources import _credential_safe_url as _credential_safe_url  # noqa: E402
from .update_install_sources import _direct_url_archive_sha256 as _direct_url_archive_sha256  # noqa: E402
from .update_install_sources import _direct_url_payload as _direct_url_payload  # noqa: E402
from .update_install_sources import _file_url_to_path as _file_url_to_path  # noqa: E402
from .update_install_sources import _local_archive_install_payload as _local_archive_install_payload  # noqa: E402
from .update_install_sources import _local_archive_update_hint as _local_archive_update_hint  # noqa: E402
from .update_install_sources import _local_source_install_payload as _local_source_install_payload  # noqa: E402
from .update_install_sources import _parsed_hol_guard_wheel_version as _parsed_hol_guard_wheel_version  # noqa: E402
from .update_install_sources import _public_direct_url_payload as _public_direct_url_payload  # noqa: E402
from .update_install_sources import _recover_local_archive_install as _recover_local_archive_install  # noqa: E402
from .update_install_sources import _resolve_requested_wheel_path as _resolve_requested_wheel_path  # noqa: E402
from .update_install_sources import _safe_path_exists as _safe_path_exists  # noqa: E402
from .update_install_sources import _safe_resolve_path as _safe_resolve_path  # noqa: E402
from .update_install_sources import _vcs_install_payload as _vcs_install_payload  # noqa: E402
from .update_installer_commands import _binary_diagnostics as _binary_diagnostics  # noqa: E402
from .update_installer_commands import _contains_any as _contains_any  # noqa: E402
from .update_installer_commands import _current_version as _current_version  # noqa: E402
from .update_installer_commands import _dependency_conflict_message as _dependency_conflict_message  # noqa: E402
from .update_installer_commands import _directory_path as _directory_path  # noqa: E402
from .update_installer_commands import _expected_script_dir as _expected_script_dir  # noqa: E402
from .update_installer_commands import _hol_guard_package_spec as _hol_guard_package_spec  # noqa: E402
from .update_installer_commands import _installer_kind as _installer_kind  # noqa: E402
from .update_installer_commands import _installer_output_text as _installer_output_text  # noqa: E402
from .update_installer_commands import _is_desktop_managed_runtime as _is_desktop_managed_runtime  # noqa: E402
from .update_installer_commands import _is_frozen_runtime as _is_frozen_runtime  # noqa: E402
from .update_installer_commands import _is_pypi_propagation_failure as _is_pypi_propagation_failure  # noqa: E402
from .update_installer_commands import _runtime_installer_kind as _runtime_installer_kind  # noqa: E402
from .update_installer_commands import _runtime_package_path as _runtime_package_path  # noqa: E402
from .update_installer_commands import _script_dir as _script_dir  # noqa: E402
from .update_installer_commands import _should_upgrade_from_pypi as _should_upgrade_from_pypi  # noqa: E402
from .update_installer_commands import _target_version_is_prerelease as _target_version_is_prerelease  # noqa: E402
from .update_installer_commands import _update_command as _update_command  # noqa: E402
from .update_installer_commands import (  # noqa: E402
    build_guard_install_surface_payload as build_guard_install_surface_payload,
)
from .update_output import _append_payload_note as _append_payload_note  # noqa: E402
from .update_output import _is_stale_install as _is_stale_install  # noqa: E402
from .update_output import _merge_version_checks as _merge_version_checks  # noqa: E402
from .update_output import _normalize_output_text as _normalize_output_text  # noqa: E402
from .update_output import _output_lines as _output_lines  # noqa: E402
from .update_output import _payload_notes as _payload_notes  # noqa: E402
from .update_output import _planned_update_message as _planned_update_message  # noqa: E402
from .update_output import _safe_update_retry_command as _safe_update_retry_command  # noqa: E402
from .update_output import _shell_command as _shell_command  # noqa: E402
from .update_output import _stale_retry_command as _stale_retry_command  # noqa: E402
from .update_output import _string_list as _string_list  # noqa: E402
from .update_output import _success_message as _success_message  # noqa: E402
from .update_output import _success_notes as _success_notes  # noqa: E402
from .update_output import _success_status as _success_status  # noqa: E402
from .update_output import _version_changed as _version_changed  # noqa: E402
from .update_receipt_results import (  # noqa: E402
    _record_verified_local_wheel_receipt as _record_verified_local_wheel_receipt,
)
from .update_receipt_results import _retain_local_wheel_staging as _retain_local_wheel_staging  # noqa: E402
from .update_receipt_results import _trusted_update_failure as _trusted_update_failure  # noqa: E402
from .update_runtime_refresh import (  # noqa: E402
    _cleanup_failed_guard_daemon_refresh as _cleanup_failed_guard_daemon_refresh,
)
from .update_runtime_refresh import _daemon_refresh_failure_note as _daemon_refresh_failure_note  # noqa: E402
from .update_runtime_refresh import (  # noqa: E402
    _package_shim_manifest_has_installed_managers as _package_shim_manifest_has_installed_managers,
)
from .update_runtime_refresh import _package_shim_refresh_note as _package_shim_refresh_note  # noqa: E402
from .update_runtime_refresh import (  # noqa: E402
    _refresh_package_shims_after_update as _refresh_package_shims_after_update,
)
from .update_runtime_refresh import _standalone_update_context as _standalone_update_context  # noqa: E402
from .update_runtime_refresh import refresh_guard_daemon_after_update as refresh_guard_daemon_after_update  # noqa: E402
from .update_status import _current_version_from_subprocess as _current_version_from_subprocess  # noqa: E402
from .update_status import _status_installed_distribution as _status_installed_distribution  # noqa: E402
from .update_status import _trusted_update_public_payload as _trusted_update_public_payload  # noqa: E402
from .update_status import build_guard_update_status_payload as build_guard_update_status_payload  # noqa: E402
from .update_version_selection import _format_python_requirements as _format_python_requirements  # noqa: E402
from .update_version_selection import _is_newer_version as _is_newer_version  # noqa: E402
from .update_version_selection import _latest_alpha_version_from_pypi as _latest_alpha_version_from_pypi  # noqa: E402
from .update_version_selection import (  # noqa: E402
    _latest_compatible_release_version as _latest_compatible_release_version,
)
from .update_version_selection import _latest_version_from_pypi as _latest_version_from_pypi  # noqa: E402
from .update_version_selection import (  # noqa: E402
    _latest_version_python_requirements as _latest_version_python_requirements,
)
from .update_version_selection import _newest_reserved_alpha_version as _newest_reserved_alpha_version  # noqa: E402
from .update_version_selection import _python_requirements_satisfied as _python_requirements_satisfied  # noqa: E402
from .update_version_selection import _python_runtime_block_message as _python_runtime_block_message  # noqa: E402
from .update_version_selection import _python_runtime_blocks_update as _python_runtime_blocks_update  # noqa: E402
from .update_version_selection import _read_bounded_pypi_response as _read_bounded_pypi_response  # noqa: E402
from .update_version_selection import _release_has_non_yanked_file as _release_has_non_yanked_file  # noqa: E402
from .update_version_selection import _runtime_python_version as _runtime_python_version  # noqa: E402
from .update_version_selection import _version_check_payload as _version_check_payload  # noqa: E402
from .update_version_selection import already_current_update_message as already_current_update_message  # noqa: E402
from .update_version_selection import select_reserved_alpha_version as select_reserved_alpha_version  # noqa: E402

__all__ = ["build_guard_install_surface_payload", "build_guard_update_status_payload", "run_guard_update"]
