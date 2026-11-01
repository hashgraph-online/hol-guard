"""Native machine supervisor installation and fail-honest health verification.

The native runtime reads the LaunchDaemon property list, runs ``launchctl`` or
``schtasks`` and decides what that evidence says. It also registers and
deletes the Windows SYSTEM task. Without a runtime that can check, the
supervisor's health is unknown.
"""

from __future__ import annotations

import json
import platform
import subprocess
import time
from pathlib import Path
from typing import Any, cast, get_args

from .contracts import (
    IntegrityReasonCode,
    MachinePaths,
    SupervisorState,
    SupervisorStatus,
    default_machine_paths,
)
from .windows_support import windows_directory

_MACOS_LABEL = "org.hol.guard.machine-health"
_MACOS_PLIST = Path(f"/Library/LaunchDaemons/{_MACOS_LABEL}.plist")
SUPERVISOR_VERDICT_FEATURE = "native-supervisor-verdict-v1"
SUPERVISOR_PROBE_FEATURE = "native-supervisor-probe-v1"
SUPERVISOR_INSTALL_FEATURE = "native-supervisor-install-v1"
SUPERVISOR_VERDICT_COMMAND = "supervisor-verdict"
SUPERVISOR_VERDICT_SCHEMA = "supervisor-verdict.v1"
_STATUS_TIMEOUT_SECONDS = 10.0
_COMMAND_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT_BYTES = 16 * 1024
_TASK_ERRORS = frozenset(
    {
        "supervisor_runtime_absent",
        "windows_system_drive_unavailable",
        "supervisor_registration_write_failed",
        "supervisor_registration_failed",
        "supervisor_removal_failed",
    }
)


def machine_executable(paths: MachinePaths, system_name: str) -> Path:
    executable = "hol-guard.exe" if system_name == "Windows" else "hol-guard"
    return paths.runtime_root / "hol-guard" / executable


def _native_answer(request: dict[str, object], feature: str) -> dict[str, Any]:
    """The runtime's answer to one supervisor op that needs ``feature``."""

    from ..native_runtime import _run_native_process, native_runtime_status

    deadline = time.monotonic() + _COMMAND_TIMEOUT_SECONDS
    status = native_runtime_status(deadline_monotonic=min(deadline, time.monotonic() + _STATUS_TIMEOUT_SECONDS))
    remaining = deadline - time.monotonic()
    output = None
    if (
        remaining > 0
        and status.available
        and status.compatible
        and status.identity is not None
        and status.capabilities is not None
        and SUPERVISOR_VERDICT_FEATURE in status.capabilities.features
        and feature in status.capabilities.features
    ):
        output = _run_native_process(
            status.identity.path,
            (SUPERVISOR_VERDICT_COMMAND, "--stdin"),
            input_text=json.dumps({"schema": SUPERVISOR_VERDICT_SCHEMA, **request}, sort_keys=True),
            timeout_seconds=remaining,
            output_limit=_OUTPUT_LIMIT_BYTES,
        )
    try:
        answer = cast(object, json.loads(output or ""))
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        raise OSError("supervisor_verdict_native_unavailable")
    return cast(dict[str, Any], answer)


def _native_verdict(request: dict[str, object]) -> SupervisorStatus:
    """The runtime's verdict after it gathered the supervisor's evidence itself."""

    answer = _native_answer(request, SUPERVISOR_PROBE_FEATURE)
    if answer.get("ok") is not True:
        # A supervisor nothing could check is never reported as running.
        raise OSError("supervisor_verdict_native_unavailable")
    return _status(answer)


def _native_task_change(request: dict[str, object], state: SupervisorState) -> None:
    """Have the runtime register or delete the Windows task, or raise why it could not."""

    answer = _native_answer(request, SUPERVISOR_INSTALL_FEATURE)
    error = answer.get("error")
    if answer.get("ok") is not True:
        known = isinstance(error, str) and error in _TASK_ERRORS
        raise OSError(error if known else "supervisor_verdict_native_unavailable")
    if answer.get("state") != state:
        raise OSError("supervisor_verdict_native_unavailable")


def _status(answer: dict[str, Any]) -> SupervisorStatus:
    state = answer.get("state")
    reason_code = answer.get("reason_code")
    if state not in get_args(SupervisorState) or reason_code not in get_args(IntegrityReasonCode):
        raise OSError("supervisor_verdict_native_unavailable")
    return SupervisorStatus(cast(SupervisorState, state), cast(IntegrityReasonCode, reason_code))


def _verify_macos_supervisor(paths: MachinePaths, plist_path: Path) -> SupervisorStatus:
    try:
        return _native_verdict(
            {
                "op": "macos-verify",
                "executable": str(machine_executable(paths, "Darwin")),
                "plist_file": str(plist_path),
                "plist_path": str(_MACOS_PLIST),
                "stdout_log": str(paths.log_root / "machine-health.log"),
                "stderr_log": str(paths.log_root / "machine-health-error.log"),
            }
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return SupervisorStatus("unknown", "supervisor_probe_failed")


_windows_directory = windows_directory


def _verify_windows_supervisor(paths: MachinePaths) -> SupervisorStatus:
    try:
        return _native_verdict(
            {
                "op": "windows-verify",
                "executable": str(machine_executable(paths, "Windows")),
                "windows_directory": _windows_directory(),
            }
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return SupervisorStatus("unknown", "supervisor_probe_failed")


def verify_machine_supervisor(
    paths: MachinePaths,
    *,
    system_name: str | None = None,
    macos_plist_path: Path = _MACOS_PLIST,
) -> SupervisorStatus:
    """Verify the protected machine health runner without trusting process path overrides."""

    resolved_system = system_name or platform.system()
    if resolved_system == "Darwin":
        return _verify_macos_supervisor(paths, macos_plist_path)
    if resolved_system == "Windows":
        return _verify_windows_supervisor(paths)
    return SupervisorStatus("unsupported", "supervisor_platform_unsupported")


def _windows_is_administrator() -> bool:
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def _require_windows_administrator() -> None:
    if platform.system() != "Windows":
        raise OSError("supervisor_platform_unsupported")
    if not _windows_is_administrator():
        raise PermissionError("supervisor_administrator_required")


def install_machine_supervisor() -> dict[str, object]:
    """Install the Windows SYSTEM health task from a machine installer context."""

    _require_windows_administrator()
    paths = default_machine_paths(system_name="Windows")
    _native_task_change(
        {
            "op": "windows-install",
            "executable": str(machine_executable(paths, "Windows")),
            "windows_directory": _windows_directory(),
            "state_root": str(paths.state_root),
        },
        "running",
    )
    return {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "supervisor-install",
        "healthy": True,
        "state": "running",
        "reasonCodes": ["supervisor_running"],
    }


def remove_machine_supervisor() -> dict[str, object]:
    """Remove the Windows SYSTEM health task from a machine installer context."""

    _require_windows_administrator()
    paths = default_machine_paths(system_name="Windows")
    _native_task_change(
        {
            "op": "windows-remove",
            "executable": str(machine_executable(paths, "Windows")),
            "windows_directory": _windows_directory(),
        },
        "absent",
    )
    return {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "supervisor-remove",
        "healthy": True,
        "state": "absent",
        "reasonCodes": [],
    }


__all__ = ["install_machine_supervisor", "remove_machine_supervisor", "verify_machine_supervisor"]
