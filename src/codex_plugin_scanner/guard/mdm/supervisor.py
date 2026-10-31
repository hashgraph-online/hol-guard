"""Native machine supervisor installation and fail-honest health verification.

The native runtime reads the LaunchDaemon property list, runs ``launchctl`` or
``schtasks`` and decides what that evidence says. Without a runtime that can
check, the supervisor's health is unknown.
"""

from __future__ import annotations

import json
import ntpath
import os
import platform
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, cast, get_args
from xml.etree import ElementTree

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
_WINDOWS_TASK_NAME = r"\HOL Guard\Machine Health"
_TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_HEALTH_ARGUMENTS = "mdm health-report --scope machine --json"
_WINDOWS_TASK_START_BOUNDARY = "2000-01-01T00:00:00"
_WINDOWS_TASK_SECURITY_DESCRIPTOR = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
_MAX_REGISTRATION_BYTES = 256 * 1024
_PROBE_TIMEOUT_SECONDS = 10
_ABSENT_HRESULTS = {2, 0x80070002, -2147024894}
SUPERVISOR_VERDICT_FEATURE = "native-supervisor-verdict-v1"
SUPERVISOR_PROBE_FEATURE = "native-supervisor-probe-v1"
SUPERVISOR_VERDICT_COMMAND = "supervisor-verdict"
SUPERVISOR_VERDICT_SCHEMA = "supervisor-verdict.v1"
_STATUS_TIMEOUT_SECONDS = 10.0
_COMMAND_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT_BYTES = 16 * 1024


def machine_executable(paths: MachinePaths, system_name: str) -> Path:
    executable = "hol-guard.exe" if system_name == "Windows" else "hol-guard"
    return paths.runtime_root / "hol-guard" / executable


def _native_verdict(request: dict[str, object]) -> SupervisorStatus:
    """The runtime's verdict after it gathered the supervisor's evidence itself."""

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
        and SUPERVISOR_PROBE_FEATURE in status.capabilities.features
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
    if not isinstance(answer, dict) or cast(dict[str, Any], answer).get("ok") is not True:
        # A supervisor nothing could check is never reported as running.
        raise OSError("supervisor_verdict_native_unavailable")
    return _status(cast(dict[str, Any], answer))


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


def _windows_process_context() -> tuple[str, dict[str, str]]:
    windows_directory = _windows_directory()
    system_drive, _ = ntpath.splitdrive(windows_directory)
    if not system_drive:
        raise OSError("windows_system_drive_unavailable")
    system_directory = ntpath.join(windows_directory, "System32")
    return system_directory, {
        "ComSpec": ntpath.join(system_directory, "cmd.exe"),
        "SystemDrive": system_drive,
        "SystemRoot": windows_directory,
        "WINDIR": windows_directory,
    }


def _run_schtasks(*arguments: str) -> subprocess.CompletedProcess[str]:
    system_directory, environment = _windows_process_context()
    executable = ntpath.join(system_directory, "schtasks.exe")
    result = subprocess.run(
        [executable, *arguments],
        check=False,
        capture_output=True,
        cwd=system_directory,
        env=environment,
        text=True,
        timeout=_PROBE_TIMEOUT_SECONDS,
    )
    if len(result.stdout.encode("utf-8")) > _MAX_REGISTRATION_BYTES or len(result.stderr.encode("utf-8")) > 4096:
        raise OSError("supervisor_probe_output_exceeded")
    return result


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


def _windows_task_xml(paths: MachinePaths) -> bytes:
    ElementTree.register_namespace("", _TASK_NAMESPACE)
    task = ElementTree.Element(f"{{{_TASK_NAMESPACE}}}Task", {"version": "1.4"})
    registration = ElementTree.SubElement(task, f"{{{_TASK_NAMESPACE}}}RegistrationInfo")
    ElementTree.SubElement(registration, f"{{{_TASK_NAMESPACE}}}URI").text = _WINDOWS_TASK_NAME
    ElementTree.SubElement(
        registration, f"{{{_TASK_NAMESPACE}}}SecurityDescriptor"
    ).text = _WINDOWS_TASK_SECURITY_DESCRIPTOR
    triggers = ElementTree.SubElement(task, f"{{{_TASK_NAMESPACE}}}Triggers")
    trigger = ElementTree.SubElement(triggers, f"{{{_TASK_NAMESPACE}}}TimeTrigger")
    ElementTree.SubElement(trigger, f"{{{_TASK_NAMESPACE}}}Enabled").text = "true"
    ElementTree.SubElement(trigger, f"{{{_TASK_NAMESPACE}}}StartBoundary").text = _WINDOWS_TASK_START_BOUNDARY
    repetition = ElementTree.SubElement(trigger, f"{{{_TASK_NAMESPACE}}}Repetition")
    ElementTree.SubElement(repetition, f"{{{_TASK_NAMESPACE}}}Interval").text = "PT5M"
    ElementTree.SubElement(repetition, f"{{{_TASK_NAMESPACE}}}StopAtDurationEnd").text = "false"
    principals = ElementTree.SubElement(task, f"{{{_TASK_NAMESPACE}}}Principals")
    principal = ElementTree.SubElement(principals, f"{{{_TASK_NAMESPACE}}}Principal", {"id": "System"})
    ElementTree.SubElement(principal, f"{{{_TASK_NAMESPACE}}}UserId").text = "S-1-5-18"
    ElementTree.SubElement(principal, f"{{{_TASK_NAMESPACE}}}LogonType").text = "ServiceAccount"
    ElementTree.SubElement(principal, f"{{{_TASK_NAMESPACE}}}RunLevel").text = "HighestAvailable"
    settings = ElementTree.SubElement(task, f"{{{_TASK_NAMESPACE}}}Settings")
    for name, value in (
        ("MultipleInstancesPolicy", "IgnoreNew"),
        ("DisallowStartIfOnBatteries", "false"),
        ("StopIfGoingOnBatteries", "false"),
        ("StartWhenAvailable", "true"),
        ("Enabled", "true"),
        ("Hidden", "true"),
        ("ExecutionTimeLimit", "PT5M"),
    ):
        ElementTree.SubElement(settings, f"{{{_TASK_NAMESPACE}}}{name}").text = value
    actions = ElementTree.SubElement(task, f"{{{_TASK_NAMESPACE}}}Actions", {"Context": "System"})
    action = ElementTree.SubElement(actions, f"{{{_TASK_NAMESPACE}}}Exec")
    ElementTree.SubElement(action, f"{{{_TASK_NAMESPACE}}}Command").text = ntpath.normpath(
        str(machine_executable(paths, "Windows"))
    )
    ElementTree.SubElement(action, f"{{{_TASK_NAMESPACE}}}Arguments").text = _HEALTH_ARGUMENTS
    return ElementTree.tostring(task, encoding="utf-16", xml_declaration=True)


def _windows_is_administrator() -> bool:
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def install_machine_supervisor() -> dict[str, object]:
    """Install the Windows SYSTEM health task from a machine installer context."""

    if platform.system() != "Windows":
        raise OSError("supervisor_platform_unsupported")
    if not _windows_is_administrator():
        raise PermissionError("supervisor_administrator_required")
    paths = default_machine_paths(system_name="Windows")
    executable = machine_executable(paths, "Windows")
    if executable.is_symlink() or not executable.is_file() or not paths.state_root.is_dir():
        raise OSError("supervisor_runtime_absent")
    descriptor, temporary_name = tempfile.mkstemp(prefix="health-task-", suffix=".xml", dir=paths.state_root)
    temporary_path = Path(temporary_name)
    try:
        payload = _windows_task_xml(paths)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("supervisor_registration_write_failed")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        result = _run_schtasks("/Create", "/TN", _WINDOWS_TASK_NAME, "/XML", str(temporary_path), "/F", "/HRESULT")
        if result.returncode != 0:
            raise OSError("supervisor_registration_failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
    return {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "supervisor-install",
        "healthy": True,
        "state": "running",
        "reasonCodes": ["supervisor_running"],
    }


def remove_machine_supervisor() -> dict[str, object]:
    """Remove the Windows SYSTEM health task from a machine installer context."""

    if platform.system() != "Windows":
        raise OSError("supervisor_platform_unsupported")
    if not _windows_is_administrator():
        raise PermissionError("supervisor_administrator_required")
    result = _run_schtasks("/Delete", "/TN", _WINDOWS_TASK_NAME, "/F", "/HRESULT")
    if result.returncode not in {0, *_ABSENT_HRESULTS}:
        raise OSError("supervisor_removal_failed")
    return {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "supervisor-remove",
        "healthy": True,
        "state": "absent",
        "reasonCodes": [],
    }


__all__ = ["install_machine_supervisor", "remove_machine_supervisor", "verify_machine_supervisor"]
