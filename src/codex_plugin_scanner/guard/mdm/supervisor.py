"""Native machine supervisor installation and fail-honest health verification."""

from __future__ import annotations

import ntpath
import os
import platform
import plistlib
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from xml.etree import ElementTree

from .contracts import MachinePaths, SupervisorStatus, default_machine_paths

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


def machine_executable(paths: MachinePaths, system_name: str) -> Path:
    executable = "hol-guard.exe" if system_name == "Windows" else "hol-guard"
    return paths.runtime_root / "hol-guard" / executable


def _bounded_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_REGISTRATION_BYTES:
            raise OSError("supervisor_registration_invalid")
        chunks: list[bytes] = []
        remaining = _MAX_REGISTRATION_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        fingerprint_before = (before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns)
        fingerprint_after = (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns)
        if (
            len(payload) > _MAX_REGISTRATION_BYTES
            or len(payload) != before.st_size
            or fingerprint_before != fingerprint_after
        ):
            raise OSError("supervisor_registration_changed")
        return payload
    finally:
        os.close(descriptor)


def _macos_registration_status(paths: MachinePaths, plist_path: Path) -> SupervisorStatus | None:
    try:
        payload = plistlib.loads(_bounded_regular_file(plist_path))
    except FileNotFoundError:
        return SupervisorStatus("absent", "supervisor_absent")
    except (OSError, plistlib.InvalidFileException, ValueError):
        return SupervisorStatus("unknown", "supervisor_probe_failed")
    if not isinstance(payload, dict) or payload.get("Label") != _MACOS_LABEL:
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    expected_arguments = [
        str(machine_executable(paths, "Darwin")),
        "mdm",
        "health-report",
        "--scope",
        "machine",
        "--json",
    ]
    arguments = payload.get("ProgramArguments")
    if not isinstance(arguments, list) or arguments != expected_arguments:
        return SupervisorStatus("stopped", "supervisor_executable_mismatch")
    expected_environment = {
        "HOME": "/var/root",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": "/var/tmp",
    }
    if payload.get("EnvironmentVariables") != expected_environment:
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    if (
        payload.get("RunAtLoad") is not True
        or payload.get("StartInterval") != 300
        or payload.get("ProcessType") != "Background"
    ):
        return SupervisorStatus("stopped", "supervisor_schedule_invalid")
    if payload.get("StandardOutPath") != str(paths.log_root / "machine-health.log") or payload.get(
        "StandardErrorPath"
    ) != str(paths.log_root / "machine-health-error.log"):
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    return None


def _run_macos_launchctl(*arguments: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["/bin/launchctl", *arguments],
        check=False,
        capture_output=True,
        cwd="/",
        env={"HOME": "/var/root", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": "/var/tmp"},
        text=True,
        timeout=_PROBE_TIMEOUT_SECONDS,
    )
    if len(result.stdout.encode("utf-8")) > _MAX_REGISTRATION_BYTES or len(result.stderr.encode("utf-8")) > 4096:
        raise OSError("supervisor_probe_output_exceeded")
    return result


def _verify_macos_supervisor(paths: MachinePaths, plist_path: Path) -> SupervisorStatus:
    registration = _macos_registration_status(paths, plist_path)
    if registration is not None:
        return registration
    try:
        disabled = _run_macos_launchctl("print-disabled", "system")
        if disabled.returncode != 0:
            return SupervisorStatus("unknown", "supervisor_probe_failed")
        pattern = rf'"{re.escape(_MACOS_LABEL)}"\s*=>\s*true'
        if re.search(pattern, disabled.stdout, re.IGNORECASE):
            return SupervisorStatus("disabled", "supervisor_disabled")
        loaded = _run_macos_launchctl("print", f"system/{_MACOS_LABEL}")
        if loaded.returncode != 0:
            return SupervisorStatus("stopped", "supervisor_stopped")
        loaded_status = _macos_loaded_status(paths, loaded.stdout)
        if loaded_status is not None:
            return loaded_status
        return SupervisorStatus("running", "supervisor_running")
    except (OSError, subprocess.SubprocessError):
        return SupervisorStatus("unknown", "supervisor_probe_failed")


def _launchctl_scalar(output: str, name: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(name)}\s*=\s*(.*?)\s*$", output)
    return match.group(1) if match is not None else None


def _launchctl_arguments(output: str) -> list[str] | None:
    match = re.search(r"(?ms)^\s*arguments\s*=\s*\{\s*\n(?P<body>.*?)^\s*\}\s*$", output)
    if match is None:
        return None
    return [line.strip() for line in match.group("body").splitlines() if line.strip()]


def _macos_loaded_status(paths: MachinePaths, output: str) -> SupervisorStatus | None:
    expected_executable = str(machine_executable(paths, "Darwin"))
    expected_arguments = [expected_executable, "mdm", "health-report", "--scope", "machine", "--json"]
    if _launchctl_scalar(output, "path") != str(_MACOS_PLIST):
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    if _launchctl_scalar(output, "program") != expected_executable:
        return SupervisorStatus("stopped", "supervisor_executable_mismatch")
    if _launchctl_arguments(output) != expected_arguments:
        return SupervisorStatus("stopped", "supervisor_executable_mismatch")
    if _launchctl_scalar(output, "run interval") != "300 seconds":
        return SupervisorStatus("stopped", "supervisor_schedule_invalid")
    if _launchctl_scalar(output, "state") not in {"running", "not running"}:
        return SupervisorStatus("stopped", "supervisor_stopped")
    return None


def _windows_directory() -> str:
    import ctypes

    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buffer, len(buffer)))
    if length == 0 or length >= len(buffer):
        raise OSError("windows_system_directory_unavailable")
    return ntpath.normpath(str(buffer.value))


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


def _xml_text(root: ElementTree.Element, path: str) -> str | None:
    element = root.find(path, {"task": _TASK_NAMESPACE})
    return element.text if element is not None else None


def _windows_security_descriptor_valid(descriptor: str | None) -> bool:
    if descriptor is None:
        return False
    match = re.fullmatch(
        r"(?:O:(?:BA|SY|S-1-5-32-544|S-1-5-18))?"
        r"(?:G:(?:BA|SY|S-1-5-32-544|S-1-5-18))?"
        r"D:P(?P<aces>(?:\([^()]+\))+)",
        descriptor,
        re.IGNORECASE,
    )
    if match is None:
        return False
    aliases = {"SY": "S-1-5-18", "BA": "S-1-5-32-544"}
    normalized_aces: list[str] = []
    for ace in re.findall(r"\(([^()]+)\)", match.group("aces")):
        fields = ace.upper().split(";")
        if len(fields) != 6:
            return False
        fields[5] = aliases.get(fields[5], fields[5])
        normalized_aces.append(f"({';'.join(fields)})")
    return len(normalized_aces) == 2 and set(normalized_aces) == {
        "(A;;FA;;;S-1-5-18)",
        "(A;;FA;;;S-1-5-32-544)",
    }


def _windows_registration_status(paths: MachinePaths, xml_text: str) -> SupervisorStatus:
    try:
        root = ElementTree.fromstring(xml_text.lstrip("\ufeff"))
    except ElementTree.ParseError:
        return SupervisorStatus("unknown", "supervisor_probe_failed")
    if root.tag != f"{{{_TASK_NAMESPACE}}}Task":
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    enabled = _xml_text(root, "./task:Settings/task:Enabled")
    if enabled is not None and enabled.casefold() == "false":
        return SupervisorStatus("disabled", "supervisor_disabled")
    if _xml_text(root, "./task:RegistrationInfo/task:URI") != _WINDOWS_TASK_NAME:
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    if not _windows_security_descriptor_valid(_xml_text(root, "./task:RegistrationInfo/task:SecurityDescriptor")):
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    principals = root.findall("./task:Principals/task:Principal", {"task": _TASK_NAMESPACE})
    if len(principals) != 1:
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    principal = principals[0]
    user_id = _xml_text(principal, "./task:UserId")
    if user_id is None or user_id.casefold() not in {"s-1-5-18", "system", r"nt authority\system"}:
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    if (
        _xml_text(principal, "./task:LogonType") != "ServiceAccount"
        or _xml_text(principal, "./task:RunLevel") != "HighestAvailable"
    ):
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    triggers = root.findall("./task:Triggers/*", {"task": _TASK_NAMESPACE})
    if len(triggers) != 1 or triggers[0].tag != f"{{{_TASK_NAMESPACE}}}TimeTrigger":
        return SupervisorStatus("stopped", "supervisor_schedule_invalid")
    trigger = triggers[0]
    if (
        _xml_text(trigger, "./task:Repetition/task:Interval") != "PT5M"
        or _xml_text(trigger, "./task:Repetition/task:StopAtDurationEnd") != "false"
        or _xml_text(trigger, "./task:StartBoundary") != _WINDOWS_TASK_START_BOUNDARY
        or _xml_text(trigger, "./task:EndBoundary") is not None
        or _xml_text(trigger, "./task:Enabled") != "true"
    ):
        return SupervisorStatus("stopped", "supervisor_schedule_invalid")
    actions_parent = root.find("./task:Actions", {"task": _TASK_NAMESPACE})
    if actions_parent is None or actions_parent.get("Context") != "System":
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    actions = root.findall("./task:Actions/*", {"task": _TASK_NAMESPACE})
    if len(actions) != 1 or actions[0].tag != f"{{{_TASK_NAMESPACE}}}Exec":
        return SupervisorStatus("stopped", "supervisor_registration_invalid")
    expected_executable = ntpath.normcase(ntpath.normpath(str(machine_executable(paths, "Windows"))))
    command = _xml_text(actions[0], "./task:Command")
    if command is None or ntpath.normcase(ntpath.normpath(command)) != expected_executable:
        return SupervisorStatus("stopped", "supervisor_executable_mismatch")
    if _xml_text(actions[0], "./task:Arguments") != _HEALTH_ARGUMENTS:
        return SupervisorStatus("stopped", "supervisor_executable_mismatch")
    if (
        _xml_text(root, "./task:Settings/task:MultipleInstancesPolicy") != "IgnoreNew"
        or _xml_text(root, "./task:Settings/task:ExecutionTimeLimit") != "PT5M"
        or _xml_text(root, "./task:Settings/task:StartWhenAvailable") != "true"
        or _xml_text(root, "./task:Settings/task:Hidden") != "true"
        or _xml_text(root, "./task:Settings/task:Enabled") != "true"
    ):
        return SupervisorStatus("stopped", "supervisor_schedule_invalid")
    if (
        _xml_text(root, "./task:Settings/task:DisallowStartIfOnBatteries") != "false"
        or _xml_text(root, "./task:Settings/task:StopIfGoingOnBatteries") != "false"
    ):
        return SupervisorStatus("stopped", "supervisor_schedule_invalid")
    return SupervisorStatus("running", "supervisor_running")


def _verify_windows_supervisor(paths: MachinePaths) -> SupervisorStatus:
    try:
        result = _run_schtasks("/Query", "/TN", _WINDOWS_TASK_NAME, "/XML", "/HRESULT")
    except (OSError, subprocess.SubprocessError):
        return SupervisorStatus("unknown", "supervisor_probe_failed")
    if result.returncode in _ABSENT_HRESULTS:
        return SupervisorStatus("absent", "supervisor_absent")
    if result.returncode != 0:
        return SupervisorStatus("unknown", "supervisor_probe_failed")
    return _windows_registration_status(paths, result.stdout)


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
