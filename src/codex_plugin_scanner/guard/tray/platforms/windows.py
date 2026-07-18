"""Windows tray platform adapter.

Manages a per-user Task Scheduler task for the tray icon. The task triggers
at interactive logon, runs ``pythonw.exe`` (no console window), and has
bounded restart-on-failure settings.

Security contract:
    - Only creates per-user tasks (no elevation, no system-wide persistence).
    - Uses ``pythonw.exe`` to avoid console flash.
    - Refuses to overwrite a same-named task that is not verifiably
      HOL Guard-owned.
    - Never includes auth tokens in the task command — the tray process
      reads tokens from guard_home at runtime.
    - Uses structured ``schtasks.exe`` argv, never PowerShell script strings
      or ``cmd.exe``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from xml.sax.saxutils import escape

from ..contracts import TrayCapability, TrayPlatform
from ..runtime import detect_capability

logger = logging.getLogger(__name__)

TASK_NAME = "HOLGuardTray"

TASK_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>HOL Guard tray icon — opens the dashboard from the menu bar.</Description>
    <URI>\\{task_name}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT60S</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions>
    <Exec>
      <Command>{executable}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>"""


def _pythonw_path() -> str:
    """Return the path to pythonw.exe (windowless Python) for the current install."""
    import sys

    exe = Path(sys.executable)
    if exe.name.lower() == "pythonw.exe":
        return str(exe)
    pythonw = exe.parent / "pythonw.exe"
    if pythonw.exists():
        return str(pythonw)
    return str(exe)


def _build_task_xml(guard_home: Path) -> str:
    """Build the Task Scheduler XML definition for the tray task.

    All interpolated values (executable path, guard_home path) are XML-escaped
    via ``xml.sax.saxutils.escape()`` — this is element content, not attribute
    content, so ``escape()`` is correct (not ``quoteattr()`` which adds quotes).
    """
    executable = _pythonw_path()
    arguments = (
        f'-m codex_plugin_scanner.guard.tray.runtime '
        f'--guard-home "{escape(str(guard_home))}"'
    )
    return TASK_XML_TEMPLATE.format(
        task_name=TASK_NAME,
        executable=escape(executable),
        arguments=arguments,
    )


def _query_task() -> dict[str, object]:
    """Query the existing task via schtasks /Query. Returns task info or absent."""
    import subprocess

    try:
        result = subprocess.run(
            ["schtasks.exe", "/Query", "/TN", TASK_NAME, "/XML"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"installed": False, "reason": "schtasks_unavailable"}
    if result.returncode != 0:
        return {"installed": False}
    xml_output = result.stdout
    owned = "codex_plugin_scanner" in xml_output or "hol-guard" in xml_output.lower()
    return {
        "installed": True,
        "owned": owned,
        "task_name": TASK_NAME,
        "xml": xml_output,
        "run_at_login": "LogonTrigger" in xml_output,
    }


class WindowsTrayAdapter:
    """Windows Task Scheduler-based tray adapter.

    Uses a per-user interactive-logon scheduled task with ``pythonw.exe``
    (no console flash), bounded restart-on-failure (3 retries, 60s interval),
    and least-privilege execution.
    """

    @property
    def platform(self) -> TrayPlatform:
        return TrayPlatform.WINDOWS

    def detect_capability(self) -> TrayCapability:
        return detect_capability()

    def inspect_registration(self, *, guard_home: Path) -> dict[str, object]:
        return _query_task()

    def install_registration(
        self,
        *,
        guard_home: Path,
        capability: TrayCapability,
        run_at_login: bool = True,
    ) -> dict[str, object]:
        existing = self.inspect_registration(guard_home=guard_home)
        if existing.get("installed") and not existing.get("owned"):
            return {
                "installed": False,
                "reason": "startup_registration_collision",
                "message": f"A foreign task exists: {TASK_NAME}",
            }

        import subprocess
        import tempfile

        task_xml = _build_task_xml(guard_home)

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".xml", delete=False, encoding="utf-16",
            ) as f:
                f.write(task_xml)
                xml_path = f.name
        except OSError as error:
            return {
                "installed": False,
                "reason": "startup_registration_failed",
                "message": f"Failed to write task XML: {error}",
            }

        try:
            result = subprocess.run(
                ["schtasks.exe", "/Create", "/XML", xml_path, "/TN", TASK_NAME, "/F"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            return {
                "installed": False,
                "reason": "schtasks_unavailable",
                "message": f"schtasks.exe not available: {error}",
            }
        finally:
            Path(xml_path).unlink(missing_ok=True)

        if result.returncode != 0:
            return {
                "installed": False,
                "reason": "startup_registration_failed",
                "message": result.stderr.strip() or "schtasks /Create failed",
            }

        return {"installed": True, "task_name": TASK_NAME, "label": TASK_NAME}

    def remove_registration(self, *, guard_home: Path) -> dict[str, object]:
        existing = self.inspect_registration(guard_home=guard_home)
        if not existing.get("installed"):
            return {"removed": False, "reason": "not_installed", "message": "No task found"}
        if not existing.get("owned"):
            return {
                "removed": False,
                "reason": "startup_registration_collision",
                "message": "Refusing to remove foreign task",
            }

        import subprocess

        try:
            result = subprocess.run(
                ["schtasks.exe", "/Delete", "/TN", TASK_NAME, "/F"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            return {
                "removed": False,
                "reason": "schtasks_unavailable",
                "message": f"schtasks.exe not available: {error}",
            }

        if result.returncode != 0:
            return {
                "removed": False,
                "reason": "internal_error",
                "message": result.stderr.strip() or "schtasks /Delete failed",
            }

        return {"removed": True, "task_name": TASK_NAME}

    def start_process(
        self,
        *,
        guard_home: Path,
        capability: TrayCapability,
    ) -> dict[str, object]:
        import subprocess

        executable = _pythonw_path()
        args = [
            executable,
            "-m", "codex_plugin_scanner.guard.tray.runtime",
            "--guard-home", str(guard_home),
        ]

        try:
            creationflags = 0
            if hasattr(subprocess, "DETACHED_PROCESS"):
                creationflags |= subprocess.DETACHED_PROCESS
            if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
                creationflags |= subprocess.CREATE_NEW_PROCESS_GROUP
            proc = subprocess.Popen(
                args,
                creationflags=creationflags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as error:
            return {"started": False, "reason": "internal_error", "message": str(error)}

        return {"started": True, "pid": proc.pid}

    def stop_process(self, *, pid: int) -> dict[str, object]:
        import subprocess

        if pid <= 0:
            return {"stopped": False, "reason": "not_running"}
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T"],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return {"stopped": False, "reason": "internal_error", "message": str(error)}

        return {"stopped": True}

    def is_process_running(self, *, pid: int) -> bool:
        from ..state import is_process_alive

        return is_process_alive(pid)
