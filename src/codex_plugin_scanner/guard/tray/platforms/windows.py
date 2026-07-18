"""Windows tray platform adapter.

Manages Run-key registry registration for the tray icon at
``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run``. The Run key
starts the tray process at login.

Security contract:
    - Only writes to HKCU (current user), never HKLM.
    - Refuses to overwrite a same-named entry that is not verifiably
      HOL Guard-owned.
    - Never includes auth tokens in the registry — the tray process
      reads tokens from guard_home at runtime.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..contracts import (
    TrayCapability,
    TrayPlatform,
)
from ..runtime import detect_capability

logger = logging.getLogger(__name__)

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_KEY_VALUE = "HOLGuardTray"


class WindowsTrayAdapter:
    """Windows Run-key-based tray adapter."""

    @property
    def platform(self) -> TrayPlatform:
        return TrayPlatform.WINDOWS

    def detect_capability(self) -> TrayCapability:
        return detect_capability()

    def inspect_registration(self, *, guard_home: Path) -> dict[str, object]:
        try:
            import winreg
        except ImportError:
            return {"installed": False, "reason": "unsupported_platform"}

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, RUN_KEY_VALUE)
                owned = "codex_plugin_scanner" in value or "hol-guard" in value
                return {
                    "installed": True,
                    "owned": owned,
                    "path": f"HKCU\\{RUN_KEY_PATH}\\{RUN_KEY_VALUE}",
                    "command": value,
                    "run_at_login": True,
                }
        except FileNotFoundError:
            return {"installed": False}
        except OSError as error:
            logger.warning("windows tray: registry read failed: %s", error)
            return {"installed": False, "reason": "internal_error", "message": str(error)}

    def install_registration(
        self,
        *,
        guard_home: Path,
        capability: TrayCapability,
        run_at_login: bool = True,
    ) -> dict[str, object]:
        try:
            import winreg
        except ImportError:
            return {"installed": False, "reason": "unsupported_platform", "message": "winreg not available"}

        # Check for existing foreign registration
        existing = self.inspect_registration(guard_home=guard_home)
        if existing.get("installed") and not existing.get("owned"):
            return {
                "installed": False,
                "reason": "startup_registration_collision",
                "message": f"A foreign Run-key entry exists: {existing.get('command', '')}",
            }

        import sys

        executable = sys.executable
        command = f'"{executable}" -m codex_plugin_scanner.guard.cli guard tray run --guard-home "{guard_home}"'

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                RUN_KEY_PATH,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(key, RUN_KEY_VALUE, 0, winreg.REG_SZ, command)
        except OSError as error:
            return {
                "installed": False,
                "reason": "startup_registration_failed",
                "message": f"Failed to write Run key: {error}",
            }

        return {
            "installed": True,
            "path": f"HKCU\\{RUN_KEY_PATH}\\{RUN_KEY_VALUE}",
            "label": RUN_KEY_VALUE,
        }

    def remove_registration(self, *, guard_home: Path) -> dict[str, object]:
        try:
            import winreg
        except ImportError:
            return {"removed": False, "reason": "unsupported_platform", "message": "winreg not available"}

        existing = self.inspect_registration(guard_home=guard_home)
        if not existing.get("installed"):
            return {"removed": False, "reason": "not_installed", "message": "No Run-key entry found"}
        if not existing.get("owned"):
            return {
                "removed": False,
                "reason": "startup_registration_collision",
                "message": "Refusing to remove foreign Run-key entry",
            }

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                RUN_KEY_PATH,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.DeleteValue(key, RUN_KEY_VALUE)
        except OSError as error:
            return {
                "removed": False,
                "reason": "internal_error",
                "message": f"Failed to delete Run key: {error}",
            }

        return {"removed": True, "path": f"HKCU\\{RUN_KEY_PATH}\\{RUN_KEY_VALUE}"}

    def start_process(
        self,
        *,
        guard_home: Path,
        capability: TrayCapability,
    ) -> dict[str, object]:
        import subprocess
        import sys

        executable = sys.executable
        args = [
            executable, "-m", "codex_plugin_scanner.guard.cli",
            "guard", "tray", "run", "--guard-home", str(guard_home),
        ]

        try:
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
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
            subprocess.run(["taskkill", "/PID", str(pid), "/T"], capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            return {"stopped": False, "reason": "internal_error", "message": str(error)}

        return {"stopped": True}

    def is_process_running(self, *, pid: int) -> bool:
        from ..state import is_process_alive

        return is_process_alive(pid)
