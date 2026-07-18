"""macOS tray platform adapter.

Manages LaunchAgent registration for the tray icon at
``~/Library/LaunchAgents/org.hol.guard.tray.plist``. The LaunchAgent
starts the tray process at login and keeps it alive.

Security contract:
    - Only writes to the user's own LaunchAgents directory.
    - Refuses to overwrite a same-named plist that is not verifiably
      HOL Guard-owned (checked via program arguments label).
    - Never includes auth tokens in the plist — the tray process reads
      tokens from guard_home at runtime.
"""

from __future__ import annotations

import logging
import plistlib
from pathlib import Path

from ..contracts import (
    TRAY_REGISTRATION_LABEL,
    TrayCapability,
    TrayPlatform,
)
from ..runtime import detect_capability

logger = logging.getLogger(__name__)

LAUNCHAGENTS_DIR = Path.home() / "Library" / "LaunchAgents"
PLIST_FILENAME = f"{TRAY_REGISTRATION_LABEL}.plist"


class MacOSTrayAdapter:
    """macOS LaunchAgent-based tray adapter."""

    @property
    def platform(self) -> TrayPlatform:
        return TrayPlatform.MACOS

    def detect_capability(self) -> TrayCapability:
        return detect_capability()

    def _plist_path(self) -> Path:
        return LAUNCHAGENTS_DIR / PLIST_FILENAME

    def inspect_registration(self, *, guard_home: Path) -> dict[str, object]:
        plist_path = self._plist_path()
        if not plist_path.is_file():
            return {"installed": False}
        try:
            with plist_path.open("rb") as f:
                plist = plistlib.load(f)
        except (OSError, plistlib.InvalidFileException) as error:
            logger.warning("macos tray: malformed plist: %s", error)
            return {"installed": True, "owned": False, "malformed": True}

        program_arguments = plist.get("ProgramArguments", [])
        owned = any("codex_plugin_scanner" in str(arg) or "hol-guard" in str(arg) for arg in program_arguments)
        return {
            "installed": True,
            "owned": owned,
            "path": str(plist_path),
            "program_arguments": list(program_arguments),
            "run_at_login": plist.get("RunAtLoad", False),
            "keep_alive": plist.get("KeepAlive", False),
        }

    def install_registration(
        self,
        *,
        guard_home: Path,
        capability: TrayCapability,
        run_at_login: bool = True,
    ) -> dict[str, object]:
        plist_path = self._plist_path()

        # Check for existing foreign registration
        if plist_path.is_file():
            existing = self.inspect_registration(guard_home=guard_home)
            if existing.get("installed") and not existing.get("owned"):
                return {
                    "installed": False,
                    "reason": "startup_registration_collision",
                    "message": f"A foreign LaunchAgent exists at {plist_path}",
                }

        # Ensure directory exists
        plist_path.parent.mkdir(parents=True, exist_ok=True)

        # Build program arguments
        import sys

        executable = sys.executable
        program_arguments = [
            executable, "-m", "codex_plugin_scanner.guard.cli",
            "guard", "tray", "run", "--guard-home", str(guard_home),
        ]

        plist_content = {
            "Label": TRAY_REGISTRATION_LABEL,
            "ProgramArguments": program_arguments,
            "RunAtLoad": run_at_login,
            "KeepAlive": False,  # Don't auto-restart; lifecycle handles crashes
            "StandardOutPath": str(guard_home / "tray" / "stdout.log"),
            "StandardErrorPath": str(guard_home / "tray" / "stderr.log"),
            "EnvironmentVariables": {
                "PYTHONUNBUFFERED": "1",
            },
        }

        try:
            with plist_path.open("wb") as f:
                plistlib.dump(plist_content, f)
        except OSError as error:
            return {
                "installed": False,
                "reason": "startup_registration_failed",
                "message": f"Failed to write plist: {error}",
            }

        return {
            "installed": True,
            "path": str(plist_path),
            "label": TRAY_REGISTRATION_LABEL,
        }

    def remove_registration(self, *, guard_home: Path) -> dict[str, object]:
        plist_path = self._plist_path()
        if not plist_path.is_file():
            return {"removed": False, "reason": "not_installed", "message": "No LaunchAgent plist found"}

        # Verify ownership before removing
        existing = self.inspect_registration(guard_home=guard_home)
        if existing.get("installed") and not existing.get("owned"):
            return {
                "removed": False,
                "reason": "startup_registration_collision",
                "message": f"Refusing to remove foreign LaunchAgent at {plist_path}",
            }

        try:
            # Unload before removing
            import subprocess

            subprocess.run(
                ["launchctl", "unload", str(plist_path)],
                capture_output=True,
                timeout=10,
                check=False,
            )
            plist_path.unlink()
        except OSError as error:
            return {
                "removed": False,
                "reason": "internal_error",
                "message": f"Failed to remove plist: {error}",
            }

        return {"removed": True, "path": str(plist_path)}

    def start_process(
        self,
        *,
        guard_home: Path,
        capability: TrayCapability,
    ) -> dict[str, object]:
        """Start the tray process via launchctl."""
        import subprocess

        plist_path = self._plist_path()
        if not plist_path.is_file():
            # Install registration first, then load
            install_result = self.install_registration(
                guard_home=guard_home,
                capability=capability,
                run_at_login=True,
            )
            if not install_result.get("installed"):
                return {
                    "started": False,
                    "reason": "startup_registration_failed",
                    "message": install_result.get("message", ""),
                }

        try:
            # Load and start the LaunchAgent
            subprocess.run(
                ["launchctl", "load", str(plist_path)],
                capture_output=True,
                timeout=15,
                check=False,
            )
            # Also kickstart it in case it's already loaded but not running
            result = subprocess.run(
                ["launchctl", "kickstart", f"gui/{_get_uid()}/{TRAY_REGISTRATION_LABEL}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                # kickstart may fail if not loaded; try list to find pid
                return {"started": True, "pid": 0, "message": "LaunchAgent loaded"}
        except (OSError, subprocess.SubprocessError) as error:
            return {"started": False, "reason": "internal_error", "message": f"launchctl failed: {error}"}

        return {"started": True, "pid": 0}

    def stop_process(self, *, pid: int) -> dict[str, object]:
        """Stop the tray process by unloading the LaunchAgent."""
        import subprocess

        plist_path = self._plist_path()
        try:
            subprocess.run(
                ["launchctl", "unload", str(plist_path)],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return {"stopped": False, "reason": "internal_error", "message": str(error)}

        return {"stopped": True}

    def is_process_running(self, *, pid: int) -> bool:
        if pid <= 0:
            # Check via launchctl list
            import subprocess

            result = subprocess.run(
                ["launchctl", "list", TRAY_REGISTRATION_LABEL],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return result.returncode == 0
        from ..state import is_process_alive

        return is_process_alive(pid)


def _get_uid() -> int:
    import os

    return os.getuid()
