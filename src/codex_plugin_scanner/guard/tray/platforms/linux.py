"""Linux tray platform adapter.

Manages XDG autostart desktop entry registration for the tray icon at
``~/.config/autostart/org.hol.guard.tray.desktop``. The autostart entry
starts the tray process at login.

Security contract:
    - Only writes to the user's own autostart directory.
    - Refuses to overwrite a same-named entry that is not verifiably
      HOL Guard-owned.
    - Never includes auth tokens in the desktop entry — the tray process
      reads tokens from guard_home at runtime.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from ..contracts import (
    TRAY_REGISTRATION_LABEL,
    TrayCapability,
    TrayPlatform,
)
from ..runtime import detect_capability

logger = logging.getLogger(__name__)

AUTOSTART_DIR = Path.home() / ".config" / "autostart"
DESKTOP_FILENAME = f"{TRAY_REGISTRATION_LABEL}.desktop"


class LinuxTrayAdapter:
    """Linux XDG autostart-based tray adapter."""

    @property
    def platform(self) -> TrayPlatform:
        return TrayPlatform.LINUX

    def detect_capability(self) -> TrayCapability:
        return detect_capability()

    def _desktop_path(self) -> Path:
        return AUTOSTART_DIR / DESKTOP_FILENAME

    def inspect_registration(self, *, guard_home: Path) -> dict[str, object]:
        desktop_path = self._desktop_path()
        if not desktop_path.is_file():
            return {"installed": False}
        try:
            content = desktop_path.read_text(encoding="utf-8")
        except OSError as error:
            logger.warning("linux tray: desktop entry read failed: %s", error)
            return {"installed": False, "reason": "internal_error", "message": str(error)}

        owned = "codex_plugin_scanner" in content or "hol-guard" in content
        exec_line = ""
        for line in content.splitlines():
            if line.startswith("Exec="):
                exec_line = line[len("Exec="):]
                break

        return {
            "installed": True,
            "owned": owned,
            "path": str(desktop_path),
            "command": exec_line,
            "run_at_login": "X-GNOME-Autostart-enabled=true" in content or "Hidden=false" in content,
        }

    def install_registration(
        self,
        *,
        guard_home: Path,
        capability: TrayCapability,
        run_at_login: bool = True,
    ) -> dict[str, object]:
        desktop_path = self._desktop_path()

        # Check for existing foreign registration
        if desktop_path.is_file():
            existing = self.inspect_registration(guard_home=guard_home)
            if existing.get("installed") and not existing.get("owned"):
                return {
                    "installed": False,
                    "reason": "startup_registration_collision",
                    "message": f"A foreign desktop entry exists at {desktop_path}",
                }

        # Ensure directory exists
        desktop_path.parent.mkdir(parents=True, exist_ok=True)

        import sys

        executable = sys.executable
        exec_command = f'"{executable}" -m codex_plugin_scanner.guard.tray.runtime --guard-home "{guard_home}"'

        hidden = "false" if run_at_login else "true"
        autostart_enabled = "true" if run_at_login else "false"

        content = "\n".join(
            [
                "[Desktop Entry]",
                "Type=Application",
                "Name=HOL Guard Tray",
                "Comment=HOL Guard menu bar icon",
                f"Exec={exec_command}",
                "Icon=hol-guard-tray",
                "Terminal=false",
                f"X-GNOME-Autostart-enabled={autostart_enabled}",
                f"Hidden={hidden}",
                "Categories=Utility;Security;",
                "StartupNotify=false",
                "",
            ]
        )

        try:
            desktop_path.write_text(content, encoding="utf-8")
            os.chmod(desktop_path, 0o644)
        except OSError as error:
            return {
                "installed": False,
                "reason": "startup_registration_failed",
                "message": f"Failed to write desktop entry: {error}",
            }

        return {
            "installed": True,
            "path": str(desktop_path),
            "label": TRAY_REGISTRATION_LABEL,
        }

    def remove_registration(self, *, guard_home: Path) -> dict[str, object]:
        desktop_path = self._desktop_path()
        if not desktop_path.is_file():
            return {"removed": False, "reason": "not_installed", "message": "No desktop entry found"}

        existing = self.inspect_registration(guard_home=guard_home)
        if not existing.get("owned"):
            return {
                "removed": False,
                "reason": "startup_registration_collision",
                "message": f"Refusing to remove foreign desktop entry at {desktop_path}",
            }

        try:
            desktop_path.unlink()
        except OSError as error:
            return {
                "removed": False,
                "reason": "internal_error",
                "message": f"Failed to remove desktop entry: {error}",
            }

        return {"removed": True, "path": str(desktop_path)}

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
            executable, "-m", "codex_plugin_scanner.guard.tray.runtime",
            "--guard-home", str(guard_home),
        ]

        try:
            proc = subprocess.Popen(
                args,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as error:
            return {"started": False, "reason": "internal_error", "message": str(error)}

        return {"started": True, "pid": proc.pid}

    def stop_process(self, *, pid: int) -> dict[str, object]:
        import signal

        if pid <= 0:
            return {"stopped": False, "reason": "not_running"}
        try:
            os.kill(pid, signal.SIGTERM)
        except (OSError, ProcessLookupError) as error:
            return {"stopped": False, "reason": "internal_error", "message": str(error)}

        return {"stopped": True}

    def is_process_running(self, *, pid: int) -> bool:
        from ..state import is_process_alive

        return is_process_alive(pid)
