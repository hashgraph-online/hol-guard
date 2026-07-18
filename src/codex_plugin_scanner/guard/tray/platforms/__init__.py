"""Platform adapter protocol and factory for tray operations.

Each platform (macOS, Windows, Linux) implements the ``TrayPlatformAdapter``
protocol to handle capability detection, registration management, and
native start/stop operations. The lifecycle module calls these adapters —
platform code never imports lifecycle.

``detect_platform_adapter()`` returns the adapter for the current platform
or None if the platform is unsupported.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from ..contracts import (
    TrayCapability,
    TrayPlatform,
)


@runtime_checkable
class TrayPlatformAdapter(Protocol):
    """Protocol for platform-specific tray adapters."""

    @property
    def platform(self) -> TrayPlatform:
        """The platform this adapter handles."""
        ...

    def detect_capability(self) -> TrayCapability:
        """Probe whether the current session can show a tray icon.

        ``supported`` must be True only when both the OS and a usable
        graphical tray backend are available. OS name alone is insufficient.
        """
        ...

    def inspect_registration(self, *, guard_home: Path) -> dict[str, object]:
        """Read the current startup registration without modifying it.

        Returns a dict with at least ``{"installed": bool}``. If a
        same-named foreign object is detected, returns ``{"installed": True,
        "owned": False}``.
        """
        ...

    def install_registration(
        self,
        *,
        guard_home: Path,
        capability: TrayCapability,
        run_at_login: bool = True,
    ) -> dict[str, object]:
        """Write the per-user startup registration idempotently.

        Must refuse to overwrite a same-named registration that is not
        verifiably HOL Guard-owned. Returns ``{"installed": bool, ...}``.
        """
        ...

    def remove_registration(self, *, guard_home: Path) -> dict[str, object]:
        """Remove only a verified HOL Guard-owned registration.

        Must not remove a foreign same-named object. Returns
        ``{"removed": bool, ...}``.
        """
        ...

    def start_process(
        self,
        *,
        guard_home: Path,
        capability: TrayCapability,
    ) -> dict[str, object]:
        """Launch the tray process in the background.

        Must not block — the process runs independently. Returns
        ``{"started": bool, "pid": int, ...}`` on success or
        ``{"started": False, "reason": str, "message": str}`` on failure.
        """
        ...

    def stop_process(self, *, pid: int) -> dict[str, object]:
        """Stop a tray process by PID.

        Returns ``{"stopped": bool, ...}`` or
        ``{"stopped": False, "reason": str}`` on failure.
        """
        ...

    def is_process_running(self, *, pid: int) -> bool:
        """Check whether a process with the given PID is still running."""
        ...


def detect_platform_adapter() -> TrayPlatformAdapter | None:
    """Return the platform adapter for the current OS, or None if unsupported.

    Imports are lazy so the module loads cleanly on any platform —
    platform-specific dependencies (pyobjc, python-xlib) are only imported
    when the adapter is actually constructed.
    """
    platform = TrayPlatform.current()
    if platform is None:
        return None

    try:
        if platform == TrayPlatform.MACOS:
            from .macos import MacOSTrayAdapter

            return MacOSTrayAdapter()
        if platform == TrayPlatform.WINDOWS:
            from .windows import WindowsTrayAdapter

            return WindowsTrayAdapter()
        if platform == TrayPlatform.LINUX:
            from .linux import LinuxTrayAdapter

            return LinuxTrayAdapter()
    except ImportError:
        return None

    return None


__all__ = ["TrayPlatformAdapter", "detect_platform_adapter"]
