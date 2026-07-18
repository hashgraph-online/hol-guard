"""Tray icon runtime: pystray-based menu bar / system tray icon.

Runs on the main thread (required by pystray on macOS). Builds the
menu, loads static icons, routes ``Open HOL Guard`` to the canonical
``dashboard_launcher.open_dashboard`` service, and provides a
``Start at Login`` toggle plus ``Quit``.

Security contract:
    - Never logs auth tokens. The launcher returns only redacted URLs.
    - Error notifications use ``desktop_notifications`` helpers and
      never include daemon auth tokens or URL fragments.
"""

from __future__ import annotations

import contextlib
import io
import logging
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .contracts import (
    DASHBOARD_OPEN_COALESCE_SECONDS,
    TrayBackend,
    TrayCapability,
    TrayPlatform,
    TrayReasonCode,
    TrayState,
)
from .security import sanitize_secret

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.config import GuardConfig
    from codex_plugin_scanner.guard.store import GuardStore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Icon loading
# ---------------------------------------------------------------------------


def _load_icon_bytes(platform: TrayPlatform) -> bytes:
    """Load the best-fit static icon for the platform.

    Uses ``importlib.resources`` so icons are read from the installed
    wheel, never from the working tree. Falls back to a 1x1 transparent
    PNG if no asset is available (keeps the tray alive on minimal
    installs).
    """
    from importlib.resources import files

    size_hint = {TrayPlatform.MACOS: "22", TrayPlatform.WINDOWS: "16", TrayPlatform.LINUX: "22"}.get(
        platform, "22"
    )
    asset_root = files("codex_plugin_scanner.guard.tray.assets")
    candidates = [
        f"hol-guard-tray-{size_hint}.png",
        f"hol-guard-tray-{size_hint}@2x.png",
        "hol-guard-tray-32.png",
        "hol-guard-tray-16.png",
    ]
    for name in candidates:
        try:
            resource = asset_root.joinpath(name)
            if resource.is_file():
                return resource.read_bytes()
        except (FileNotFoundError, AttributeError):
            continue
    # Minimal 1x1 transparent PNG fallback
    return bytes(
        [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
            0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41,
            0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
            0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
            0x42, 0x60, 0x82,
        ]
    )


# ---------------------------------------------------------------------------
# Menu callbacks
# ---------------------------------------------------------------------------


class TrayMenuCallbacks:
    """Bound callbacks for tray menu items.

    Kept as a small dataclass so tests can inject fakes without
    constructing the full runtime.
    """

    def __init__(
        self,
        *,
        open_dashboard: Callable[[], None],
        toggle_start_at_login: Callable[[], bool],
        quit_tray: Callable[[], None],
    ) -> None:
        self.open_dashboard = open_dashboard
        self.toggle_start_at_login = toggle_start_at_login
        self.quit_tray = quit_tray


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


class TrayRuntime:
    """Runs the tray icon on the main thread.

    The runtime is single-use: construct, ``run()``, then either the
    user selects ``Quit`` or ``stop()`` is called from another thread.
    """

    def __init__(
        self,
        *,
        guard_home: Path,
        store: GuardStore,
        config: GuardConfig,
        capability: TrayCapability,
        start_at_login: bool = False,
        callbacks: TrayMenuCallbacks | None = None,
    ) -> None:
        self._guard_home = guard_home
        self._store = store
        self._config = config
        self._capability = capability
        self._start_at_login = start_at_login
        self._callbacks = callbacks
        self._icon: Any = None
        self._stop_requested = threading.Event()
        self._last_open_at: float = 0.0
        self._open_lock = threading.Lock()
        self._state = TrayState.STARTING

    @property
    def state(self) -> TrayState:
        return self._state

    def request_open_dashboard(self) -> None:
        """Menu callback: open the dashboard, coalescing repeated clicks."""
        now = time.monotonic()
        with self._open_lock:
            if now - self._last_open_at < DASHBOARD_OPEN_COALESCE_SECONDS:
                logger.debug("tray: open request coalesced")
                return
            self._last_open_at = now

        if self._callbacks is not None:
            self._callbacks.open_dashboard()
            return
        self._open_dashboard_internal()

    def _open_dashboard_internal(self) -> None:
        """Default open handler: call the canonical launcher."""
        try:
            from ..dashboard_launcher import open_dashboard

            result = open_dashboard(
                guard_home=self._guard_home,
                store=self._store,
                config=self._config,
                force_open=True,
                open_key="tray",
            )
            if not result.opened and result.reason not in {
                "policy-disabled",
                "already-opened",
                "live-client",
            }:
                self._notify_error(
                    f"Could not open HOL Guard dashboard: {result.reason}",
                    error=result.error,
                )
        except Exception as error:  # pragma: no cover - defensive
            logger.exception("tray: dashboard open failed")
            self._notify_error("Could not open HOL Guard dashboard", error=str(error))

    def request_toggle_start_at_login(self) -> bool:
        """Menu callback: toggle start-at-login. Returns new state."""
        new_state = self._callbacks.toggle_start_at_login() if self._callbacks is not None else not self._start_at_login
        self._start_at_login = new_state
        return new_state

    def request_quit(self) -> None:
        """Menu callback: stop the tray icon."""
        if self._callbacks is not None:
            self._callbacks.quit_tray()
        self._stop_requested.set()
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:  # pragma: no cover - defensive
                logger.exception("tray: icon.stop() failed")

    def stop(self) -> None:
        """Stop the tray from another thread."""
        self._stop_requested.set()
        if self._icon is not None:
            with contextlib.suppress(Exception):
                self._icon.stop()

    def run(self) -> int:
        """Run the tray icon on the main thread. Returns exit code."""
        if self._capability.platform is None or not self._capability.supported:
            logger.warning("tray: cannot run on unsupported platform")
            self._state = TrayState.UNSUPPORTED
            return 1

        try:
            import pystray
            from PIL import Image
        except ImportError as error:
            logger.error("tray: pystray/Pillow not available: %s", error)
            self._state = TrayState.UNSUPPORTED
            return 1

        icon_bytes = _load_icon_bytes(self._capability.platform)
        try:
            image: Any = Image.open(io_bytes(icon_bytes))
            image.load()
        except Exception as error:
            logger.error("tray: icon load failed: %s", error)
            image = Image.new("RGBA", (16, 16), (0, 0, 0, 0))

        menu = pystray.Menu(
            pystray.MenuItem(
                "Open HOL Guard",
                lambda _icon, _item: self.request_open_dashboard(),
                default=True,
            ),
            pystray.MenuItem(
                "Start at Login",
                lambda _icon, _item: self.request_toggle_start_at_login(),
                checked=lambda _item: self._start_at_login,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Quit HOL Guard",
                lambda _icon, _item: self.request_quit(),
            ),
        )

        self._icon = pystray.Icon(
            name="hol-guard-tray",
            icon=image,
            title="HOL Guard",
            menu=menu,
        )
        self._state = TrayState.RUNNING
        logger.info("tray: starting on %s via %s", self._capability.platform.value, self._capability.backend.value)
        try:
            self._icon.run()
        finally:
            self._state = TrayState.STOPPING
            self._state = TrayState.ABSENT
        return 0

    def _notify_error(self, message: str, *, error: str | None = None) -> None:
        """Surface an error via desktop notifications, never leaking tokens."""
        try:
            from ..desktop_notifications import (
                DesktopApprovalNotification,
                send_desktop_approval_notification,
            )

            sanitized = sanitize_secret(message)
            if error:
                sanitized_error = sanitize_secret(error)
                sanitized = f"{sanitized} ({sanitized_error})"
            notification = DesktopApprovalNotification(
                request_id="tray-error",
                title="HOL Guard",
                message=sanitized,
                approval_url="",
            )
            send_desktop_approval_notification(notification)
        except Exception:  # pragma: no cover - defensive
            logger.exception("tray: error notification failed")


def io_bytes(data: bytes):
    """Wrap bytes in a file-like object for PIL.Image.open."""
    return io.BytesIO(data)


def detect_capability() -> TrayCapability:
    """Detect the current platform's tray capability without importing pystray.

    On Linux, requires either ``DISPLAY`` (Xorg) or ``WAYLAND_DISPLAY``
    (Wayland) to be set in the environment — pystray's appindicator backend
    cannot initialize without a display server, so headless/SSH sessions
    report ``NO_DISPLAY_SERVER`` rather than crashing at icon.run().
    """
    platform = TrayPlatform.current()
    if platform is None:
        return TrayCapability(
            platform=None,
            backend=TrayBackend.NONE,
            supported=False,
            reason=TrayReasonCode.UNSUPPORTED_PLATFORM,
            details=f"Unsupported platform: {sys.platform}",
        )

    backend_map = {
        TrayPlatform.MACOS: TrayBackend.APPKIT,
        TrayPlatform.WINDOWS: TrayBackend.WIN32,
        TrayPlatform.LINUX: TrayBackend.APPINDICATOR,
    }
    backend = backend_map.get(platform, TrayBackend.NONE)

    # Linux requires a display server. Headless/SSH/container sessions
    # without DISPLAY or WAYLAND_DISPLAY cannot host a tray icon.
    if platform is TrayPlatform.LINUX:
        import os

        has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        if not has_display:
            return TrayCapability(
                platform=platform,
                backend=backend,
                supported=False,
                reason=TrayReasonCode.NO_DISPLAY,
                details="No DISPLAY or WAYLAND_DISPLAY environment variable set",
            )

    try:
        import pystray  # noqa: F401
        from PIL import Image  # noqa: F401
    except Exception as error:
        # Broaden beyond ImportError: pystray may raise RuntimeError or
        # platform-specific errors on broken installs. Treat any import-time
        # failure as a missing dependency so callers get a clean unsupported
        # payload instead of a propagated exception.
        return TrayCapability(
            platform=platform,
            backend=backend,
            supported=False,
            reason=TrayReasonCode.DEPENDENCY_MISSING,
            details=f"pystray or Pillow not available: {error}",
        )

    return TrayCapability(
        platform=platform,
        backend=backend,
        supported=True,
        reason=TrayReasonCode.OK,
        details=f"{platform.value} with {backend.value} backend",
    )


def _main() -> int:
    """Entry point for ``python -m codex_plugin_scanner.guard.tray.runtime``.

    Parses ``--guard-home``, constructs a TrayRuntime, writes the locator
    before starting the icon loop, and removes it on exit.
    """
    import argparse

    from .state import (
        build_locator_for_current_process,
        remove_locator,
        reset_crash_count,
        write_locator,
    )

    parser = argparse.ArgumentParser(description="Run the HOL Guard tray icon")
    parser.add_argument("--guard-home", required=True)
    args = parser.parse_args()
    guard_home = Path(args.guard_home)

    capability = detect_capability()
    if not capability.supported:
        print(f"Tray not supported: {capability.details}", file=sys.stderr)
        return 1

    # Write locator before starting so the lifecycle readiness check passes
    locator = build_locator_for_current_process(
        guard_home=guard_home,
        package_version="",
        backend=capability.backend,
    )
    try:
        write_locator(guard_home, locator)
        reset_crash_count(guard_home)
    except OSError as error:
        print(f"Failed to write locator: {error}", file=sys.stderr)
        return 1

    # Construct store/config for the dashboard launcher
    try:
        from ..config import load_guard_config
        from ..store import GuardStore

        store = GuardStore(guard_home)
        config = load_guard_config(guard_home)
    except Exception as error:
        print(f"Failed to load guard config: {error}", file=sys.stderr)
        remove_locator(guard_home)
        return 1

    runtime = TrayRuntime(
        guard_home=guard_home,
        store=store,
        config=config,
        capability=capability,
    )

    try:
        return runtime.run()
    finally:
        # Clean up locator on exit (normal quit, signal, or crash)
        with contextlib.suppress(Exception):
            remove_locator(guard_home)


if __name__ == "__main__":
    sys.exit(_main())
