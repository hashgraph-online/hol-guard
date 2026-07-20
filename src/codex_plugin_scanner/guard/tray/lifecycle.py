"""Tray lifecycle orchestration: start, stop, status, repair.

Single entry point for ``hol-guard tray`` CLI subcommands. Coordinates
capability detection, locator persistence, process start/stop, crash
recovery, and registration management. Delegates platform-specific
work to ``TrayPlatformAdapter`` implementations.

Security contract:
    - Never passes auth tokens to subprocesses. The tray process
      receives only ``guard_home`` and reads tokens itself at runtime.
    - Status payloads contain only redacted URLs and process identity
      — never auth tokens or URL fragments.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .contracts import (
    MAX_CRASH_RETRIES,
    PROCESS_START_TIMEOUT_SECONDS,
    PROCESS_STOP_TIMEOUT_SECONDS,
    TrayBackend,
    TrayCapability,
    TrayLifecycleResult,
    TrayLocator,
    TrayReasonCode,
    TrayState,
)
from .platforms import detect_platform_adapter
from .runtime import detect_capability
from .state import (
    build_locator_for_current_process,
    crash_loop_detected,
    is_process_alive,
    locator_is_stale,
    read_locator,
    record_crash,
    remove_locator,
    reset_crash_count,
    write_locator,
)

if TYPE_CHECKING:
    from .platforms import TrayPlatformAdapter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Status query
# ---------------------------------------------------------------------------


def get_status(
    guard_home: Path,
    *,
    package_version: str = "",
    adapter: TrayPlatformAdapter | None = None,
) -> tuple[TrayState, TrayCapability, TrayLocator | None]:
    """Return the current tray state, capability, and locator (if any).

    Reconciles on-disk locator with live process state:
    - If locator is missing → state is ABSENT or SUPPORTED (based on capability)
    - If locator exists but process is dead → state is STALE
    - If locator exists and process is alive → state is RUNNING
    - If crash loop detected → state is REPAIR_REQUIRED
    """
    capability = detect_capability()
    if not capability.supported:
        return TrayState.UNSUPPORTED, capability, None

    try:
        locator = read_locator(guard_home)
    except ValueError as error:
        logger.warning("tray: locator malformed: %s", error)
        return TrayState.REPAIR_REQUIRED, capability, None

    if locator is None:
        # No running process. Check if a startup registration exists
        # (LaunchAgent/Task Scheduler/XDG autostart) so the dashboard
        # can show INSTALLED vs SUPPORTED.
        if adapter is None:
            adapter = detect_platform_adapter()
        if adapter is not None:
            try:
                reg = adapter.inspect_registration(guard_home=guard_home)
                if reg.get("installed") and reg.get("owned"):
                    return TrayState.INSTALLED, capability, None
            except Exception:
                # Registration inspection is non-fatal; fall through to SUPPORTED.
                pass
        return TrayState.SUPPORTED, capability, None

    if crash_loop_detected(guard_home):
        return TrayState.REPAIR_REQUIRED, capability, locator

    if locator_is_stale(locator):
        return TrayState.STALE, capability, locator

    return TrayState.RUNNING, capability, locator


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------


def start_tray(
    guard_home: Path,
    *,
    package_version: str = "",
    force: bool = False,
    adapter: TrayPlatformAdapter | None = None,
) -> TrayLifecycleResult:
    """Start the tray icon process.

    Steps:
    1. Detect capability. If unsupported, return failure.
    2. Check for existing running tray. If running and not force, return ALREADY_RUNNING.
    3. Check crash loop. If detected, return CRASH_LOOP_DETECTED.
    4. Start the tray process via the platform adapter.
    5. Wait for the process to report readiness (locator file written).
    6. Reset crash count on success.

    Returns a TrayLifecycleResult with state, reason, and message.
    """
    capability = detect_capability()
    if not capability.supported:
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.UNSUPPORTED,
            reason=capability.reason,
            message=f"Tray not supported: {capability.details}",
        )

    # Check for existing running tray
    state, _, existing_locator = get_status(guard_home, package_version=package_version, adapter=adapter)
    if state == TrayState.RUNNING and existing_locator is not None:
        if force:
            logger.info("tray: force-stopping existing tray at pid %s", existing_locator.pid)
            stop_result = stop_tray(guard_home, adapter=adapter)
            if not stop_result.ok:
                # Abort: if the old tray ignores SIGTERM and we proceed,
                # we'd have two tray processes competing for the same
                # locator. The user must manually repair.
                return TrayLifecycleResult(
                    ok=False,
                    state=TrayState.REPAIR_REQUIRED,
                    reason=TrayReasonCode.PROCESS_STOP_TIMEOUT,
                    message=(
                        f"Force-stop of existing tray (pid {existing_locator.pid}) failed: "
                        f"{stop_result.message}. Run 'hol-guard guard tray repair' to reset."
                    ),
                    recovery_command="hol-guard guard tray repair",
                )
        else:
            return TrayLifecycleResult(
                ok=True,
                state=TrayState.RUNNING,
                reason=TrayReasonCode.ALREADY_RUNNING,
                message=f"Tray already running (pid {existing_locator.pid})",
            )

    # Check crash loop
    if crash_loop_detected(guard_home):
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.REPAIR_REQUIRED,
            reason=TrayReasonCode.CRASH_LOOP_DETECTED,
            message=f"Crash loop detected ({MAX_CRASH_RETRIES} crashes). Run 'hol-guard guard tray repair' to reset.",
        )

    # Clean up stale locator if present
    if state == TrayState.STALE:
        logger.info("tray: removing stale locator")
        remove_locator(guard_home)

    # Start the process
    if adapter is not None:
        return _start_via_adapter(
            guard_home,
            package_version=package_version,
            capability=capability,
            adapter=adapter,
        )

    # Default: spawn a subprocess running the tray runtime
    return _start_subprocess(
        guard_home,
        package_version=package_version,
        capability=capability,
    )


def _start_subprocess(
    guard_home: Path,
    *,
    package_version: str,
    capability: TrayCapability,
) -> TrayLifecycleResult:
    """Start the tray as a detached subprocess."""
    executable = sys.executable
    module = "codex_plugin_scanner.guard.tray.runtime"
    args = [executable, "-m", module, "--guard-home", str(guard_home)]

    try:
        if os.name == "nt":
            # Windows: detached process
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            proc = subprocess.Popen(
                args,
                creationflags=creationflags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
        else:
            # POSIX: new session, detached
            proc = subprocess.Popen(
                args,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
    except OSError as error:
        logger.exception("tray: failed to spawn subprocess")
        record_crash(guard_home)
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.FAILED,
            reason=TrayReasonCode.INTERNAL_ERROR,
            message=f"Failed to start tray process: {error}",
        )

    # Wait for readiness (locator file appears)
    deadline = time.monotonic() + PROCESS_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if not is_process_alive(proc.pid):
            logger.error("tray: process exited during startup (pid %s)", proc.pid)
            record_crash(guard_home)
            return TrayLifecycleResult(
                ok=False,
                state=TrayState.FAILED,
                reason=TrayReasonCode.INTERNAL_ERROR,
                message=f"Tray process exited during startup (pid {proc.pid})",
            )
        try:
            locator = read_locator(guard_home)
            if locator is not None and locator.pid == proc.pid:
                reset_crash_count(guard_home)
                return TrayLifecycleResult(
                    ok=True,
                    state=TrayState.RUNNING,
                    reason=TrayReasonCode.OK,
                    message=f"Tray started (pid {proc.pid})",
                )
        except ValueError:
            logger.warning("tray: locator malformed during startup")
        time.sleep(0.2)

    # Timeout
    logger.error("tray: startup timed out (pid %s)", proc.pid)
    record_crash(guard_home)
    return TrayLifecycleResult(
        ok=False,
        state=TrayState.FAILED,
        reason=TrayReasonCode.PROCESS_START_TIMEOUT,
        message=f"Tray process did not report readiness within {PROCESS_START_TIMEOUT_SECONDS}s (pid {proc.pid})",
    )


def _start_via_adapter(
    guard_home: Path,
    *,
    package_version: str,
    capability: TrayCapability,
    adapter: TrayPlatformAdapter,
) -> TrayLifecycleResult:
    """Start the tray via a platform adapter (for testing or custom backends)."""
    try:
        result = adapter.start_process(guard_home=guard_home, capability=capability)
    except Exception as error:
        logger.exception("tray: adapter.start_process failed")
        record_crash(guard_home)
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.FAILED,
            reason=TrayReasonCode.INTERNAL_ERROR,
            message=f"Adapter failed to start tray: {error}",
        )

    if not result.get("started"):
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.FAILED,
            reason=TrayReasonCode(result.get("reason", "internal_error")),
            message=str(result.get("message", "Adapter did not start the tray")),
        )

    pid = result.get("pid", 0)
    deadline = time.monotonic() + PROCESS_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            locator = read_locator(guard_home)
            if locator is not None and (pid == 0 or locator.pid == pid):
                reset_crash_count(guard_home)
                actual_pid = locator.pid if locator.pid else pid
                return TrayLifecycleResult(
                    ok=True,
                    state=TrayState.RUNNING,
                    reason=TrayReasonCode.OK,
                    message=f"Tray started (pid {actual_pid})",
                )
        except ValueError:
            pass
        time.sleep(0.2)

    record_crash(guard_home)
    return TrayLifecycleResult(
        ok=False,
        state=TrayState.FAILED,
        reason=TrayReasonCode.PROCESS_START_TIMEOUT,
        message=f"Tray process did not report readiness within {PROCESS_START_TIMEOUT_SECONDS}s (pid {pid})",
    )


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------


def stop_tray(
    guard_home: Path,
    *,
    adapter: TrayPlatformAdapter | None = None,
) -> TrayLifecycleResult:
    """Stop the running tray process.

    Sends SIGTERM (POSIX) or taskkill (Windows), waits for exit, then
    removes the locator. If the process doesn't exit within
    ``PROCESS_STOP_TIMEOUT_SECONDS``, returns a timeout failure.
    """
    try:
        locator = read_locator(guard_home)
    except ValueError as error:
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.REPAIR_REQUIRED,
            reason=TrayReasonCode.LOCATOR_MALFORMED,
            message=f"Locator file is malformed: {error}",
            recovery_command="hol-guard guard tray repair",
        )

    if locator is None:
        return TrayLifecycleResult(
            ok=True,
            state=TrayState.ABSENT,
            reason=TrayReasonCode.NOT_RUNNING,
            message="No tray is running",
        )

    if not is_process_alive(locator.pid):
        logger.info("tray: process already dead, cleaning up locator")
        remove_locator(guard_home)
        return TrayLifecycleResult(
            ok=True,
            state=TrayState.ABSENT,
            reason=TrayReasonCode.NOT_RUNNING,
            message="Tray process was not running; locator removed",
        )

    # PID-reuse safety: if the process start fingerprint no longer matches
    # the locator, the PID was recycled to an unrelated process. Refuse to
    # signal it; clean up our stale locator instead.
    if locator_is_stale(locator):
        logger.warning(
            "tray: locator pid %s is stale (PID reused or process replaced); cleaning up",
            locator.pid,
        )
        remove_locator(guard_home)
        return TrayLifecycleResult(
            ok=True,
            state=TrayState.ABSENT,
            reason=TrayReasonCode.NOT_RUNNING,
            message="Tray process was no longer the one we started; locator removed (no signal sent)",
        )

    # Stop via adapter or direct signal
    if adapter is not None:
        try:
            adapter.stop_process(pid=locator.pid)
        except Exception as error:
            logger.exception("tray: adapter.stop_process failed")
            return TrayLifecycleResult(
                ok=False,
                state=TrayState.RUNNING,
                reason=TrayReasonCode.INTERNAL_ERROR,
                message=f"Failed to stop tray: {error}",
            )
    else:
        try:
            _terminate_process(locator.pid)
        except Exception as error:
            logger.exception("tray: failed to terminate process")
            return TrayLifecycleResult(
                ok=False,
                state=TrayState.RUNNING,
                reason=TrayReasonCode.INTERNAL_ERROR,
                message=f"Failed to stop tray: {error}",
            )

    # Wait for exit
    deadline = time.monotonic() + PROCESS_STOP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if not is_process_alive(locator.pid):
            remove_locator(guard_home)
            return TrayLifecycleResult(
                ok=True,
                state=TrayState.ABSENT,
                reason=TrayReasonCode.OK,
                message=f"Tray stopped (pid {locator.pid})",
            )
        time.sleep(0.1)

    return TrayLifecycleResult(
        ok=False,
        state=TrayState.RUNNING,
        reason=TrayReasonCode.PROCESS_STOP_TIMEOUT,
        message=f"Tray process did not exit within {PROCESS_STOP_TIMEOUT_SECONDS}s (pid {locator.pid})",
        recovery_command="hol-guard guard tray repair",
    )


def _terminate_process(pid: int) -> None:
    """Terminate a process gracefully (SIGTERM on POSIX, taskkill on Windows)."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    else:
        import signal

        os.kill(pid, signal.SIGTERM)


# ---------------------------------------------------------------------------
# Repair
# ---------------------------------------------------------------------------


def repair_tray(guard_home: Path) -> TrayLifecycleResult:
    """Repair the tray state after crashes or corruption.

    Steps:
    1. Stop any running tray (best-effort).
    2. Remove the locator file.
    3. Reset crash count.
    4. Return success — caller can now ``start_tray`` fresh.
    """
    logger.info("tray: starting repair")

    # Best-effort stop
    try:
        stop_result = stop_tray(guard_home)
        if not stop_result.ok:
            logger.warning("tray: repair could not stop tray: %s", stop_result.message)
    except Exception as error:
        logger.warning("tray: repair stop failed: %s", error)

    # Remove locator
    remove_locator(guard_home)

    # Reset crash count by writing a fresh locator then removing it
    # (reset_crash_count only works if a locator exists)
    try:
        fresh = build_locator_for_current_process(
            guard_home=guard_home,
            package_version="",
            backend=TrayBackend.NONE,
        )
        write_locator(guard_home, fresh)
        reset_crash_count(guard_home)
        remove_locator(guard_home)
    except Exception as error:
        logger.warning("tray: could not reset crash count: %s", error)

    return TrayLifecycleResult(
        ok=True,
        state=TrayState.ABSENT,
        reason=TrayReasonCode.OK,
        message="Tray state repaired. Run 'hol-guard tray start' to start the tray.",
    )


# ---------------------------------------------------------------------------
# Registration management
# ---------------------------------------------------------------------------


def install_registration(
    guard_home: Path,
    *,
    adapter: TrayPlatformAdapter,
    run_at_login: bool = True,
) -> TrayLifecycleResult:
    """Install the tray startup registration (LaunchAgent / Run key / autostart)."""
    capability = detect_capability()
    if not capability.supported:
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.UNSUPPORTED,
            reason=capability.reason,
            message=f"Tray not supported: {capability.details}",
        )

    try:
        result = adapter.install_registration(
            guard_home=guard_home,
            capability=capability,
            run_at_login=run_at_login,
        )
    except Exception as error:
        logger.exception("tray: registration install failed")
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.SUPPORTED,
            reason=TrayReasonCode.STARTUP_REGISTRATION_FAILED,
            message=f"Failed to install registration: {error}",
        )

    if not result.get("installed"):
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.SUPPORTED,
            reason=TrayReasonCode.STARTUP_REGISTRATION_FAILED,
            message=str(result.get("message", "Registration was not installed")),
        )

    return TrayLifecycleResult(
        ok=True,
        state=TrayState.INSTALLED,
        reason=TrayReasonCode.OK,
        message="Tray startup registration installed",
    )


def remove_registration(
    guard_home: Path,
    *,
    adapter: TrayPlatformAdapter,
) -> TrayLifecycleResult:
    """Remove the tray startup registration."""
    try:
        result = adapter.remove_registration(guard_home=guard_home)
    except Exception as error:
        logger.exception("tray: registration removal failed")
        return TrayLifecycleResult(
            ok=False,
            state=TrayState.INSTALLED,
            reason=TrayReasonCode.INTERNAL_ERROR,
            message=f"Failed to remove registration: {error}",
        )

    if not result.get("removed"):
        return TrayLifecycleResult(
            ok=True,
            state=TrayState.SUPPORTED,
            reason=TrayReasonCode.NOT_INSTALLED,
            message=str(result.get("message", "No registration was present")),
        )

    return TrayLifecycleResult(
        ok=True,
        state=TrayState.SUPPORTED,
        reason=TrayReasonCode.OK,
        message="Tray startup registration removed",
    )
