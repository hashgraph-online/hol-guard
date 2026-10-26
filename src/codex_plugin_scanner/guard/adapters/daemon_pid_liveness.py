"""Daemon PID liveness check embedded in generated hook clients."""

from __future__ import annotations

DAEMON_PID_LIVENESS_TEMPLATE = """
def _daemon_pid_is_alive(pid: int) -> bool:
    if os.name == "nt":
        # Signal 0 is CTRL_C_EVENT on Windows; os.kill would send a console
        # interrupt, and fails outright when the daemon has another console.
        try:
            from codex_plugin_scanner.guard.windows_paths import windows_process_liveness
        except Exception:
            return True
        return windows_process_liveness(pid) is not False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True
"""
