"""Terminate an isolated worker process tree and report whether containment was proven."""

from __future__ import annotations

import os
import signal
import subprocess
from contextlib import suppress
from typing import Protocol

from .codex_hook_windows_job import windows_system_executable_path


class WorkerProcess(Protocol):
    @property
    def pid(self) -> int | None: ...

    def is_alive(self) -> bool: ...
    def join(self, timeout: float | None = None) -> None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...


def terminate_worker_tree(process: WorkerProcess, signal_number: int) -> bool:
    """Signal one isolated worker tree and report whether tree containment was proven."""

    if os.name == "nt" and process.pid is not None:
        try:
            result = subprocess.run(
                [windows_system_executable_path("taskkill.exe"), "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
    if os.name != "nt" and process.pid is not None:
        try:
            os.killpg(process.pid, signal_number)
            return True
        except ProcessLookupError:
            pass
        except OSError:
            pass
    if signal_number == getattr(signal, "SIGKILL", 9):
        with suppress(OSError):
            process.kill()
    else:
        with suppress(OSError):
            process.terminate()
    return False


__all__ = ["WorkerProcess", "terminate_worker_tree"]
