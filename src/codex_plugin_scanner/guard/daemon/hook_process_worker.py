"""Process primitives shared by the isolated hook worker pool."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Protocol


class WorkerProcess(Protocol):
    @property
    def pid(self) -> int | None: ...

    def is_alive(self) -> bool: ...
    def join(self, timeout: float | None = None) -> None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...


class WorkerConnection(Protocol):
    def send(self, obj: object) -> None: ...
    def recv(self) -> object: ...
    def poll(self, timeout: float = 0.0) -> bool: ...
    def close(self) -> None: ...


@dataclass(slots=True)
class HookWorkerSlot:
    process: WorkerProcess
    connection: WorkerConnection
    retire_lock: threading.Lock = field(default_factory=threading.Lock)
    retired: bool = False


@dataclass(frozen=True, slots=True)
class HookProcessReview:
    """One isolated hook evaluation result."""

    payload: dict[str, object] | None
    reason_code: str | None


def terminate_worker_tree(process: WorkerProcess, signal_number: int) -> None:
    """Signal one isolated worker and its descendants."""

    if os.name == "nt" and process.pid is not None:
        system_root = os.environ.get("SYSTEMROOT")
        taskkill = os.path.join(system_root, "System32", "taskkill.exe") if system_root else "taskkill.exe"
        try:
            result = subprocess.run(
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0:
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
    if os.name != "nt" and process.pid is not None:
        try:
            os.killpg(process.pid, signal_number)
            return
        except (OSError, ProcessLookupError):
            pass
    if signal_number == getattr(signal, "SIGKILL", 9):
        with suppress(OSError):
            process.kill()
    else:
        with suppress(OSError):
            process.terminate()


__all__ = [
    "HookProcessReview",
    "HookWorkerSlot",
    "WorkerConnection",
    "WorkerProcess",
    "terminate_worker_tree",
]
