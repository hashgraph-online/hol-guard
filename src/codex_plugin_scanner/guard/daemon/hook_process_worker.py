"""Process primitives shared by the isolated hook worker pool."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Protocol

from ..codex_hook_windows_job import windows_system_executable_path


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
    windows_job_contained: bool = False
    isolation_ready: bool = True


@dataclass(frozen=True, slots=True)
class HookProcessReview:
    """One isolated hook evaluation result."""

    payload: dict[str, object] | None
    reason_code: str | None


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


def retire_worker_slot(slot: HookWorkerSlot, *, graceful: bool = False) -> bool:
    """Contain one worker tree; callers may run this outside request deadlines."""

    with slot.retire_lock:
        if slot.retired:
            return not slot.process.is_alive()
        slot.retired = True
    if graceful and slot.process.is_alive():
        with suppress(BrokenPipeError, OSError):
            slot.connection.send(("stop", None))
        slot.process.join(timeout=0.2)
    if not slot.process.is_alive():
        return True
    tree_contained = terminate_worker_tree(slot.process, getattr(signal, "SIGKILL", 9))
    slot.process.join(timeout=0.5)
    contained = (
        tree_contained or slot.windows_job_contained or not slot.isolation_ready
    ) and not slot.process.is_alive()
    if not contained:
        with slot.retire_lock:
            slot.retired = False
    return contained


__all__ = [
    "HookProcessReview",
    "HookWorkerSlot",
    "WorkerConnection",
    "WorkerProcess",
    "retire_worker_slot",
    "terminate_worker_tree",
]
