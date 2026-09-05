"""Process primitives shared by the isolated hook worker pool."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Protocol

from ..codex_hook_windows_job import windows_system_executable_path

_WORKER_RETIRE_JOIN_TIMEOUT_SECONDS = 2.0


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
    handshake_lock: threading.RLock = field(default_factory=threading.RLock)
    retire_lock: threading.Lock = field(default_factory=threading.Lock)
    retired: bool = False
    windows_job_contained: bool = False
    isolation_ready: bool = False
    pre_isolation_contained: bool = False
    request_exposed: bool = False


@dataclass(frozen=True, slots=True)
class HookProcessReview:
    """One isolated hook evaluation result."""

    payload: dict[str, object] | None
    reason_code: str | None
    receipt: dict[str, object] | None = None


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


def terminate_owned_process_group(process: WorkerProcess, signal_number: int) -> bool:
    if os.name == "nt" or process.pid is None or not process.is_alive():
        return False
    try:
        os.killpg(process.pid, signal_number)
        return True
    except ProcessLookupError:
        with suppress(OSError):
            process.kill()
        return True
    except OSError:
        return False


def retire_worker_slot(slot: HookWorkerSlot, *, graceful: bool = False) -> bool:
    """Contain one worker tree; callers may run this outside request deadlines."""

    with slot.retire_lock:
        if slot.retired:
            return not slot.process.is_alive()
        slot.retired = True
    if graceful and slot.process.is_alive():
        with slot.handshake_lock:
            with suppress(BrokenPipeError, OSError):
                slot.connection.send(("stop", None))
            slot.process.join(timeout=0.2)
    if os.name != "nt" and slot.isolation_ready:
        tree_contained = terminate_owned_process_group(slot.process, getattr(signal, "SIGKILL", 9))
    elif slot.pre_isolation_contained:
        if slot.process.is_alive():
            with suppress(OSError):
                slot.process.kill()
        tree_contained = True
    elif slot.process.is_alive():
        with suppress(OSError):
            slot.process.kill()
        tree_contained = False
    else:
        # A worker that died before the parent sent it a review request never
        # handled untrusted input. Its dead bootstrap process cannot retain
        # request-derived descendants, so the supervisor may safely replace it.
        tree_contained = slot.windows_job_contained or not slot.request_exposed
    slot.process.join(timeout=_WORKER_RETIRE_JOIN_TIMEOUT_SECONDS)
    contained = (tree_contained or slot.windows_job_contained) and not slot.process.is_alive()
    if not contained:
        with slot.retire_lock:
            slot.retired = False
    return contained


def worker_retirement_thread(
    slot: HookWorkerSlot,
    *,
    graceful: bool,
    name: str,
    on_contained: Callable[[], None],
    on_failed: Callable[[], None],
    on_done: Callable[[threading.Thread], None],
) -> threading.Thread:
    def retire() -> None:
        try:
            if retire_worker_slot(slot, graceful=graceful):
                on_contained()
            else:
                on_failed()
        finally:
            on_done(threading.current_thread())

    return threading.Thread(target=retire, name=name, daemon=True)


__all__ = [
    "HookProcessReview",
    "HookWorkerSlot",
    "WorkerConnection",
    "WorkerProcess",
    "retire_worker_slot",
    "terminate_owned_process_group",
    "terminate_worker_tree",
    "worker_retirement_thread",
]
