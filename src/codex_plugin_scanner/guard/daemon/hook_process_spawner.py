from __future__ import annotations

import multiprocessing
import os
import time
from pathlib import Path

from .hook_process_entrypoint import hook_worker_main
from .hook_process_protocol import as_string_object_dict, is_pair
from .hook_process_worker import HookWorkerSlot


def spawn_hook_worker(guard_home: Path | None) -> HookWorkerSlot:
    context = multiprocessing.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=True)
    process = context.Process(
        target=hook_worker_main,
        args=(child_connection, str(guard_home) if guard_home is not None else None),
        name="hol-guard-hook-worker",
        daemon=False,
    )
    try:
        process.start()
    except BaseException:
        parent_connection.close()
        child_connection.close()
        raise
    child_connection.close()
    return HookWorkerSlot(
        process=process,
        connection=parent_connection,
        isolation_ready=False,
    )


def hook_worker_became_isolated(slot: HookWorkerSlot, timeout: float) -> bool:
    if timeout <= 0:
        return False
    try:
        if not slot.connection.poll(timeout):
            return False
        message = slot.connection.recv()
        if message == ("isolation_failed", None):
            slot.pre_isolation_contained = True
            return False
        if not is_pair(message) or message[0] != "isolated":
            return False
        proof = as_string_object_dict(message[1])
        if proof is None:
            return False
        if os.name == "nt":
            if proof.get("windows_job_contained") is not True:
                return False
            slot.windows_job_contained = True
        elif proof.get("process_group_id") != slot.process.pid:
            return False
        slot.isolation_ready = True
        return True
    except (EOFError, OSError):
        return False


def hook_worker_became_ready(slot: HookWorkerSlot, timeout: float) -> bool:
    if timeout <= 0:
        return False
    deadline = time.monotonic() + timeout
    if not slot.isolation_ready and not hook_worker_became_isolated(slot, timeout):
        return False
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    try:
        return slot.connection.poll(remaining) and slot.connection.recv() == ("ready", None)
    except (EOFError, OSError):
        return False


__all__ = [
    "hook_worker_became_isolated",
    "hook_worker_became_ready",
    "spawn_hook_worker",
]
