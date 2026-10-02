from __future__ import annotations

import multiprocessing
import os
import time
from pathlib import Path

from .hook_process_entrypoint import hook_worker_main
from .hook_process_protocol import as_string_object_dict, is_pair
from .hook_process_worker import HookWorkerSlot, allowlisted_startup_failure_code


def _record_startup_failure(slot: HookWorkerSlot, code: str) -> None:
    with slot.startup_failure_lock:
        if slot.startup_failure_code is None:
            slot.startup_failure_code = code


def _message_startup_failure(message: object, *, kind: str, prefix: str, fallback: str) -> str:
    if not is_pair(message) or message[0] != kind:
        return fallback
    details = as_string_object_dict(message[1])
    code = allowlisted_startup_failure_code(details.get("reason_code")) if details is not None else None
    return code if code is not None and code.startswith(prefix) else fallback


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
        _record_startup_failure(slot, "hook_process_isolation_timeout")
        return False
    deadline = time.monotonic() + timeout
    if not slot.handshake_lock.acquire(timeout=timeout):
        _record_startup_failure(slot, "hook_process_isolation_timeout")
        return False
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not slot.connection.poll(remaining):
            _record_startup_failure(slot, "hook_process_isolation_timeout")
            return False
        message = slot.connection.recv()
        if is_pair(message) and message[0] == "isolation_failed":
            slot.pre_isolation_contained = True
            _record_startup_failure(
                slot,
                _message_startup_failure(
                    message,
                    kind="isolation_failed",
                    prefix="hook_process_isolation_",
                    fallback="hook_process_isolation_failed",
                ),
            )
            return False
        if not is_pair(message) or message[0] != "isolated":
            _record_startup_failure(slot, "hook_process_isolation_protocol")
            return False
        proof = as_string_object_dict(message[1])
        if proof is None:
            _record_startup_failure(slot, "hook_process_isolation_protocol")
            return False
        if os.name == "nt":
            if proof.get("windows_job_contained") is not True:
                _record_startup_failure(slot, "hook_process_isolation_proof_failed")
                return False
            slot.windows_job_contained = True
        elif proof.get("process_group_id") != slot.process.pid:
            _record_startup_failure(slot, "hook_process_isolation_proof_failed")
            return False
        slot.isolation_ready = True
        return True
    except (EOFError, OSError):
        _record_startup_failure(slot, "hook_process_isolation_pipe_failed")
        return False
    finally:
        slot.handshake_lock.release()


def hook_worker_became_ready(slot: HookWorkerSlot, timeout: float) -> bool:
    if timeout <= 0:
        _record_startup_failure(slot, "hook_process_ready_timeout")
        return False
    deadline = time.monotonic() + timeout
    if not slot.handshake_lock.acquire(timeout=timeout):
        _record_startup_failure(slot, "hook_process_ready_timeout")
        return False
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _record_startup_failure(slot, "hook_process_ready_timeout")
            return False
        if not slot.isolation_ready and not hook_worker_became_isolated(slot, remaining):
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _record_startup_failure(slot, "hook_process_ready_timeout")
            return False
        if not slot.connection.poll(remaining):
            _record_startup_failure(slot, "hook_process_ready_timeout")
            return False
        message = slot.connection.recv()
        if message == ("ready", None):
            return True
        _record_startup_failure(
            slot,
            _message_startup_failure(
                message,
                kind="worker_failed",
                prefix="hook_process_evaluator_",
                fallback="hook_process_ready_protocol",
            ),
        )
        return False
    except (EOFError, OSError):
        _record_startup_failure(slot, "hook_process_ready_pipe_failed")
        return False
    finally:
        slot.handshake_lock.release()


__all__ = [
    "hook_worker_became_isolated",
    "hook_worker_became_ready",
    "spawn_hook_worker",
]
