"""Record unlisted CLI launches seen on the native hook path, off the decision path."""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Mapping
from pathlib import Path

from .hook_native_saved_approval import _launch_cwd
from .hook_request_parsing import pre_tool_command

_LOGGER = logging.getLogger(__name__)
_MAX_PENDING = 64

_lock = threading.Lock()
_pending: queue.Queue[tuple[object, str, Path, Path | None]] = queue.Queue(maxsize=_MAX_PENDING)
_worker: threading.Thread | None = None


def observe_native_pre_tool_cli(
    store: object,
    *,
    payload: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
) -> bool:
    """Queue the payload command for CLI observation; drop it when the queue is full."""

    command = pre_tool_command(payload)
    if command is None:
        return False
    cwd = _launch_cwd(payload, workspace)
    if cwd is None:
        return False
    try:
        _pending.put_nowait((store, command, cwd, home_dir))
    except queue.Full:
        return False
    _ensure_worker()
    return True


def _ensure_worker() -> None:
    global _worker
    with _lock:
        if _worker is not None and _worker.is_alive():
            return
        _worker = threading.Thread(target=_drain, name="hol-guard-cli-observer", daemon=True)
        _worker.start()


def _drain() -> None:
    from ..local_cli_hook import observe_unlisted_cli

    while True:
        store, command, cwd, home_dir = _pending.get()
        try:
            observe_unlisted_cli(store=store, command=command, cwd=cwd, home_dir=home_dir)
        except Exception:
            _LOGGER.warning("native CLI observation failed", exc_info=True)
        finally:
            _pending.task_done()


__all__ = ["observe_native_pre_tool_cli"]
