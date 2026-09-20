"""Guard daemon locks helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


@_manager.contextmanager
def _guard_daemon_recovery_lock(guard_home: _manager.Path, *, timeout_seconds: float | None = None):
    """Serialize a complete daemon recovery transaction for one Guard home."""

    lock_key = str(guard_home.resolve())
    with _manager._RECOVERY_LOCKS_GUARD:
        thread_lock = _manager._RECOVERY_LOCKS.setdefault(lock_key, _manager.threading.Lock())
    deadline = None if timeout_seconds is None else _manager.time.monotonic() + max(0.0, timeout_seconds)
    if timeout_seconds is None:
        acquired_thread_lock = thread_lock.acquire()
    else:
        assert deadline is not None
        acquired_thread_lock = thread_lock.acquire(timeout=max(0.0, deadline - _manager.time.monotonic()))
    if not acquired_thread_lock:
        raise RuntimeError("Timed out waiting for Guard daemon recovery ownership.")
    file_locked = False
    try:
        lock_path = guard_home / _manager._GUARD_DAEMON_RECOVERY_LOCK_FILE
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            if timeout_seconds is None:
                _manager._lock_daemon_start_file(handle)
                file_locked = True
            else:
                assert deadline is not None
                while _manager.time.monotonic() < deadline:
                    if _manager._try_lock_daemon_file(handle):
                        file_locked = True
                        break
                    _manager.time.sleep(
                        min(
                            _manager.GUARD_DAEMON_POLL_INTERVAL_SECONDS,
                            max(0.0, deadline - _manager.time.monotonic()),
                        )
                    )
                if not file_locked:
                    raise RuntimeError("Timed out waiting for Guard daemon recovery ownership.")
            try:
                yield
            finally:
                if file_locked:
                    _manager._unlock_daemon_start_file(handle)
    finally:
        thread_lock.release()


def acquire_guard_daemon_owner_lock(guard_home: _manager.Path) -> _manager.BinaryIO:
    """Claim the single daemon slot before any background worker can read secrets."""

    inventory = _manager._guard_daemon_process_inventory_for_guard_home(guard_home)
    if inventory is None:
        raise RuntimeError("Guard could not verify that the daemon slot is available.")
    if any(pid != _manager.os.getpid() for pid, _port in inventory):
        raise RuntimeError("A Guard daemon is already active for this Guard home.")
    lock_path = guard_home / _manager._GUARD_DAEMON_OWNER_LOCK_FILE
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    if not _manager._try_lock_daemon_file(handle):
        handle.close()
        raise RuntimeError("A Guard daemon is already active for this Guard home.")
    inventory = _manager._guard_daemon_process_inventory_for_guard_home(guard_home)
    if inventory is None or any(pid != _manager.os.getpid() for pid, _port in inventory):
        _manager._unlock_daemon_start_file(handle)
        handle.close()
        raise RuntimeError("A Guard daemon is already active for this Guard home.")
    return handle


def release_guard_daemon_owner_lock(handle: _manager.BinaryIO | None) -> None:
    if handle is None or handle.closed:
        return
    _manager._unlock_daemon_start_file(handle)
    handle.close()


@_manager.contextmanager
def _guard_daemon_state_write_lock(guard_home: _manager.Path):
    """Serialize the token/state generation across threads and processes."""

    lock_key = str(guard_home.resolve())
    with _manager._STATE_WRITE_LOCKS_GUARD:
        thread_lock = _manager._STATE_WRITE_LOCKS.setdefault(lock_key, _manager.threading.Lock())
    with thread_lock:
        lock_path = guard_home / "daemon-state-write.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            _manager._lock_daemon_start_file(handle)
            try:
                yield
            finally:
                _manager._unlock_daemon_start_file(handle)
