"""Cross-request daemon state for replayed requests.

Replay processes run side by side, so every read-check-write of this state
holds an exclusive lock on ``daemon-replay-state.lock`` and rereads the file
first: a nonce or challenge one process consumes is gone for the next.
"""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from .mcp_discovery_jobs import _JOB_ID, _MAX_RUNNING_JOBS, DiscoveryJobError, McpDiscoveryJobs, _Job

try:
    import fcntl
except ImportError:  # pragma: no cover - the native edge runs on Unix only
    fcntl = None


_STATE_FILENAME = "daemon-replay-state.json"
_LOCK_FILENAME = "daemon-replay-state.lock"
_STATE_LIMIT_BYTES = 1024 * 1024
_PERSISTED_FIELDS = (
    "guard_cloud_connect_state",
    "package_firewall_connect_state",
    "daemon_discovery_challenges",
    "dashboard_reconnect_consumed_challenges",
    "package_firewall_session_nonces",
    "mcp_discovery_jobs",
)
_DISCOVERY_FIELD = "mcp_discovery_jobs"
_DISCOVERY_RETENTION_SECONDS = 600.0
_DISCOVERY_CANCEL_POLL_SECONDS = 0.5


class _FileLock:
    """An exclusive lock shared by every replay process, reentrant in each."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._local = threading.RLock()
        self._depth = 0
        self._descriptor: int | None = None

    def __enter__(self) -> _FileLock:
        _ = self._local.acquire()
        if self._depth == 0:
            try:
                self._descriptor = _locked_descriptor(self._path)
            except OSError:
                self._local.release()
                raise
        self._depth += 1
        return self

    def __exit__(self, *exc: object) -> None:
        self._depth -= 1
        if self._depth == 0 and self._descriptor is not None:
            # Closing the descriptor releases the lock.
            with suppress(OSError):
                os.close(self._descriptor)
            self._descriptor = None
        self._local.release()


def _locked_descriptor(path: Path) -> int:
    """An open descriptor holding the exclusive lock on ``path``.

    Raises instead of going on unlocked: two replays must never both believe
    they hold the shared state.
    """

    if fcntl is None:
        raise OSError("file locking is unavailable")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


class _ReplayState:
    """The cross-request fields, read from and written back to one file."""

    def __init__(self, guard_home: Path) -> None:
        self._path = guard_home / _STATE_FILENAME
        self.lock = _FileLock(guard_home / _LOCK_FILENAME)

    def read(self) -> dict[str, Any]:
        try:
            if self._path.is_symlink():
                return {}
            with self._path.open("rb") as handle:
                raw = handle.read(_STATE_LIMIT_BYTES + 1)
        except OSError:
            return {}
        if len(raw) > _STATE_LIMIT_BYTES:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def get(self, field: str) -> Any:
        with self.lock:
            return self.read().get(field)

    def set(self, field: str, value: Any) -> None:
        with self.lock:
            state = self.read()
            if value is None:
                state.pop(field, None)
            else:
                state[field] = value
            encoded = json.dumps(state, separators=(",", ":"), default=str).encode("utf-8")
            if len(encoded) > _STATE_LIMIT_BYTES:
                return
            temporary = self._path.with_name(f".{_STATE_FILENAME}.{os.getpid()}.{threading.get_ident()}")
            with suppress(OSError):
                temporary.unlink()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(temporary, flags, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self._path)
            except OSError:
                with suppress(OSError):
                    temporary.unlink()


class _PersistedMapping(dict[str, Any]):
    """A dict whose every change is written back to the replay state."""

    def __init__(self, state: _ReplayState, field: str) -> None:
        super().__init__()
        self._state = state
        self._field = field
        self.reload()

    def reload(self) -> None:
        """Replace the contents with what another process may have written."""

        stored = self._state.get(self._field)
        super().clear()
        super().update(stored if isinstance(stored, dict) else {})

    def _save(self) -> None:
        self._state.set(self._field, dict(self))

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(key, value)
        self._save()

    def __delitem__(self, key: Any) -> None:
        super().__delitem__(key)
        self._save()

    def pop(self, key: Any, *default: Any) -> Any:
        value = super().pop(key, *default)
        self._save()
        return value

    def clear(self) -> None:
        super().clear()
        self._save()

    def update(self, *args: Any, **kwargs: Any) -> None:
        super().update(*args, **kwargs)
        self._save()


class _SyncedLock:
    """A handler lock that holds the replay state lock and rereads the
    mappings it guards, so a check-then-consume is atomic across processes."""

    def __init__(self, state: _ReplayState, *mappings: _PersistedMapping) -> None:
        self._state = state
        self._mappings = mappings

    def __enter__(self) -> _SyncedLock:
        _ = self._state.lock.__enter__()
        try:
            for mapping in self._mappings:
                mapping.reload()
        except BaseException:
            self._state.lock.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        self._state.lock.__exit__(*exc)


class _ReplayDiscoveryJobs(McpDiscoveryJobs):
    """Discovery jobs whose status every replay process can read.

    The process that starts a job runs it and records each state change; a
    later request, in another process, polls or cancels it through the
    record. The owner watches the record for a cancel.
    """

    def __init__(self, state: _ReplayState) -> None:
        super().__init__()
        self._state = state

    def _records(self) -> dict[str, dict[str, Any]]:
        stored = self._state.get(_DISCOVERY_FIELD)
        if not isinstance(stored, dict):
            return {}
        now = time.time()
        records: dict[str, dict[str, Any]] = {}
        for job_id, record in stored.items():
            if not isinstance(job_id, str) or not isinstance(record, dict):
                continue
            finished = record.get("finished")
            if isinstance(finished, (int, float)) and now - finished >= _DISCOVERY_RETENTION_SECONDS:
                continue
            if record.get("state") in {"running", "cancelling"} and not _process_alive(record.get("owner")):
                record = {**record, "state": "failed", "error": "discovery_failed", "finished": now}
            records[job_id] = record
        return records

    def _store(self, records: dict[str, dict[str, Any]]) -> None:
        self._state.set(_DISCOVERY_FIELD, records)

    @staticmethod
    def _public(job_id: str, record: dict[str, Any]) -> dict[str, object]:
        return {
            "job_id": job_id,
            "cli_id": record.get("cli_id", ""),
            "state": record.get("state"),
            "error": record.get("error"),
        }

    def start(
        self,
        cli_id: str,
        run: Any,
        *,
        reuse_seconds: float = 0,
        requested_job_id: str | None = None,
    ) -> dict[str, object]:
        with self._state.lock:
            records = self._records()
            if requested_job_id is not None and not _JOB_ID.fullmatch(requested_job_id):
                raise DiscoveryJobError("invalid_discovery_job")
            pending = records.get(requested_job_id or "")
            if pending is not None and pending.get("pending_cancel") is True:
                del records[requested_job_id or ""]
                self._store(records)
                return {"job_id": requested_job_id, "cli_id": cli_id, "state": "cancelled", "error": None}
            if pending is not None:
                raise DiscoveryJobError("discovery_job_id_conflict")
            now = time.time()
            for job_id, record in sorted(records.items(), key=lambda item: item[1].get("started", 0), reverse=True):
                if record.get("cli_id") != cli_id:
                    continue
                finished = record.get("finished")
                age = now - finished if isinstance(finished, (int, float)) else None
                if record.get("state") in {"running", "cancelling"}:
                    return self._public(job_id, record)
                if record.get("state") == "failed" and age is not None and age < 10:
                    raise DiscoveryJobError("discovery_retry_backoff")
                if record.get("state") == "complete" and age is not None and age < reuse_seconds:
                    return self._public(job_id, record)
                break
            if (
                sum(record.get("state") in {"running", "cancelling"} for record in records.values())
                >= _MAX_RUNNING_JOBS
            ):
                raise DiscoveryJobError("discovery_busy")
            job = super().start(cli_id, run, reuse_seconds=reuse_seconds, requested_job_id=requested_job_id)
            job_id = str(job["job_id"])
            records = self._records()
            records.setdefault(job_id, {"cli_id": cli_id, "started": now, "owner": os.getpid()}).update(
                {"state": job["state"], "error": job["error"]}
            )
            self._store(records)
            return job

    def read(self, job_id: str, *, cancel: bool = False) -> dict[str, object]:
        with self._state.lock:
            records = self._records()
            if job_id in self._jobs:
                public = super().read(job_id, cancel=cancel)
                if cancel and job_id in records:
                    records[job_id].update({"state": public["state"], "cancel": True})
                    self._store(records)
                return public
            record = records.get(job_id)
            if record is None or record.get("pending_cancel") is True:
                if cancel and _JOB_ID.fullmatch(job_id):
                    records[job_id] = {
                        "cli_id": "",
                        "state": "cancelled",
                        "pending_cancel": True,
                        "finished": time.time(),
                    }
                    self._store(records)
                    return {"job_id": job_id, "cli_id": "", "state": "cancelled", "error": None}
                raise DiscoveryJobError("discovery_job_unavailable")
            if cancel and record.get("state") == "running":
                record.update({"state": "cancelling", "cancel": True})
                self._store(records)
            return self._public(job_id, record)

    def _run(self, job: _Job, run: Any) -> None:
        watcher = threading.Thread(
            target=self._watch_cancel, args=(job,), name="hol-guard-mcp-discovery-cancel", daemon=True
        )
        watcher.start()
        try:
            super()._run(job, run)
        finally:
            with self._state.lock:
                records = self._records()
                record = records.setdefault(job.job_id, {"cli_id": job.cli_id, "started": time.time()})
                record.update({"state": job.state, "error": job.code, "finished": time.time(), "owner": os.getpid()})
                self._store(records)

    def _watch_cancel(self, job: _Job) -> None:
        while job.finished is None:
            record = self._records().get(job.job_id)
            if record is not None and record.get("cancel") is True:
                job.cancel.set()
                return
            time.sleep(_DISCOVERY_CANCEL_POLL_SECONDS)


def _process_alive(pid: object) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True
