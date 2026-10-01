"""Small in-memory pool for explicitly requested, Guard-owned MCP probes."""

from __future__ import annotations

import logging
import re
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from uuid import uuid4

_LOG = logging.getLogger(__name__)
_JOB_ID = re.compile(r"[a-f0-9]{32}\Z")
# Two slow providers can occupy half the pool while two other connections
# still refresh. Four also caps concurrent job threads and their possible
# child processes/stdio descriptors; callers beyond this ceiling get busy.
_MAX_RUNNING_JOBS = 4
_PUBLIC_FAILURE_CODES = frozenset(
    {
        "mcp_refresh_unavailable",
        "catalog_revision_conflict",
        "configured_host_scan_failed",
        "observed_provider_scan_failed",
        "catalog_limit_reached",
        "mcp_launch_failed",
        "mcp_transport_failed",
        "mcp_initialize_failed",
        "mcp_protocol_unsupported",
        "mcp_capability_rejected",
    }
)


class DiscoveryJobError(ValueError):
    pass


class DiscoveryStageError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass
class _Job:
    job_id: str
    cli_id: str
    started: float
    cancel: threading.Event = field(default_factory=threading.Event)
    state: str = "running"
    code: str | None = None
    finished: float | None = None
    thread: threading.Thread | None = None

    def public(self) -> dict[str, object]:
        return {"job_id": self.job_id, "cli_id": self.cli_id, "state": self.state, "error": self.code}


class McpDiscoveryJobs:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, _Job] = {}
        self._pending_cancels: dict[str, float] = {}
        self._closed = False

    def start(
        self,
        cli_id: str,
        run: Callable[[threading.Event], None],
        *,
        reuse_seconds: float = 0,
        requested_job_id: str | None = None,
    ) -> dict[str, object]:
        with self._lock:
            if self._closed:
                raise DiscoveryJobError("discovery_unavailable")
            if requested_job_id is not None and not _JOB_ID.fullmatch(requested_job_id):
                raise DiscoveryJobError("invalid_discovery_job")
            now = time.monotonic()
            self._pending_cancels = {key: seen for key, seen in self._pending_cancels.items() if now - seen < 60}
            if requested_job_id in self._pending_cancels:
                del self._pending_cancels[requested_job_id]
                return {"job_id": requested_job_id, "cli_id": cli_id, "state": "cancelled", "error": None}
            if requested_job_id in self._jobs:
                raise DiscoveryJobError("discovery_job_id_conflict")
            self._jobs = {
                key: job for key, job in self._jobs.items() if job.finished is None or now - job.finished < 600
            }
            for job in reversed(tuple(self._jobs.values())):
                if job.cli_id != cli_id:
                    continue
                if job.state in {"running", "cancelling"}:
                    return job.public()
                if job.state == "failed" and job.finished is not None and now - job.finished < 10:
                    raise DiscoveryJobError("discovery_retry_backoff")
                if job.state == "complete" and job.finished is not None and now - job.finished < reuse_seconds:
                    return job.public()
                break
            if sum(job.finished is None for job in self._jobs.values()) >= _MAX_RUNNING_JOBS:
                raise DiscoveryJobError("discovery_busy")
            while len(self._jobs) >= 16:
                oldest = next((key for key, job in self._jobs.items() if job.finished is not None), None)
                if oldest is None:
                    raise DiscoveryJobError("discovery_busy")
                del self._jobs[oldest]
            job = _Job(requested_job_id or uuid4().hex, cli_id, now)
            self._jobs[job.job_id] = job
            job.thread = threading.Thread(
                target=self._run,
                args=(job, run),
                name="hol-guard-mcp-discovery",
                daemon=True,
            )
            try:
                job.thread.start()
            except RuntimeError:
                del self._jobs[job.job_id]
                raise DiscoveryJobError("discovery_unavailable") from None
            return job.public()

    def read(self, job_id: str, *, cancel: bool = False) -> dict[str, object]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                if cancel and _JOB_ID.fullmatch(job_id):
                    now = time.monotonic()
                    self._pending_cancels = {
                        key: seen for key, seen in self._pending_cancels.items() if now - seen < 60
                    }
                    if len(self._pending_cancels) >= 64:
                        self._pending_cancels.pop(next(iter(self._pending_cancels)))
                    self._pending_cancels[job_id] = now
                    return {"job_id": job_id, "cli_id": "", "state": "cancelled", "error": None}
                raise DiscoveryJobError("discovery_job_unavailable")
            if cancel and job.finished is None:
                job.cancel.set()
                job.state = "cancelling"
            return job.public()

    def _run(self, job: _Job, run: Callable[[threading.Event], None]) -> None:
        code = None
        try:
            if not job.cancel.is_set():
                run(job.cancel)
        except Exception as error:
            # Never expose a launch command, environment, provider result, or
            # exception text to polling clients. API codes are a narrow enum.
            candidate = getattr(error, "code", None)
            code = candidate if candidate in _PUBLIC_FAILURE_CODES else "discovery_failed"
            # Exception text, locals and source lines may contain provider output.
            frames = tuple(
                f"{frame.name}:{frame.lineno}" for frame in traceback.extract_tb(error.__traceback__, limit=8)
            )
            _LOG.warning("MCP discovery job %s failed (%s, %s) at %s", job.job_id, code, type(error).__name__, frames)
        finally:
            with self._lock:
                job.finished = time.monotonic()
                job.state = "cancelled" if job.cancel.is_set() else "failed" if code else "complete"
                job.code = None if job.cancel.is_set() else code

    def close(self) -> bool:
        with self._lock:
            self._closed = True
            jobs = tuple(self._jobs.values())
            for job in jobs:
                job.cancel.set()
        deadline = time.monotonic() + 3
        for job in jobs:
            if job.thread is not None:
                job.thread.join(max(0, deadline - time.monotonic()))
        return all(job.thread is None or not job.thread.is_alive() for job in jobs)
