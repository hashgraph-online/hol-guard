"""The daemon's long-lived background workers, run in one child of the native daemon.

The native daemon starts ``desktop daemon-workers`` once it is listening and
keeps the child's standard input open. The child runs the workers that wait on
their own signals instead of a fixed tick (the command queue, Cloud review
sync, approval attention, the repair self-check, the resident watchdog and the
workspace assessment worker) and stops them all when its standard input
closes, which happens when the daemon exits for any reason.

Status the old in-process daemon kept on its server object is kept in the
Guard store instead, so the per-request handlers can read it.
"""

from __future__ import annotations

import logging
import sys
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

REPAIR_SELF_CHECK_KEY = "daemon_repair_self_check_status"
ATTENTION_PREFIX = "daemon_approval_attention:"
_REFRESH_SECONDS = 10.0
_ATTENTION_POLL_SECONDS = 1.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def queue_approval_attention(store: GuardStore, *, operation_id: str, requests: list[dict[str, object]]) -> None:
    """Hands an operation waiting on approval to the worker host's attention loop."""

    store.set_sync_payload(
        f"{ATTENTION_PREFIX}{operation_id}",
        {"operation_id": operation_id, "requests": requests},
        _now(),
    )


class DurableApprovalAttention:
    """Stands in for the attention coordinator in a process that does not outlive its request."""

    def __init__(self, store: GuardStore) -> None:
        self._store = store

    def schedule(self, *, operation_id: str, requests: list[dict[str, object]], browser_url: str) -> None:
        # The worker host rebuilds the browser address from the approval URL,
        # so the daemon key never reaches the store.
        del browser_url
        queue_approval_attention(self._store, operation_id=operation_id, requests=requests)


def _take_attention(store: GuardStore) -> list[dict[str, object]]:
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        rows = connection.execute(
            "select state_key from sync_state where state_key like ? escape '\\'",
            (ATTENTION_PREFIX.replace("_", "\\_") + "%",),
        ).fetchall()
    taken: list[dict[str, object]] = []
    for row in rows:
        key = str(row["state_key"])
        payload = store.get_sync_payload(key)
        store.delete_sync_payload(key)
        if isinstance(payload, dict):
            taken.append(payload)
    return taken


class WorkerHost:
    """Starts, refreshes and stops the long-lived workers for one Guard home."""

    def __init__(self, store: GuardStore, *, home_dir: Path) -> None:
        self.store = store
        self.home_dir = home_dir
        self.stop = threading.Event()
        self._command_queue: Any = None
        self._cloud_review_sync: Any = None
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    def _record(self, code: str) -> None:
        _LOGGER.warning("Guard worker host error: %s", code)

    def _start_command_queue_after_authority(self) -> bool:
        from ..daemon.command_queue_worker import start_command_queue_worker

        if self.stop.is_set():
            return False
        with self._lock:
            self._command_queue = start_command_queue_worker(self.store, self._command_queue)
        return True

    def refresh_queues(self) -> None:
        """Applies changed Cloud connectivity and consent, as the daemon's refresh route did."""

        from ..daemon.command_queue_worker import refresh_command_queue_worker
        from ..runtime.cloud_review_sync_worker import refresh_cloud_review_sync_worker

        with self._lock:
            self._command_queue, _ = refresh_command_queue_worker(
                self.store, self._command_queue, shutting_down=self.stop.is_set()
            )
            self._cloud_review_sync, _ = refresh_cloud_review_sync_worker(
                self.store,
                self._cloud_review_sync,
                shutting_down=self.stop.is_set(),
                on_authority_changed=self._start_command_queue_after_authority,
            )

    def _loop(self, name: str, body: Callable[[], None], interval: float) -> None:
        def run() -> None:
            while not self.stop.is_set():
                try:
                    body()
                except Exception:
                    _LOGGER.exception("Guard worker host loop %s failed", name)
                if self.stop.wait(interval):
                    return

        thread = threading.Thread(target=run, daemon=True, name=f"guard-worker-{name}")
        thread.start()
        self._threads.append(thread)

    def start(self) -> None:
        from ..browser_opener import open_browser_url
        from ..daemon import repair_self_check
        from ..daemon.command_queue_worker import start_command_queue_worker
        from ..native_resident_watchdog import start_native_resident_watchdog
        from ..runtime.approval_attention import ApprovalAttentionCoordinator
        from ..runtime.cloud_review_sync import start_cloud_sync_sync_worker
        from ..runtime.surface_server import GuardSurfaceRuntime
        from ..workspace_assessment_worker import start_workspace_assessment_worker

        attention = ApprovalAttentionCoordinator(
            store=self.store,
            runtime=GuardSurfaceRuntime(self.store),
            opener=open_browser_url,
            home_dir=self.home_dir,
        )
        attention.start()
        self._attention = attention
        self._loop("attention", lambda: self._schedule_attention(attention), _ATTENTION_POLL_SECONDS)
        with self._lock:
            self._command_queue = start_command_queue_worker(self.store, self._command_queue)
            self._cloud_review_sync = start_cloud_sync_sync_worker(
                self.store,
                self._cloud_review_sync,
                on_authority_changed=self._start_command_queue_after_authority,
            )
        self._loop("queue-refresh", self.refresh_queues, _REFRESH_SECONDS)

        def publish(status: dict[str, object]) -> None:
            self.store.set_sync_payload(REPAIR_SELF_CHECK_KEY, status, _now())

        self._threads.append(
            repair_self_check.start_self_check(self.store, publish=publish, stop=self.stop, on_error=self._record)
        )
        watchdog = start_native_resident_watchdog(self.store.guard_home, stop=self.stop, on_error=self._record)
        if isinstance(watchdog, threading.Thread):
            self._threads.append(watchdog)
        assessment = start_workspace_assessment_worker(self.store, stop=self.stop, on_error=self._record)
        if isinstance(assessment, threading.Thread):
            self._threads.append(assessment)

    def _schedule_attention(self, attention: Any) -> None:
        from ..daemon.manager import ensure_guard_daemon_auth_token
        from ..local_dashboard_session import build_approval_browser_url

        pending = _take_attention(self.store)
        if not pending:
            return
        key = ensure_guard_daemon_auth_token(self.store.guard_home)
        for item in pending:
            requests = item.get("requests")
            operation_id = item.get("operation_id")
            if not isinstance(requests, list) or not isinstance(operation_id, str):
                continue
            typed = [request for request in requests if isinstance(request, dict)]
            first_url = next(
                (request["approval_url"] for request in typed if isinstance(request.get("approval_url"), str)),
                None,
            )
            browser_url = build_approval_browser_url(first_url, auth_token=key)
            if browser_url is not None:
                attention.schedule(operation_id=operation_id, requests=typed, browser_url=browser_url)

    def shutdown(self) -> None:
        from ..daemon.command_queue_worker import stop_command_queue_worker
        from ..runtime.cloud_review_sync import stop_cloud_sync_sync_worker

        self.stop.set()
        attention = getattr(self, "_attention", None)
        if attention is not None:
            attention.stop()
        with self._lock:
            self._command_queue = stop_command_queue_worker(self._command_queue)
            self._cloud_review_sync = stop_cloud_sync_sync_worker(self._cloud_review_sync)
        for thread in self._threads:
            thread.join(timeout=2.0)


def run_worker_host(guard_home: Path) -> int:
    """Runs the workers until standard input closes."""

    store = GuardStore(guard_home)
    host = WorkerHost(store, home_dir=Path.home().expanduser().resolve(strict=False))
    host.start()
    try:
        # The daemon holds the other end; end of file means it has gone.
        while sys.stdin.buffer.read(4096):
            pass
    except (OSError, ValueError, KeyboardInterrupt):
        pass
    finally:
        host.shutdown()
    return 0


__all__ = [
    "ATTENTION_PREFIX",
    "REPAIR_SELF_CHECK_KEY",
    "DurableApprovalAttention",
    "WorkerHost",
    "queue_approval_attention",
    "run_worker_host",
]
