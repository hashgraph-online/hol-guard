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
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

REPAIR_SELF_CHECK_KEY = "daemon_repair_self_check_status"
ATTENTION_PREFIX = "daemon_approval_attention:"
REFRESH_REQUEST_KEY = "daemon_worker_refresh_request"
REFRESH_STATUS_KEY = "daemon_worker_refresh_status"
_REFRESH_SECONDS = 10.0
_ATTENTION_POLL_SECONDS = 1.0
_REFRESH_POLL_SECONDS = 0.2
_REFRESH_WAIT_SECONDS = 5.0
_REFRESH_OPERATION = "guard.review.resolveExact"


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


class DurableWorkerRefresh:
    """Asks the worker host to apply changed Cloud connectivity and consent.

    A request handler does not own the workers, so it leaves a request in the
    store and waits briefly for the host's answer, as the daemon's refresh route
    did in process.
    """

    def __init__(self, store: GuardStore, *, wait_seconds: float = _REFRESH_WAIT_SECONDS) -> None:
        self._store = store
        self._wait_seconds = wait_seconds

    def refresh_command_queue_worker(self) -> dict[str, object]:
        nonce = uuid.uuid4().hex
        self._store.set_sync_payload(REFRESH_REQUEST_KEY, {"nonce": nonce}, _now())
        deadline = time.monotonic() + self._wait_seconds
        while time.monotonic() < deadline:
            status = self._store.get_sync_payload(REFRESH_STATUS_KEY)
            if isinstance(status, dict) and status.get("nonce") == nonce:
                return {
                    "operation": _REFRESH_OPERATION,
                    "running": status.get("running") is True,
                    "sync_running": status.get("sync_running") is True,
                }
            time.sleep(_REFRESH_POLL_SECONDS)
        return {"operation": _REFRESH_OPERATION, "running": False, "sync_running": False}


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
        self._hook_worker: Any = None
        self._attention: Any = None

    def _record(self, code: str) -> None:
        _LOGGER.warning("Guard worker host error: %s", code)

    def _start_command_queue_after_authority(self) -> bool:
        from ..cloud_control.command_queue_worker import start_command_queue_worker

        if self.stop.is_set():
            return False
        with self._lock:
            self._command_queue = start_command_queue_worker(self.store, self._command_queue)
        return True

    def refresh_queues(self) -> tuple[bool, bool]:
        """Applies changed Cloud connectivity and consent, as the daemon's refresh route did."""

        from ..cloud_control.command_queue_worker import refresh_command_queue_worker
        from ..runtime.cloud_review_sync_worker import refresh_cloud_review_sync_worker

        with self._lock:
            self._command_queue, running = refresh_command_queue_worker(
                self.store, self._command_queue, shutting_down=self.stop.is_set()
            )
            self._cloud_review_sync, sync_running = refresh_cloud_review_sync_worker(
                self.store,
                self._cloud_review_sync,
                shutting_down=self.stop.is_set(),
                on_authority_changed=self._start_command_queue_after_authority,
            )
        return running, sync_running

    def answer_refresh_request(self) -> None:
        """Answers a request handler's refresh request left in the store."""

        request = self.store.get_sync_payload(REFRESH_REQUEST_KEY)
        if not isinstance(request, dict) or not isinstance(request.get("nonce"), str):
            return
        self.store.delete_sync_payload(REFRESH_REQUEST_KEY)
        running, sync_running = self.refresh_queues()
        self.store.set_sync_payload(
            REFRESH_STATUS_KEY,
            {"nonce": request["nonce"], "running": running, "sync_running": sync_running},
            _now(),
        )

    def _loop(self, name: str, body: Callable[[], object], interval: float) -> None:
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
        from ..cloud_control.command_queue_worker import start_command_queue_worker
        from ..native_resident_watchdog import start_native_resident_watchdog
        from ..runtime.approval_attention import ApprovalAttentionCoordinator
        from ..runtime.cloud_review_sync import start_cloud_sync_sync_worker
        from ..runtime.surface_server import GuardSurfaceRuntime
        from ..runtime_health import repair_self_check
        from ..workspace_assessment_worker import start_workspace_assessment_worker

        self._start_policy_publication()
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
        self._loop("refresh-request", self.answer_refresh_request, _REFRESH_POLL_SECONDS)

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

    def _start_policy_publication(self) -> None:
        """Keeps the native policy snapshot, its direct-lane ACK and evidence drain live.

        The daemon's hook worker owned the publisher for the daemon's whole
        life: it publishes the snapshot the resident enforces, renews the
        direct-lane lease and drains direct-hook evidence. A request handler
        ends with its request, so this host owns it now.
        """

        from ..evidence_drains.hook_evidence_dispatch import HookEvidenceDispatch
        from ..hook_review.hook_worker import HookWorker
        from ..native_hook_evidence_writer import NativeHookEvidenceWriter

        try:
            # Direct answers are bound only while their evidence has a writer,
            # so the drain gets the same writer the daemon's hooks use.
            self._hook_worker = HookWorker(
                store=self.store,
                home_dir=self.home_dir,
                activity_writer=NativeHookEvidenceWriter(store=self.store),
                evidence_dispatch=HookEvidenceDispatch(),
                capture_writer=None,
                wait_for_native_policy=False,
            )
        except Exception:
            _LOGGER.exception("Guard worker host could not start native policy publication")
            self._hook_worker = None

    def wait_for_policy_publication(self) -> None:
        """Waits, bounded, for the first native policy publication."""

        from ..hook_review.hook_worker import _NATIVE_POLICY_STARTUP_READY_TIMEOUT_SECONDS

        hook_worker = getattr(self, "_hook_worker", None)
        publisher = getattr(hook_worker, "policy_snapshot_publisher", None)
        wait_until_ready = getattr(publisher, "wait_until_ready", None)
        if callable(wait_until_ready):
            try:
                _ = wait_until_ready(time.monotonic() + _NATIVE_POLICY_STARTUP_READY_TIMEOUT_SECONDS)
            except Exception:
                _LOGGER.exception("Guard worker host could not wait for native policy publication")

    def _schedule_attention(self, attention: Any) -> None:
        from ..local_dashboard_session import build_approval_browser_url
        from ..native_daemon_manage import ensure_guard_daemon_auth_token

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
        from ..cloud_control.command_queue_worker import stop_command_queue_worker
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
        hook_worker = getattr(self, "_hook_worker", None)
        if hook_worker is not None:
            try:
                hook_worker.close(deadline_monotonic=time.monotonic() + 5.0)
            except Exception:
                _LOGGER.exception("Guard worker host could not stop native policy publication")


def run_worker_host(guard_home: Path) -> int:
    """Runs the workers until standard input closes."""

    store = GuardStore(guard_home)
    host = WorkerHost(store, home_dir=Path.home().expanduser().resolve(strict=False))
    host.start()
    host.wait_for_policy_publication()
    # The daemon announces itself only after this line, so its first hook
    # finds a published policy, as it did when the daemon's own hook worker
    # waited for one before the daemon reported ready.
    sys.stdout.write("ready\n")
    sys.stdout.flush()
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
