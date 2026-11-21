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

import contextlib
import logging
import os
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
_INSTALLED_AUTHORITY_RETRY_SECONDS = 10.0
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
        self._prepared_hook_worker: Any = None
        self._policy_prepare_thread: threading.Thread | None = None
        self._attention: Any = None
        self._installed_authority_admitted = False

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

    def start(self, on_phase: Callable[[str], None] | None = None) -> None:
        """Admits the installed release and starts policy publication.

        Only these steps stand between the daemon and its first hook. The
        other workers start in ``start_background_workers``, after the host
        reports ready.
        """

        # Admit the installed release before the first publication, as the
        # Python daemon did at startup. A snapshot bound to packs an older
        # engine compiled is refused by the resident, so publishing first
        # would fail every hook closed until something else migrated it.
        report = on_phase or (lambda _step: None)
        self._start_private_state_resident()
        # Building the hook worker publishes nothing, so it runs beside the
        # admission; publishing starts only once the admission has run.
        self._prepare_policy_publication()
        self._admit_installed_release(on_phase=report)
        report("admitted")
        self._start_policy_publication()
        report("publishing")
        if not self._installed_authority_admitted:
            self._loop("installed-authority", self._admit_installed_release, _INSTALLED_AUTHORITY_RETRY_SECONDS)

    def start_background_workers(self) -> None:
        """Starts the workers no hook waits on.

        Approval attention, the cloud queues, the repair self-check, the
        resident watchdog and workspace assessment each poll or wait on their
        own schedule. Starting them before the host reported ready held every
        cold start for their imports and threads, while the first policy
        publication competed with them for the interpreter.
        """

        from ..browser_opener import open_browser_url
        from ..cloud_control.command_queue_worker import start_command_queue_worker
        from ..native_resident_watchdog import start_native_resident_watchdog
        from ..runtime.approval_attention import ApprovalAttentionCoordinator
        from ..runtime.cloud_review_sync import start_cloud_sync_sync_worker
        from ..runtime.surface_server import GuardSurfaceRuntime
        from ..runtime_health import repair_self_check
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

    def _admit_installed_release(self, on_phase: Callable[[str], None] | None = None) -> None:
        """Migrates the active command packs to the installed engine, once it succeeds.

        Only the first attempt, during start, reports its steps; the retry
        loop runs after the daemon has stopped reading them.
        """

        if self._installed_authority_admitted:
            return
        from ..extension_control_host import migrate_installed_authority

        self._installed_authority_admitted = migrate_installed_authority(self.store, on_phase=on_phase)

    def _start_private_state_resident(self) -> None:
        """Opens the Windows resident stream beside admission.

        This host serves the resident from its first publication anyway. Opened
        now, the private-state checks admission and publication make go over
        the stream instead of each starting a runtime process.
        """

        if os.name != "nt":
            return
        from ..native_policy_snapshot_windows_resident import start_private_state_resident

        def open_stream() -> None:
            try:
                start_private_state_resident(self.store.guard_home)
            except Exception:
                _LOGGER.warning("Guard worker host could not open the resident stream early", exc_info=True)

        thread = threading.Thread(target=open_stream, daemon=True, name="guard-worker-resident-start")
        try:
            thread.start()
        except RuntimeError:
            _LOGGER.warning("Guard worker host could not start the resident stream opener", exc_info=True)
            return
        self._threads.append(thread)

    def _prepare_policy_publication(self) -> None:
        """Builds the hook worker on a thread of its own, without starting it."""

        def build() -> None:
            hook_worker = self._build_hook_worker()
            # The first publication's policy compiles read only config files
            # and the store, so they run here too; publishing still waits.
            warm = getattr(getattr(hook_worker, "policy_snapshot_publisher", None), "warm_first_publication", None)
            if callable(warm):
                warm()
            self._prepared_hook_worker = hook_worker

        thread = threading.Thread(target=build, daemon=True, name="guard-worker-policy-prepare")
        try:
            thread.start()
        except RuntimeError:
            _LOGGER.exception("Guard worker host could not prepare native policy publication")
            return
        self._policy_prepare_thread = thread

    def _build_hook_worker(self) -> Any:
        from ..hook_review.hook_worker import HookWorker
        from ..resident_evidence_client import ResidentEvidenceClient
        from ..resident_evidence_dispatch import ResidentEvidenceDispatch

        try:
            # Direct answers are bound only while their evidence has a writer,
            # so the drain gets the same writer the daemon's hooks use.
            return HookWorker(
                store=self.store,
                home_dir=self.home_dir,
                activity_writer=ResidentEvidenceClient(store=self.store),
                evidence_dispatch=ResidentEvidenceDispatch(),
                capture_writer=None,
                wait_for_native_policy=False,
                start_native_policy=False,
            )
        except Exception:
            _LOGGER.exception("Guard worker host could not build the native policy publisher")
            return None

    def _start_policy_publication(self) -> None:
        """Keeps the native policy snapshot, its direct-lane ACK and evidence drain live.

        The daemon's hook worker owned the publisher for the daemon's whole
        life: it publishes the snapshot the resident enforces, renews the
        direct-lane lease and drains direct-hook evidence. A request handler
        ends with its request, so this host owns it now.
        """

        thread = self._policy_prepare_thread
        if thread is not None:
            thread.join()
        hook_worker = self._prepared_hook_worker
        self._prepared_hook_worker = None
        if hook_worker is None:
            # The thread could not build it; build it here, as before.
            hook_worker = self._build_hook_worker()
        if hook_worker is None:
            self._hook_worker = None
            return
        try:
            hook_worker.start_native_policy_publication(home_dir=self.home_dir)
        except Exception:
            _LOGGER.exception("Guard worker host could not start native policy publication")
            self._hook_worker = None
            with contextlib.suppress(Exception):
                hook_worker.close(deadline_monotonic=time.monotonic() + 5.0)
            return
        self._hook_worker = hook_worker

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


def _report_phase(step: str) -> None:
    """Tells the daemon which start step just finished; it journals each one."""

    _ = sys.stdout.write(f"phase {step}\n")
    sys.stdout.flush()


def _wait_for_daemon_to_close() -> None:
    try:
        # The daemon holds the other end; end of file means it has gone.
        while sys.stdin.buffer.read(4096):
            pass
    except (OSError, ValueError, KeyboardInterrupt):
        pass


def run_worker_host(guard_home: Path) -> int:
    """Runs the workers until standard input closes."""

    from ..cli.desktop_daemon_workers import wait_for_early_runtime_status
    from ..runtime_health.background_diagnostics import install_sink, release_sink
    from ..runtime_health.diagnostics import BackgroundLogWriter

    # Opening the store makes native calls that need the runtime status, which
    # the launch started resolving beside the imports.
    wait_for_early_runtime_status()
    store = GuardStore(guard_home)
    # Nothing else in this process opens daemon.log, so without these sinks a
    # failed migration or publication left no line for support to read.
    writer = BackgroundLogWriter(store.guard_home)
    try:
        install_sink(writer.error, notice=writer.notice)
        _report_phase("launched")
        host = WorkerHost(store, home_dir=Path.home().expanduser().resolve(strict=False))
        host.start(on_phase=_report_phase)
        _report_phase("started")
        host.wait_for_policy_publication()
        # The daemon announces itself only after this line, so its first hook
        # finds a published policy, as it did when the daemon's own hook worker
        # waited for one before the daemon reported ready.
        _ = sys.stdout.write("ready\n")
        sys.stdout.flush()
        try:
            host.start_background_workers()
            _wait_for_daemon_to_close()
        finally:
            host.shutdown()
    finally:
        # A start that raises still writes what it queued, such as a failed
        # migration, before the process exits.
        release_sink(writer.error)
        _ = writer.close()
    return 0


__all__ = [
    "ATTENTION_PREFIX",
    "REPAIR_SELF_CHECK_KEY",
    "DurableApprovalAttention",
    "WorkerHost",
    "queue_approval_attention",
    "run_worker_host",
]
