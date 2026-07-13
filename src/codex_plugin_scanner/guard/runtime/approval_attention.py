"""Attention-aware browser escalation for pending Guard approvals."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import final

from ..config import GuardConfig, load_guard_config
from ..store import GuardStore
from .surface_server import GuardSurfaceRuntime

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_BROWSER_OPEN_COOLDOWN_SECONDS = 300.0


@dataclass(frozen=True, slots=True)
class _PendingAttention:
    operation_id: str
    request_ids: tuple[str, ...]
    browser_url: str
    due_at: float


def request_max_severity(request: dict[str, object]) -> str:
    """Return the highest structured risk severity on an approval request."""

    highest = "info"
    decision = request.get("decision_v2_json")
    signals = decision.get("signals") if isinstance(decision, dict) else None
    if not isinstance(signals, list):
        return highest
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        severity = signal.get("severity")
        if isinstance(severity, str) and _SEVERITY_ORDER.get(severity, -1) > _SEVERITY_ORDER[highest]:
            highest = severity
    return highest


def should_open_immediately(requests: list[dict[str, object]], threshold: str) -> bool:
    threshold_rank = _SEVERITY_ORDER.get(threshold, _SEVERITY_ORDER["critical"])
    return any(_SEVERITY_ORDER[request_max_severity(request)] >= threshold_rank for request in requests)


@final
class ApprovalAttentionCoordinator:
    """Open one approval tab only when a pending operation still needs attention."""

    def __init__(
        self,
        *,
        store: GuardStore,
        runtime: GuardSurfaceRuntime,
        opener: Callable[[str], object],
        clock: Callable[[], float] = time.monotonic,
        cooldown_seconds: float = _BROWSER_OPEN_COOLDOWN_SECONDS,
    ) -> None:
        self._store = store
        self._runtime = runtime
        self._opener = opener
        self._clock = clock
        self._cooldown_seconds = cooldown_seconds
        self._condition = threading.Condition()
        self._pending: dict[str, _PendingAttention] = {}
        self._last_opened_at: float | None = None
        self._stopping = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._condition:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stopping = False
            self._thread = threading.Thread(
                target=self._run,
                daemon=True,
                name="guard-approval-attention",
            )
            self._thread.start()

    def stop(self) -> None:
        with self._condition:
            self._stopping = True
            self._pending.clear()
            self._condition.notify_all()
            thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        with self._condition:
            self._thread = None

    def schedule(
        self,
        *,
        operation_id: str,
        requests: list[dict[str, object]],
        browser_url: str,
    ) -> None:
        request_ids = tuple(
            str(request["request_id"]) for request in requests if isinstance(request.get("request_id"), str)
        )
        if not request_ids:
            return
        config = self._config_for_requests(requests)
        if config.approval_surface_policy != "attention-aware":
            return
        delay = (
            0.0
            if should_open_immediately(requests, config.approval_browser_immediate_severity)
            else float(config.approval_browser_delay_seconds)
        )
        item = _PendingAttention(
            operation_id=operation_id,
            request_ids=request_ids,
            browser_url=browser_url,
            due_at=self._clock() + delay,
        )
        with self._condition:
            self._pending[operation_id] = item
            self._condition.notify_all()

    def process_due(self) -> None:
        """Process due work synchronously; exposed for deterministic tests."""

        now = self._clock()
        with self._condition:
            due = [item for item in self._pending.values() if item.due_at <= now]
            for item in due:
                self._pending.pop(item.operation_id, None)
        for item in due:
            self._open_if_still_blocking(item, now=now)

    def _run(self) -> None:
        while True:
            with self._condition:
                if self._stopping:
                    return
                if not self._pending:
                    self._condition.wait()
                    continue
                next_due = min(item.due_at for item in self._pending.values())
                wait_seconds = max(0.0, next_due - self._clock())
                if wait_seconds > 0:
                    self._condition.wait(wait_seconds)
                    continue
            self.process_due()

    def _open_if_still_blocking(self, item: _PendingAttention, *, now: float) -> None:
        operation = self._store.get_guard_operation(item.operation_id)
        if operation is None or operation.get("status") != "waiting_on_approval":
            return
        requests = [
            request
            for request_id in item.request_ids
            if (request := self._store.get_approval_request(request_id)) is not None
            and request.get("status") == "pending"
        ]
        if not requests or self._operation_was_superseded(operation):
            return
        config = self._config_for_requests(requests)
        if config.approval_surface_policy != "attention-aware" or self._runtime.has_live_surface("approval-center"):
            return
        if self._last_opened_at is not None and now - self._last_opened_at < self._cooldown_seconds:
            return
        try:
            opened = self._opener(item.browser_url)
        except Exception:
            return
        if opened is False:
            return
        self._last_opened_at = now
        self._runtime.record_surface_open(surface="approval-center", open_key=f"attention:{item.request_ids[0]}")

    def _operation_was_superseded(self, operation: dict[str, object]) -> bool:
        session_id = operation.get("session_id")
        created_at = operation.get("created_at")
        if not isinstance(session_id, str) or not isinstance(created_at, str):
            return False
        return any(
            candidate.get("operation_id") != operation.get("operation_id")
            and isinstance(candidate.get("created_at"), str)
            and str(candidate["created_at"]) > created_at
            for candidate in self._store.list_guard_operations(session_id=session_id)
        )

    def _config_for_requests(self, requests: list[dict[str, object]]) -> GuardConfig:
        workspace = next(
            (Path(value) for request in requests if isinstance((value := request.get("workspace")), str)),
            None,
        )
        return load_guard_config(self._store.guard_home, workspace)
