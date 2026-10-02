"""Request-local route evidence for one private installed-runtime benchmark."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Mapping
from typing import Any

from scripts.native_slo_contract import SAFE_ROUTE_NAMES

_PROBE_KEY = "_guard_slo_probe_id"


class RequestRouteTracker:
    """Retain the worker protocol's route for each benchmark request.

    Instrument only this benchmark's runner instance. Tokens are synthetic and
    registered before each request; no payload, receipt, or caller data is retained.
    Late results cannot recreate a completed token or grow the active map.

    The runner must expose review and _record_route_metric; an optional worker
    must expose review_http_payload and metrics.record_route. Missing methods
    are harness errors and must fail before any instrumentation is installed.
    Only private benchmark instances may be passed; this is not a daemon API.
    """

    def __init__(self, runner: Any, worker: Any = None) -> None:
        self._runner = runner
        self._review = runner.review
        self._record = runner._record_route_metric
        self._worker = worker
        self._worker_review = worker.review_http_payload if worker is not None else None
        self._worker_record = worker.metrics.record_route if worker is not None else None
        self._local = threading.local()
        self._lock = threading.Lock()
        self._active: dict[str, str | None] = {}
        self._closed = False
        runner.review = self._tracked_review
        runner._record_route_metric = self._tracked_record
        if worker is not None:
            worker.review_http_payload = self._tracked_worker_review
            worker.metrics.record_route = self._tracked_worker_record

    def begin(self, payload: Mapping[str, object]) -> tuple[dict[str, object], str]:
        """Reject use after shutdown; a closed harness is not a native sample."""
        token = uuid.uuid4().hex
        with self._lock:
            if self._closed:
                raise RuntimeError("native_installed_slo_failed: route tracker is closed")
            self._active[token] = None
        return {**payload, _PROBE_KEY: token}, token

    def finish(self, token: str) -> str:
        with self._lock:
            return self._active.pop(token, None) or "native_fail_safe"

    def _tracked_record(self, route: object) -> None:
        self._record(route)
        self._capture_route(route)

    def _tracked_worker_record(self, route: object) -> None:
        record = self._worker_record
        if record is None:
            raise RuntimeError("native_installed_slo_failed: route worker is unavailable")
        record(route)
        self._capture_route(route)

    def _capture_route(self, route: object) -> None:
        if getattr(self._local, "depth", 0):
            self._local.route = route if isinstance(route, str) and route in SAFE_ROUTE_NAMES else None

    def _tracked_review(self, *args: Any, **kwargs: Any) -> Any:
        return self._invoke(self._review, *args, **kwargs)

    def _tracked_worker_review(self, *args: Any, **kwargs: Any) -> Any:
        return self._invoke(self._worker_review, *args, **kwargs)

    def _invoke(self, review: Any, *args: Any, **kwargs: Any) -> Any:
        depth = getattr(self._local, "depth", 0)
        if depth == 0:
            self._local.route = None
        self._local.depth = depth + 1
        try:
            result = review(*args, **kwargs)
            result_payload = result if isinstance(result, Mapping) else getattr(result, "payload", None)
            terminal_failure = isinstance(getattr(result, "reason_code", None), str)
            if depth == 0 and (result_payload is not None or terminal_failure):
                payload = kwargs.get("payload")
                token = payload.get(_PROBE_KEY) if isinstance(payload, Mapping) else None
                if isinstance(token, str):
                    with self._lock:
                        if token in self._active:
                            self._active[token] = self._local.route
            return result
        finally:
            self._local.depth = depth
            if depth == 0:
                self._local.route = None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._active.clear()
        self._runner.review = self._review
        self._runner._record_route_metric = self._record
        if self._worker is not None:
            self._worker.review_http_payload = self._worker_review
            self._worker.metrics.record_route = self._worker_record
