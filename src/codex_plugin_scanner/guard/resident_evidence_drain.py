"""Bounded transport poller for the resident's direct-evidence diagnostics."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Protocol, cast

EVIDENCE_BATCH_FEATURE = "hook-direct-evidence-batch-v1"
_DRAIN_SCHEMA = "guard-hook-direct-evidence-batch.v1"
_DRAIN_INTERVAL_SECONDS = 0.25
_DRAIN_TIMEOUT_SECONDS = 2.0


class _DrainHost(Protocol):
    @property
    def guard_home(self) -> Path: ...

    @property
    def policy_snapshot_publisher(self) -> object: ...

    @property
    def activity_writer(self) -> object | None: ...


def _decode_batch(
    output: bytes | None,
    counters: object | None = None,
    on_store_fatal: Callable[[], object] | None = None,
) -> tuple[int, int, bool, bool] | None:
    """Read the resident's aggregate commit diagnostics."""

    if not output:
        return None
    try:
        page = json.loads(output)
    except (TypeError, ValueError):
        return None
    if not isinstance(page, dict) or page.get("schema") != _DRAIN_SCHEMA:
        return None
    record_count = page.get("record_count")
    pages = page.get("pages")
    more = page.get("more")
    failed = page.get("failed")
    epoch = page.get("epoch")
    if (
        not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count < 0
        or not isinstance(pages, int)
        or isinstance(pages, bool)
        or pages < 0
        or not isinstance(more, bool)
        or not isinstance(failed, bool)
        or not isinstance(epoch, str)
        or not epoch
    ):
        return None
    if counters is not None and "counters" in page:
        observe = getattr(counters, "observe_page", None)
        if callable(observe):
            observe(epoch, page.get("counters"))
    if on_store_fatal is not None and isinstance(page.get("store_fatal"), dict):
        with suppress(Exception):
            on_store_fatal()
    return pages, record_count, more, failed


class ResidentEvidenceDrain:
    """Poll the resident's direct-evidence queue without recording in Python."""

    def __init__(
        self,
        host: _DrainHost,
        *,
        interval_seconds: float = _DRAIN_INTERVAL_SECONDS,
        transport: Callable[[], tuple[Path, Callable[..., bytes | None]] | None] | None = None,
    ) -> None:
        self._host = host
        self._interval_seconds = interval_seconds
        self._transport = transport or self._publisher_transport
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.pages = 0
        self.records = 0
        self.failures = 0
        self._counters = getattr(host, "hook_counters", None)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="hol-guard-resident-evidence", daemon=True)
        self._thread.start()

    def stop(self, *, timeout_seconds: float = 1.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if thread is not None and thread.is_alive():
            return False
        while self.drain_once(deadline_monotonic=deadline):
            # Rust reports an unfinished batch. Keep using the caller's
            # original shutdown deadline across requests.
            pass
        return True

    def drain_once(self, *, deadline_monotonic: float | None = None) -> bool:
        try:
            return self._drain_batch(deadline_monotonic=deadline_monotonic)
        finally:
            counters = self._counters
            if counters is not None:
                with suppress(Exception):
                    maybe_log = getattr(counters, "maybe_log", None)
                    if callable(maybe_log):
                        maybe_log()

    def _drain_batch(self, *, deadline_monotonic: float | None = None) -> bool:
        from .native_runtime import _isolated_environment

        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            return False
        transport = self._transport()
        if transport is None:
            return False
        executable, client = transport
        request_deadline = time.monotonic() + _DRAIN_TIMEOUT_SECONDS
        if deadline_monotonic is not None:
            request_deadline = min(request_deadline, deadline_monotonic)
        remaining = request_deadline - time.monotonic()
        if remaining <= 0:
            return False
        budget_ms = max(1, int(remaining * 1_000))
        # Give the final page and the reply time before the client times out.
        batch_budget_ms = budget_ms - min(250, budget_ms // 4)
        payload = json.dumps(
            {
                "operation": "hook_direct_evidence_commit",
                "deadline_budget_ms": budget_ms,
                "request": {
                    "guard_home": str(self._host.guard_home),
                    "batch": {"budget_ms": batch_budget_ms, "shutdown": deadline_monotonic is not None},
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            output = client(
                executable=executable,
                guard_home=self._host.guard_home,
                environment=_isolated_environment(),
                payload=payload,
                deadline_monotonic=request_deadline,
            )
        except Exception:
            output = None
        batch = _decode_batch(
            output,
            self._counters,
            lambda: self._recover_writer_store(deadline_monotonic),
        )
        if batch is None:
            self.failures += 1
            return False
        pages, count, more, failed = batch
        self.pages += pages
        self.records += count
        self.failures += int(failed)
        return more

    def _recover_writer_store(self, deadline_monotonic: float | None = None) -> None:
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            return
        stats = getattr(self._host.activity_writer, "stats", None)
        if callable(stats):
            _ = stats()

    def _publisher_transport(self) -> tuple[Path, Callable[..., bytes | None]] | None:
        transport = getattr(self._host.policy_snapshot_publisher, "direct_evidence_transport", None)
        if not callable(transport):
            return None
        return cast("tuple[Path, Callable[..., bytes | None]] | None", transport())

    def _run(self) -> None:
        while not self._stop.is_set():
            more = False
            with suppress(Exception):
                more = self.drain_once()
            if not more:
                self._stop.wait(self._interval_seconds)


__all__ = ["EVIDENCE_BATCH_FEATURE", "ResidentEvidenceDrain"]
