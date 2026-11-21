"""Bounded transport poller for the resident's direct-evidence diagnostics."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Protocol, cast

_DRAIN_SCHEMA = "guard-hook-direct-evidence-commit.v1"
_DRAIN_INTERVAL_SECONDS = 0.25
_DRAIN_TIMEOUT_SECONDS = 2.0
_MAX_PAGES_PER_WAKE = 8


class _DrainHost(Protocol):
    @property
    def guard_home(self) -> Path: ...

    @property
    def policy_snapshot_publisher(self) -> object: ...

    @property
    def activity_writer(self) -> object | None: ...


def _decode_page(
    output: bytes | None,
    counters: object | None = None,
    on_store_fatal: Callable[[], object] | None = None,
) -> tuple[int, int] | None:
    """Read the diagnostics for a batch the resident has committed."""

    if not output:
        return None
    try:
        page = json.loads(output)
    except (TypeError, ValueError):
        return None
    if not isinstance(page, dict) or page.get("schema") != _DRAIN_SCHEMA:
        return None
    record_count = page.get("record_count")
    remaining = page.get("remaining")
    epoch = page.get("epoch")
    if (
        not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count < 0
        or not isinstance(remaining, int)
        or isinstance(remaining, bool)
        or remaining < 0
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
    return record_count, remaining


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
        self.drain_once(deadline_monotonic=deadline)
        return True

    def drain_once(self, *, deadline_monotonic: float | None = None) -> bool:
        try:
            return self._drain_pages(deadline_monotonic=deadline_monotonic)
        finally:
            counters = self._counters
            if counters is not None:
                with suppress(Exception):
                    maybe_log = getattr(counters, "maybe_log", None)
                    if callable(maybe_log):
                        maybe_log()

    def _drain_pages(self, *, deadline_monotonic: float | None = None) -> bool:
        pages = 0
        while deadline_monotonic is not None or pages < _MAX_PAGES_PER_WAKE:
            pages += 1
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                return False
            page = self._fetch_page(deadline_monotonic=deadline_monotonic)
            if page is None:
                return False
            count, remaining = page
            self.pages += 1
            self.records += count
            if remaining == 0:
                return False
        return True

    def _fetch_page(self, *, deadline_monotonic: float | None = None) -> tuple[int, int] | None:
        from .native_runtime import _isolated_environment

        transport = self._transport()
        if transport is None:
            return None
        executable, client = transport
        request_deadline = time.monotonic() + _DRAIN_TIMEOUT_SECONDS
        if deadline_monotonic is not None:
            request_deadline = min(request_deadline, deadline_monotonic)
        remaining = request_deadline - time.monotonic()
        if remaining <= 0:
            return None
        payload = json.dumps(
            {
                "operation": "hook_direct_evidence_commit",
                "deadline_budget_ms": max(1, int(remaining * 1_000)),
                "request": {"guard_home": str(self._host.guard_home)},
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
        page = _decode_page(
            output,
            self._counters,
            lambda: self._recover_writer_store(deadline_monotonic),
        )
        if page is None:
            self.failures += 1
        return page

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


__all__ = ["ResidentEvidenceDrain", "_decode_page"]
