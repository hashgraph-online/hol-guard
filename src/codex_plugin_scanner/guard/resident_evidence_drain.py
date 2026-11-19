"""Bounded transport poller for evidence already owned by the resident.

The resident records receipts, activity, fence windows, captures, and notices
while it serves a direct answer.  This module only asks for another page and
acknowledges the cursor the resident returned.  It deliberately does not
inspect or write evidence records in Python.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

_DRAIN_SCHEMA = "guard-hook-direct-evidence.v1"
_DRAIN_INTERVAL_SECONDS = 0.25
_DRAIN_TIMEOUT_SECONDS = 2.0
_MAX_PAGES_PER_WAKE = 8


@dataclass(frozen=True, slots=True)
class _PageRecord:
    value: object
    key: str | None


class _DrainHost(Protocol):
    @property
    def store(self) -> object: ...

    @property
    def guard_home(self) -> Path: ...

    @property
    def policy_snapshot_publisher(self) -> object: ...

    @property
    def activity_writer(self) -> object | None: ...

    def _record_post_tool_activity(self, *, harness: str, payload: Mapping[str, object], succeeded: bool) -> None: ...


def _decode_page(
    output: bytes | None,
    counters: object | None = None,
    on_store_fatal: Callable[[], object] | None = None,
) -> tuple[list[_PageRecord], int, tuple[str, int] | None] | None:
    """Decode only the bounded page metadata needed to advance the cursor."""

    if not output:
        return None
    try:
        page = json.loads(output)
    except (TypeError, ValueError):
        return None
    if not isinstance(page, dict) or page.get("schema") != _DRAIN_SCHEMA:
        return None
    records = page.get("records")
    sequences = page.get("sequences")
    remaining = page.get("remaining")
    through = page.get("through")
    epoch = page.get("epoch")
    if not isinstance(records, list) or isinstance(remaining, bool) or not isinstance(remaining, int):
        return None
    if sequences is not None and (
        not isinstance(sequences, list)
        or len(sequences) != len(records)
        or not isinstance(epoch, str)
        or not epoch
        or any(isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1 for sequence in sequences)
    ):
        return None
    page_records = [
        _PageRecord(value, f"{epoch}:{sequence}" if sequences is not None else None)
        for value, sequence in zip(records, sequences or [None] * len(records), strict=True)
    ]
    if counters is not None and "counters" in page:
        observe = getattr(counters, "observe_page", None)
        if callable(observe):
            observe(epoch, page.get("counters"))
    if on_store_fatal is not None and isinstance(page.get("store_fatal"), dict):
        with suppress(Exception):
            on_store_fatal()
    if through is None:
        return page_records, remaining, None
    if isinstance(through, bool) or not isinstance(through, int) or through < 1:
        return None
    if not isinstance(epoch, str) or not epoch:
        return None
    return page_records, remaining, (epoch, through)


class ResidentEvidenceDrain:
    """Poll the resident's direct-evidence queue without recording in Python."""

    def __init__(
        self,
        host: _DrainHost,
        *,
        interval_seconds: float = _DRAIN_INTERVAL_SECONDS,
        transport: Callable[[], tuple[Path, Callable[..., bytes | None]] | None] | None = None,
        record_handler: Callable[[object], bool | str] | None = None,
    ) -> None:
        self._host = host
        self._interval_seconds = interval_seconds
        self._transport = transport or self._publisher_transport
        self._record_handler = record_handler or self._record_fallback
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.pages = 0
        self.records = 0
        self.failures = 0
        self._ack: tuple[str, int] | None = None
        self._counters = getattr(host, "hook_counters", None)
        self._handled_epoch: str | None = None
        self._handled_records: set[str] = set()
        self._last_page_keys: set[str] = set()
        self._acknowledged_page = False

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
            records, remaining, through = page
            count = len(records)
            self.pages += 1
            self.records += count
            if through is not None and through[0] != self._handled_epoch:
                self._handled_epoch = through[0]
                self._handled_records.clear()
                self._last_page_keys.clear()
            handled, current_keys = self._record_page(records)
            if not handled:
                self.failures += 1
                return False
            if self._acknowledged_page:
                self._handled_records.difference_update(self._last_page_keys - current_keys)
                self._acknowledged_page = False
            self._last_page_keys = current_keys
            if through is not None:
                self._ack = through
            if remaining == 0 or through is None:
                if deadline_monotonic is not None and through is not None:
                    # Shutdown must deliver the final cursor before the
                    # publisher closes. Background polling sends it on the
                    # next wake instead.
                    continue
                return False
        return True

    def _fetch_page(
        self, *, deadline_monotonic: float | None = None
    ) -> tuple[list[_PageRecord], int, tuple[str, int] | None] | None:
        from .native_runtime import _isolated_environment

        transport = self._transport()
        if transport is None:
            return None
        executable, client = transport
        request: dict[str, object] = {"guard_home": str(self._host.guard_home)}
        pending_ack = self._ack
        if self._ack is not None:
            request["ack_epoch"], request["ack_through"] = self._ack
        request_deadline = time.monotonic() + _DRAIN_TIMEOUT_SECONDS
        if deadline_monotonic is not None:
            request_deadline = min(request_deadline, deadline_monotonic)
        remaining = request_deadline - time.monotonic()
        if remaining <= 0:
            return None
        payload = json.dumps(
            {
                "operation": "hook_direct_evidence_drain",
                "deadline_budget_ms": max(1, int(remaining * 1_000)),
                "request": request,
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
        page = _decode_page(output, self._counters, self._recover_writer_store)
        if page is None:
            self.failures += 1
        elif pending_ack is not None and self._ack == pending_ack:
            self._ack = None
            self._acknowledged_page = True
        return page

    def _recover_writer_store(self) -> None:
        stats = getattr(self._host.activity_writer, "stats", None)
        if callable(stats):
            _ = stats()

    def _record_fallback(self, record: object) -> bool | str:
        from .resident_evidence_fallback import record_resident_evidence_fallback

        return record_resident_evidence_fallback(self._host, record)

    def _record_page(self, records: list[_PageRecord]) -> tuple[bool, set[str]]:
        current_keys: set[str] = set()
        for item in records:
            record = item.value
            if item.key is not None:
                key = item.key
            else:
                try:
                    key = json.dumps(record, sort_keys=True, separators=(",", ":"))
                except (TypeError, ValueError):
                    key = repr(record)
            current_keys.add(key)
            if key in self._handled_records:
                continue
            try:
                outcome = self._record_handler(record)
            except Exception:
                return False, current_keys
            if outcome is True or outcome in {"handled", "drop"}:
                self._handled_records.add(key)
                continue
            return False, current_keys
        return True, current_keys

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
