"""Diagnostic counts of how hooks reach the resident and the daemon.

The resident counts each hook it settles directly, by harness and by outcome:
an answer, or the reason it deferred. Each evidence drain page carries those
counts. The daemon counts each hook request its hook route receives, by
harness. A bridge asks the resident first and posts to the daemon only when
the resident defers or the bridge cannot use the resident at all, so the
daemon's received count minus the resident's defers estimates the hooks a
bridge handed to the daemon without the resident: the resident was down or
timed out, or the bridge rejected the shape itself.

Both counts are diagnostics only. Nothing reads them to decide a hook. Harness
names are reduced to a fixed set of slots, and no path, command or payload is
kept. The daemon log gets one line when the counts change, at most once per
interval.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from typing import Final

HARNESS_SLOTS: Final = (
    "codex",
    "claude-code",
    "cursor",
    "copilot",
    "kimi",
    "devin",
    "zcode",
    "openclaw",
    "hermes",
    "cline",
    "opencode",
    "grok",
    "pi",
    "omp",
    "other",
)
_NAMED_SLOTS: Final = frozenset(HARNESS_SLOTS[:-1])
_OTHER: Final = "other"
_LOG_EVENT: Final = "hook_direct_counters"
_LOG_INTERVAL_SECONDS: Final = 300.0
_MAX_OUTCOMES: Final = 64
_OUTCOME_CODE: Final = re.compile(r"[a-z_]{1,64}")


def harness_slot(harness: object) -> str:
    """The slot a harness name counts under; any unknown name is ``other``."""

    return harness if isinstance(harness, str) and harness in _NAMED_SLOTS else _OTHER


def decode_resident_counters(value: object) -> dict[str, dict[str, int]] | None:
    """The resident's counts from a drain page, or ``None`` when malformed."""

    if not isinstance(value, Mapping):
        return None
    by_harness = value.get("by_harness")
    if not isinstance(by_harness, Mapping):
        return None
    decoded: dict[str, dict[str, int]] = {}
    for harness, outcomes in by_harness.items():
        if harness not in HARNESS_SLOTS or not isinstance(outcomes, Mapping) or len(outcomes) > _MAX_OUTCOMES:
            return None
        counts: dict[str, int] = {}
        for code, count in outcomes.items():
            if not isinstance(code, str) or _OUTCOME_CODE.fullmatch(code) is None:
                return None
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                return None
            counts[code] = count
        decoded[harness] = counts
    return decoded


class HookCounterLog:
    """Hold the latest counts and log them when they change."""

    def __init__(
        self,
        *,
        interval_seconds: float = _LOG_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._lock = threading.Lock()
        self._received: dict[str, int] = dict.fromkeys(HARNESS_SLOTS, 0)
        self._resident: tuple[str, dict[str, dict[str, int]]] | None = None
        self._interval_seconds = interval_seconds
        self._clock = clock
        self._sink: Callable[..., object] | None = None
        self._logged: dict[str, object] | None = None
        self._logged_at: float | None = None

    def bind_sink(self, sink: Callable[..., object]) -> None:
        """Log through ``sink(event, detail=...)``, the daemon diagnostics."""

        self._sink = sink

    def note_received(self, harness: object) -> None:
        """Count one hook request the daemon received."""

        slot = harness_slot(harness)
        with self._lock:
            self._received[slot] += 1

    def observe_page(self, epoch: object, counters: object) -> None:
        """Keep the resident counts a drain page carried, when it has them."""

        decoded = decode_resident_counters(counters)
        if decoded is None or not isinstance(epoch, str) or not epoch:
            return
        with self._lock:
            self._resident = (epoch, decoded)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            epoch, resident = self._resident if self._resident is not None else (None, {})
            received = {slot: count for slot, count in self._received.items() if count}
        return {"epoch": epoch, "resident": resident, "received": received}

    def maybe_log(self) -> bool:
        """Log the counts when they changed and the interval has passed."""

        sink = self._sink
        if sink is None:
            return False
        now = self._clock()
        if self._logged_at is not None and now - self._logged_at < self._interval_seconds:
            return False
        current = self.snapshot()
        if current == self._logged or (not current["resident"] and not current["received"]):
            return False
        # The interval also paces retries; the snapshot counts as logged only
        # once the sink accepts it, so a failed delivery is retried later.
        # `DaemonDiagnostics.record` reports a dropped line by returning False.
        self._logged_at = now
        delivered = sink(_LOG_EVENT, detail=json.dumps(current, separators=(",", ":"), sort_keys=True))
        if delivered is False:
            return False
        self._logged = current
        return True


def bind_hook_counter_sink(worker: object, diagnostics: object) -> None:
    """Log the worker's counts through the daemon diagnostics, when both exist."""

    counters = getattr(worker, "hook_counters", None)
    record = getattr(diagnostics, "record", None)
    if isinstance(counters, HookCounterLog) and callable(record):
        counters.bind_sink(record)


def note_hook_received(worker: object, harness: object) -> None:
    """Count one hook request on the daemon hook route, without judging it."""

    counters = getattr(worker, "hook_counters", None)
    if isinstance(counters, HookCounterLog):
        counters.note_received(harness)


__all__ = [
    "HARNESS_SLOTS",
    "HookCounterLog",
    "bind_hook_counter_sink",
    "decode_resident_counters",
    "harness_slot",
    "note_hook_received",
]
