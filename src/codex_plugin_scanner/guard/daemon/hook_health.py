"""Bounded worker counters for the existing authenticated health response."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .hook_metrics import HookMetricsRecorder


class _Worker(Protocol):
    @property
    def metrics(self) -> HookMetricsRecorder: ...


class _ProcessRunner(Protocol):
    def stats(self) -> Mapping[str, object]: ...


class HookHealthSource(Protocol):
    @property
    def hook_worker(self) -> _Worker: ...

    @property
    def hook_process_runner(self) -> _ProcessRunner: ...


def hook_worker_health(
    server: HookHealthSource,
    process_capacity: Mapping[str, object],
    request_capacity: Mapping[str, object],
) -> dict[str, object]:
    """Keep direct and child execution counters separate so resets stay visible."""

    return {
        "hook_process_capacity": process_capacity,
        "hook_workers": server.hook_process_runner.stats(),
        "hook_worker_routes": server.hook_worker.metrics.snapshot()["routes"],
        "request_capacity": request_capacity,
    }
