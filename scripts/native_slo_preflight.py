"""Operation accounting for native SLO preflight checks."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from scripts.native_slo_progress import SloProgress


@contextmanager
def preflight_operation(progress: SloProgress, stage: str) -> Iterator[None]:
    progress.plan_operation(stage)
    progress.activate(stage)
    progress.submit(stage)
    progress.attempt(stage)
    try:
        yield
    except Exception as error:
        progress.fail_request(stage)
        progress.record_failure(error, stage=stage, labels={})
        raise
    else:
        progress.complete(stage)
